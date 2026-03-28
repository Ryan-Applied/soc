"""Wiz connector — polls Wiz GraphQL API and publishes to Kafka.

Four data flows based on the actual Wiz API docs:
  Issues        → Kafka ctem.raw.wiz → WizNormaliser → ctem.normalized
  CCF           → Kafka ctem.raw.wiz → WizNormaliser → ctem.normalized
  Vulnerabilities → Kafka ctem.raw.wiz → WizNormaliser → ctem.normalized
  Cloud Resources → Postgres org_assets (attack surface inventory)
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from confluent_kafka import Producer

from wiz_connector.auth import WizTokenManager
from wiz_connector.queries import (
    CCF_QUERY,
    CLOUD_RESOURCES_QUERY,
    CLOUD_RESOURCES_VARIABLES,
    DEFAULT_CCF_FILTERS,
    DEFAULT_CCF_ORDER,
    DEFAULT_ISSUE_FILTERS,
    DEFAULT_ISSUE_ORDER,
    DEFAULT_VULN_FILTERS,
    DEFAULT_VULN_ORDER,
    ISSUES_QUERY,
    PAYLOAD_TYPE_CCF,
    PAYLOAD_TYPE_ISSUE,
    PAYLOAD_TYPE_VULNERABILITY,
    VULNERABILITIES_QUERY,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wiz entity/asset type → org_assets.asset_type column value
# ---------------------------------------------------------------------------
_WIZ_TYPE_TO_ASSET_TYPE: dict[str, str] = {
    "VIRTUAL_MACHINE": "server",
    "CONTAINER": "server",
    "KUBERNETES_NODE": "server",
    "SERVERLESS": "cloud_resource",
    "DATABASE": "database",
    "STORAGE_BUCKET": "cloud_resource",
    "LOAD_BALANCER": "network_device",
    "NETWORK_INTERFACE": "network_device",
    "CLOUD_ACCOUNT": "cloud_resource",
}

_PLATFORM_PREFIX: dict[str, str] = {
    "AWS": "aws",
    "GCP": "gcp",
    "AZURE": "azure",
    "OCI": "oci",
    "ALIBABA": "ali",
}

MAX_RETRIES = 3
BASE_BACKOFF = 2.0  # seconds


def _delta_filter_inlast(amount: int = 1, unit: str = "DurationFilterValueUnitDays") -> dict:
    """Build an inLast delta filter used by CCF and vulnerability queries."""
    return {"inLast": {"amount": amount, "unit": unit}}


class WizConnector:
    """Polls the Wiz GraphQL API for Issues, CCF, Vulnerabilities and Assets.

    All security findings (Issues, CCF, Vulnerabilities) are published to the
    ``ctem.raw.wiz`` Kafka topic, each with a ``wiz_payload_type`` discriminator
    field so the downstream WizNormaliser can route them correctly.

    Cloud resources are upserted into ``org_assets`` for attack-surface mapping.
    """

    ISSUES_TOPIC = "ctem.raw.wiz"
    PAGE_SIZE = 500   # Wiz supports up to 500 per page

    def __init__(
        self,
        *,
        api_url: str,
        client_id: str,
        client_secret: str,
        kafka_bootstrap: str,
        pg_pool: Any | None = None,
        poll_interval_seconds: int = 300,
        delta_hours: int = 1,          # look-back window for incremental polls
        tenant_id: str = "default",
        connector_id: str = "",
        project_id: str = "*",         # Wiz project scope ("*" = all projects)
    ) -> None:
        self._api_url = api_url
        self._tenant_id = tenant_id
        self._connector_id = connector_id
        self._poll_interval = poll_interval_seconds
        self._delta_hours = delta_hours
        self._pg_pool = pg_pool
        self._project_id = project_id
        self._running = False

        self._token_manager = WizTokenManager(
            client_id=client_id,
            client_secret=client_secret,
        )
        self._producer = Producer({"bootstrap.servers": kafka_bootstrap})
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        """Main polling loop: issues → CCF → vulns → assets, then sleep."""
        self._running = True
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30.0, read=60.0, write=30.0, pool=30.0),
        )
        logger.info(
            "WizConnector started (id=%s tenant=%s api=%s interval=%ds delta=%dh)",
            self._connector_id, self._tenant_id, self._api_url,
            self._poll_interval, self._delta_hours,
        )
        try:
            while self._running:
                t0 = asyncio.get_event_loop().time()
                await self._run_cycle()
                elapsed = asyncio.get_event_loop().time() - t0
                await asyncio.sleep(max(0.0, self._poll_interval - elapsed))
        finally:
            await self._close_http()
            self._producer.flush(timeout=10)
            logger.info("WizConnector stopped (id=%s)", self._connector_id)

    def stop(self) -> None:
        self._running = False

    async def _close_http(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    async def _run_cycle(self) -> None:
        for label, coro in [
            ("issues",          self.poll_issues()),
            ("ccf",             self.poll_cloud_config_findings()),
            ("vulnerabilities", self.poll_vulnerabilities()),
            ("assets",          self.poll_assets()),
        ]:
            try:
                count = await coro
                logger.info("Poll %s complete (id=%s count=%d)", label, self._connector_id, count)
            except Exception:
                logger.error("Poll %s failed (id=%s)", label, self._connector_id, exc_info=True)

    # ------------------------------------------------------------------
    # Issues polling
    # ------------------------------------------------------------------

    async def poll_issues(self) -> int:
        """Fetch Issues updated in the last delta_hours window."""
        since = datetime.now(timezone.utc) - timedelta(hours=self._delta_hours)
        filters = copy.deepcopy(DEFAULT_ISSUE_FILTERS)
        filters["updatedAt"] = {"after": since.strftime("%Y-%m-%dT%H:%M:%SZ")}

        return await self._paginate_and_publish(
            query=ISSUES_QUERY,
            variables={"filterBy": filters, "orderBy": DEFAULT_ISSUE_ORDER},
            data_path=["data", "issues"],
            payload_type=PAYLOAD_TYPE_ISSUE,
            mapper=self._issue_to_kafka_payload,
        )

    # ------------------------------------------------------------------
    # Cloud Configuration Findings (CCF)
    # ------------------------------------------------------------------

    async def poll_cloud_config_findings(self) -> int:
        """Fetch CCF findings analyzed in the last delta_hours window."""
        filters = copy.deepcopy(DEFAULT_CCF_FILTERS)
        filters["analyzedAt"] = _delta_filter_inlast(
            amount=self._delta_hours,
            unit="DurationFilterValueUnitHours",
        )

        return await self._paginate_and_publish(
            query=CCF_QUERY,
            variables={"filterBy": filters, "orderBy": DEFAULT_CCF_ORDER},
            data_path=["data", "configurationFindings"],
            payload_type=PAYLOAD_TYPE_CCF,
            mapper=self._ccf_to_kafka_payload,
        )

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    async def poll_vulnerabilities(self) -> int:
        """Fetch CVE findings updated in the last delta_hours window."""
        filters = copy.deepcopy(DEFAULT_VULN_FILTERS)
        filters["updatedAt"] = _delta_filter_inlast(
            amount=self._delta_hours,
            unit="DurationFilterValueUnitHours",
        )

        return await self._paginate_and_publish(
            query=VULNERABILITIES_QUERY,
            variables={"filterBy": filters, "orderBy": DEFAULT_VULN_ORDER},
            data_path=["data", "vulnerabilityFindings"],
            payload_type=PAYLOAD_TYPE_VULNERABILITY,
            mapper=self._vuln_to_kafka_payload,
        )

    # ------------------------------------------------------------------
    # Cloud resource / asset inventory
    # ------------------------------------------------------------------

    async def poll_assets(self) -> int:
        """Fetch cloud resources and upsert into org_assets."""
        if self._pg_pool is None:
            return 0

        variables = copy.deepcopy(CLOUD_RESOURCES_VARIABLES)
        variables["projectId"] = self._project_id
        variables["first"] = self.PAGE_SIZE
        cursor: str | None = None
        total = 0

        while True:
            if cursor:
                variables["after"] = cursor
            data = await self._graphql(CLOUD_RESOURCES_QUERY, variables)
            search = data.get("data", {}).get("graphSearch", {})
            nodes = search.get("nodes", [])
            page_info = search.get("pageInfo", {})

            for node in nodes:
                for entity in node.get("entities", []):
                    # Skip Wiz "Discovered:" placeholder resources
                    name = entity.get("name", "")
                    if name.startswith("Discovered: "):
                        continue
                    asset = self._resource_to_org_asset(entity)
                    if asset is None:
                        continue
                    try:
                        await self._upsert_org_asset(self._pg_pool, asset)
                        total += 1
                    except Exception:
                        logger.warning(
                            "Asset upsert failed (asset_id=%s)", asset.get("asset_id"), exc_info=True,
                        )

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        return total

    # ------------------------------------------------------------------
    # Generic paginated publish helper
    # ------------------------------------------------------------------

    async def _paginate_and_publish(
        self,
        query: str,
        variables: dict[str, Any],
        data_path: list[str],
        payload_type: str,
        mapper: Any,
    ) -> int:
        """Paginate through a Wiz query, map each node, and publish to Kafka."""
        variables = copy.deepcopy(variables)
        variables.setdefault("first", self.PAGE_SIZE)
        cursor: str | None = None
        total = 0

        while True:
            if cursor:
                variables["after"] = cursor
            resp = await self._graphql(query, variables)

            page_data: dict[str, Any] = resp
            for key in data_path:
                page_data = page_data.get(key, {})

            nodes: list[dict[str, Any]] = page_data.get("nodes", [])
            page_info: dict[str, Any] = page_data.get("pageInfo", {})

            for node in nodes:
                payload = mapper(node)
                payload["wiz_payload_type"] = payload_type
                payload["tenant_id"] = self._tenant_id
                key = node.get("id", "").encode("utf-8")
                value = json.dumps(payload, default=str).encode("utf-8")
                self._producer.produce(topic=self.ISSUES_TOPIC, key=key, value=value)
                total += 1

            self._producer.flush(timeout=5)

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        return total

    # ------------------------------------------------------------------
    # GraphQL transport
    # ------------------------------------------------------------------

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=30.0, read=60.0, write=30.0, pool=30.0),
            )

        for attempt in range(MAX_RETRIES):
            token = await self._token_manager.get_token()
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
            body = {"query": query, "variables": variables}

            try:
                response = await self._http.post(self._api_url, json=body, headers=headers)
            except httpx.TransportError:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(BASE_BACKOFF ** attempt)
                    continue
                raise

            if response.status_code == 401:
                # Force token refresh on 401
                self._token_manager._expires_at = 0.0
                self._token_manager._token = None
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(BASE_BACKOFF ** attempt)
                    continue
                response.raise_for_status()

            if response.status_code != 200:
                logger.error("GraphQL HTTP %d: %s", response.status_code, response.text[:300])
                response.raise_for_status()

            data: dict[str, Any] = response.json()
            if "errors" in data:
                raise RuntimeError(f"Wiz GraphQL errors: {data['errors']}")
            return data

        raise RuntimeError("GraphQL request failed after all retries")

    # ------------------------------------------------------------------
    # Payload mappers — translate Wiz API shapes to WizNormaliser input
    # ------------------------------------------------------------------

    def _issue_to_kafka_payload(self, issue: dict[str, Any]) -> dict[str, Any]:
        """Map a Wiz issue node to WizNormaliser.normalise() input format."""
        entity: dict[str, Any] = issue.get("entitySnapshot") or {}
        source_rule: dict[str, Any] = issue.get("sourceRule") or {}
        typename = source_rule.get("__typename", "")

        # Control has remediationInstructions; CloudEventRule has sourceType
        if typename == "Control":
            description = source_rule.get("description", "")
            remediation = source_rule.get("remediationInstructions", "")
        else:
            description = source_rule.get("description", "")
            remediation = ""

        projects = [p.get("name", "") for p in (issue.get("projects") or []) if p.get("name")]

        return {
            "id": issue.get("id", ""),
            "title": source_rule.get("name") or issue.get("type", ""),
            "severity": issue.get("severity", "MEDIUM"),
            "status": issue.get("status", "OPEN"),
            "resource_id": entity.get("id", ""),
            "asset_id": entity.get("id", ""),
            "resource_type": entity.get("type", ""),
            "asset_name": entity.get("name", ""),
            "description": description,
            "remediation": remediation,
            "detected_at": issue.get("createdAt", ""),
            "updated_at": issue.get("updatedAt", ""),
            "resolved_at": issue.get("resolvedAt"),
            "cloud_platform": entity.get("cloudPlatform", ""),
            "region": entity.get("region", ""),
            "subscription_id": entity.get("subscriptionExternalId", ""),
            "subscription_name": entity.get("subscriptionName", ""),
            "tags": entity.get("tags") or {},
            "evidence_url": entity.get("cloudProviderURL", ""),
            "projects": projects,
            "source_rule_id": source_rule.get("id", ""),
            "source_rule_name": source_rule.get("name", ""),
            "source_rule_type": typename,
        }

    def _ccf_to_kafka_payload(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Map a Wiz CCF node to WizNormaliser.normalise() input format."""
        resource: dict[str, Any] = finding.get("resource") or {}
        rule: dict[str, Any] = finding.get("rule") or {}
        subscription: dict[str, Any] = finding.get("subscription") or {}

        # Map CCF result to a severity-compatible signal for the normaliser
        # result: "PASS" / "FAIL" / "MANUAL" — all CCF fetched here are FAIL
        return {
            "id": finding.get("id", ""),
            "title": finding.get("name") or rule.get("name", ""),
            "severity": finding.get("severity", "MEDIUM"),
            "status": finding.get("status", "OPEN"),
            "resource_id": resource.get("id", ""),
            "asset_id": resource.get("id", ""),
            "resource_type": resource.get("type", ""),
            "asset_name": resource.get("name", ""),
            "description": rule.get("description", ""),
            "remediation": finding.get("remediation") or rule.get("remediationInstructions", ""),
            "detected_at": finding.get("firstSeenAt", ""),
            "updated_at": finding.get("analyzedAt", ""),
            "cloud_platform": subscription.get("cloudProvider", ""),
            "subscription_id": subscription.get("externalId", ""),
            "subscription_name": subscription.get("name", ""),
            "rule_short_id": rule.get("shortId", ""),
            "rule_name": rule.get("name", ""),
            "result": finding.get("result", ""),
            "source": finding.get("source", ""),
        }

    def _vuln_to_kafka_payload(self, vuln: dict[str, Any]) -> dict[str, Any]:
        """Map a Wiz vulnerability finding to WizNormaliser.normalise() input."""
        asset: dict[str, Any] = vuln.get("vulnerableAsset") or {}
        projects = [p.get("name", "") for p in (vuln.get("projects") or []) if p.get("name")]

        # Internet exposure flags — useful for CTEM consequence scoring
        wide_exposure = asset.get("hasWideInternetExposure", False)
        limited_exposure = asset.get("hasLimitedInternetExposure", False)
        exposure_label = "wide" if wide_exposure else ("limited" if limited_exposure else "none")

        return {
            "id": vuln.get("id", ""),
            "title": vuln.get("name", ""),
            "detailed_name": vuln.get("detailedName", ""),
            "severity": vuln.get("severity", "MEDIUM"),
            "status": vuln.get("status", "OPEN"),
            "description": vuln.get("description") or vuln.get("name", ""),
            "score": vuln.get("score"),
            "epss_probability": vuln.get("epssProbability"),
            "has_exploit": vuln.get("hasExploit", False),
            "has_cisa_kev": vuln.get("hasCisaKevExploit", False),
            "cisa_kev_due_date": vuln.get("cisaKevDueDate"),
            "is_high_profile": vuln.get("isHighProfileThreat", False),
            "validated_in_runtime": vuln.get("validatedInRuntime", False),
            "has_initial_access_potential": vuln.get("hasInitialAccessPotential", False),
            "fixed_version": vuln.get("fixedVersion"),
            "detected_at": vuln.get("firstDetectedAt", ""),
            "updated_at": vuln.get("lastDetectedAt", ""),
            "resolved_at": vuln.get("resolvedAt"),
            "resource_id": asset.get("id", ""),
            "asset_id": asset.get("id", ""),
            "asset_name": asset.get("name", ""),
            "resource_type": asset.get("type", ""),
            "cloud_platform": asset.get("cloudPlatform", ""),
            "subscription_id": asset.get("subscriptionExternalId") or asset.get("subscriptionId", ""),
            "subscription_name": asset.get("subscriptionName", ""),
            "tags": asset.get("tags") or {},
            "internet_exposure": exposure_label,
            "operating_system": asset.get("operatingSystem", ""),
            "projects": projects,
            "remediation": f"Update to fixed version: {vuln.get('fixedVersion')}" if vuln.get("fixedVersion") else "",
        }

    # ------------------------------------------------------------------
    # Asset inventory helpers
    # ------------------------------------------------------------------

    def _resource_to_org_asset(self, resource: dict[str, Any]) -> dict[str, Any] | None:
        asset_id: str = (resource.get("id") or "").strip()
        if not asset_id:
            return None

        asset_name: str = resource.get("name") or asset_id
        wiz_type: str = (resource.get("type") or "").upper()
        asset_type: str = _WIZ_TYPE_TO_ASSET_TYPE.get(wiz_type, "cloud_resource")

        # properties is a JSON blob from graphSearch
        props: dict[str, Any] = resource.get("properties") or {}
        cloud_platform: str = (props.get("cloudPlatform") or props.get("providerType") or "").upper()
        region: str = props.get("region") or props.get("location") or ""

        prefix = _PLATFORM_PREFIX.get(cloud_platform, cloud_platform.lower())
        if prefix and region:
            zone = f"{prefix}/{region}"
        elif prefix:
            zone = prefix
        else:
            zone = region or "unknown"

        raw_tags: Any = resource.get("tags") or props.get("tags") or {}
        if isinstance(raw_tags, dict):
            tags: list[str] = [f"{k}={v}" for k, v in raw_tags.items()]
        elif isinstance(raw_tags, list):
            tags = [str(t) for t in raw_tags]
        else:
            tags = []

        parts = [wiz_type.replace("_", " ").title()] if wiz_type else []
        if region:
            parts.append(f"in {region}")
        if cloud_platform:
            parts.append(f"({cloud_platform})")
        description = " ".join(parts) or asset_name

        return {
            "asset_id": asset_id,
            "asset_name": asset_name,
            "asset_type": asset_type,
            "zone": zone,
            "tags": tags,
            "owner_team": None,
            "criticality": "medium",
            "description": description,
            "cmdb_source": "wiz",
        }

    async def _upsert_org_asset(self, pool: Any, asset: dict[str, Any]) -> None:
        await pool.execute(
            """
            INSERT INTO org_assets (
                asset_id, asset_name, asset_type, zone,
                tags, owner_team, criticality, description, cmdb_source,
                last_updated
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
            ON CONFLICT (asset_id) DO UPDATE SET
                asset_name  = EXCLUDED.asset_name,
                asset_type  = EXCLUDED.asset_type,
                zone        = EXCLUDED.zone,
                tags        = EXCLUDED.tags,
                owner_team  = COALESCE(EXCLUDED.owner_team, org_assets.owner_team),
                criticality = EXCLUDED.criticality,
                description = EXCLUDED.description,
                cmdb_source = EXCLUDED.cmdb_source,
                last_updated = NOW()
            """,
            asset["asset_id"],
            asset["asset_name"],
            asset["asset_type"],
            asset["zone"],
            asset["tags"],
            asset.get("owner_team"),
            asset.get("criticality", "medium"),
            asset.get("description", ""),
            asset.get("cmdb_source", "wiz"),
        )
