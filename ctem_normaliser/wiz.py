"""Wiz normaliser — handles Issues, CCF, and Vulnerability payloads.

All three Wiz data types flow through the same Kafka topic (ctem.raw.wiz)
and are distinguished by the ``wiz_payload_type`` discriminator field set
by WizConnector:
  "issue"          — security issues raised by Wiz controls / event rules
  "ccf"            — cloud configuration findings (misconfigurations)
  "vulnerability"  — CVE findings on VMs, containers, serverless
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ctem_normaliser.base import BaseNormaliser
from ctem_normaliser.models import (
    ZONE_CONSEQUENCE_FALLBACK,
    CTEMExposure,
    compute_ctem_score,
    compute_severity,
    compute_sla_deadline,
    generate_exposure_key,
)

# Wiz severity → exploitability bucket
_EXPLOITABILITY_MAP: dict[str, str] = {
    "CRITICAL": "high",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFORMATIONAL": "low",
}

_EXPLOITABILITY_SCORE: dict[str, float] = {
    "high": 0.9,
    "medium": 0.5,
    "low": 0.2,
}

# Wiz cloud platform prefix → asset zone
_PLATFORM_ZONE: dict[str, str] = {
    "aws": "Zone3_Enterprise",
    "azure": "Zone3_Enterprise",
    "gcp": "Zone3_Enterprise",
}

# Wiz resource type keyword → zone override
_ZONE_MAP: dict[str, str] = {
    "edge": "Zone1_EdgeInference",
    "orbital": "Zone1_EdgeInference",
    "demo": "Zone4_External",
    "public": "Zone4_External",
}


class WizNormaliser(BaseNormaliser):
    """Normalises Wiz Issues, CCF findings, and CVE vulnerabilities."""

    def __init__(self, neo4j_client: Any | None = None) -> None:
        self._neo4j = neo4j_client

    def source_name(self) -> str:
        return "wiz"

    def normalise(self, raw: dict[str, Any]) -> CTEMExposure:
        """Route to the correct normalisation path based on wiz_payload_type."""
        payload_type = raw.get("wiz_payload_type", "issue")
        if payload_type == "vulnerability":
            return self._normalise_vulnerability(raw)
        if payload_type == "ccf":
            return self._normalise_ccf(raw)
        return self._normalise_issue(raw)

    # ------------------------------------------------------------------
    # Issue normalisation
    # ------------------------------------------------------------------

    def _normalise_issue(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title") or raw.get("source_rule_name", "")
        asset_id = raw.get("asset_id") or raw.get("resource_id", "")
        original_severity = raw.get("severity", "MEDIUM").upper()
        resource_type = raw.get("resource_type", "").lower()
        cloud_platform = raw.get("cloud_platform", "").lower()

        asset_zone = self._classify_zone(resource_type, cloud_platform)
        consequence = self._get_consequence(asset_zone)
        exploitability = _EXPLOITABILITY_MAP.get(original_severity, "medium")
        exploitability_score = _EXPLOITABILITY_SCORE.get(exploitability, 0.5)
        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        return CTEMExposure(
            exposure_key=generate_exposure_key("wiz", title, asset_id),
            ts=raw.get("detected_at", datetime.now(timezone.utc).isoformat()),
            source_tool="wiz",
            title=title,
            description=raw.get("description", ""),
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type=raw.get("resource_type", ""),
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique=raw.get("atlas_technique", ""),
            attack_technique=raw.get("attack_technique", ""),
            threat_model_ref=raw.get("threat_model_ref", ""),
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url=raw.get("evidence_url", raw.get("url", "")),
            tenant_id=raw.get("tenant_id", ""),
        )

    # ------------------------------------------------------------------
    # CCF (Cloud Configuration Finding) normalisation
    # ------------------------------------------------------------------

    def _normalise_ccf(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title") or raw.get("rule_name", "")
        asset_id = raw.get("asset_id") or raw.get("resource_id", "")
        original_severity = raw.get("severity", "MEDIUM").upper()
        cloud_platform = raw.get("cloud_platform", "").lower()
        resource_type = raw.get("resource_type", "").lower()

        asset_zone = self._classify_zone(resource_type, cloud_platform)
        consequence = self._get_consequence(asset_zone)
        exploitability = _EXPLOITABILITY_MAP.get(original_severity, "medium")
        exploitability_score = _EXPLOITABILITY_SCORE.get(exploitability, 0.5)
        severity = compute_severity(exploitability, consequence)
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        description = raw.get("description", "")
        rule_short_id = raw.get("rule_short_id", "")
        if rule_short_id:
            description = f"[{rule_short_id}] {description}".strip()

        return CTEMExposure(
            exposure_key=generate_exposure_key("wiz_ccf", title, asset_id),
            ts=raw.get("detected_at") or raw.get("updated_at", datetime.now(timezone.utc).isoformat()),
            source_tool="wiz",
            title=f"[CCF] {title}",
            description=description,
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type=resource_type,
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique="",
            attack_technique="",
            threat_model_ref="",
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url="",
            tenant_id=raw.get("tenant_id", ""),
        )

    # ------------------------------------------------------------------
    # Vulnerability normalisation
    # ------------------------------------------------------------------

    def _normalise_vulnerability(self, raw: dict[str, Any]) -> CTEMExposure:
        title = raw.get("title", "")
        asset_id = raw.get("asset_id") or raw.get("resource_id", "")
        original_severity = raw.get("severity", "MEDIUM").upper()
        cloud_platform = raw.get("cloud_platform", "").lower()
        resource_type = raw.get("resource_type", "").lower()

        # Boost exploitability for known exploited / CISA KEV vulns
        exploitability_bucket = _EXPLOITABILITY_MAP.get(original_severity, "medium")
        exploitability_score = _EXPLOITABILITY_SCORE.get(exploitability_bucket, 0.5)

        if raw.get("has_cisa_kev"):
            exploitability_score = min(1.0, exploitability_score + 0.2)
        elif raw.get("has_exploit"):
            exploitability_score = min(1.0, exploitability_score + 0.1)

        # Wide internet exposure elevates consequence
        asset_zone = self._classify_zone(resource_type, cloud_platform)
        if raw.get("internet_exposure") == "wide":
            asset_zone = "Zone4_External"

        consequence = self._get_consequence(asset_zone)
        severity = compute_severity(
            "high" if exploitability_score >= 0.8 else exploitability_bucket,
            consequence,
        )
        ctem_score = compute_ctem_score(exploitability_score, consequence)

        description = raw.get("description") or raw.get("detailed_name", title)
        if raw.get("has_cisa_kev"):
            description = f"[CISA KEV] {description}"
        elif raw.get("is_high_profile"):
            description = f"[High Profile] {description}"

        return CTEMExposure(
            exposure_key=generate_exposure_key("wiz_vuln", title, asset_id),
            ts=raw.get("detected_at", datetime.now(timezone.utc).isoformat()),
            source_tool="wiz",
            title=f"[CVE] {title}",
            description=description,
            severity=severity,
            original_severity=original_severity,
            asset_id=asset_id,
            asset_type=resource_type,
            asset_zone=asset_zone,
            exploitability_score=exploitability_score,
            physical_consequence=consequence,
            ctem_score=ctem_score,
            atlas_technique="",
            attack_technique="",
            threat_model_ref="",
            status="Open",
            sla_deadline=compute_sla_deadline(severity),
            remediation_guidance=raw.get("remediation", ""),
            evidence_url="",
            tenant_id=raw.get("tenant_id", ""),
        )

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------

    def _classify_zone(self, resource_type: str, cloud_platform: str) -> str:
        for keyword, zone in _ZONE_MAP.items():
            if keyword in resource_type or keyword in cloud_platform:
                return zone
        return _PLATFORM_ZONE.get(cloud_platform, "Zone3_Enterprise")

    def _get_consequence(self, asset_zone: str) -> str:
        return ZONE_CONSEQUENCE_FALLBACK.get(asset_zone, "data_loss")
