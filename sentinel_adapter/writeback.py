"""Idempotent Microsoft Sentinel incident write-back and outbox persistence."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, uuid5


class TransientWritebackError(Exception):
    pass


class PermanentWritebackError(Exception):
    pass


class SentinelIncidentClient:
    """Write an investigation comment and label to a Sentinel incident."""

    API_VERSION = "2025-09-01"
    ARM_SCOPE = "https://management.azure.com/.default"

    def __init__(self, credential: Any) -> None:
        self._credential = credential

    async def write_investigation_summary(
        self, payload: dict[str, Any], idempotency_key: str
    ) -> None:
        required = (
            "subscription_id",
            "resource_group",
            "workspace_name",
            "incident_name",
            "comment",
        )
        missing = [key for key in required if not payload.get(key)]
        if missing:
            raise PermanentWritebackError(
                f"Missing Sentinel write-back fields: {', '.join(missing)}"
            )

        base_url = self._incident_url(payload)
        comment_id = str(uuid5(NAMESPACE_URL, idempotency_key))
        comment_url = (
            f"{base_url}/comments/{comment_id}?api-version={self.API_VERSION}"
        )
        await self._request(
            "PUT",
            comment_url,
            json_body={"properties": {"message": payload["comment"]}},
        )

        incident_url = f"{base_url}?api-version={self.API_VERSION}"
        incident = await self._request("GET", incident_url)
        properties = incident.get("properties", {})
        labels = list(properties.get("labels") or [])
        existing_names = {
            str(label.get("labelName", "")).lower() for label in labels
        }
        requested_tags = payload.get("tags") or ["ALUSKORT-Investigated"]
        for tag in requested_tags:
            if str(tag).lower() not in existing_names:
                labels.append({"labelName": str(tag), "labelType": "User"})

        if len(labels) == len(properties.get("labels") or []):
            return

        writable_properties = {
            key: properties[key]
            for key in (
                "title",
                "description",
                "severity",
                "status",
                "owner",
                "firstActivityTimeUtc",
                "lastActivityTimeUtc",
                "classification",
                "classificationReason",
                "classificationComment",
            )
            if key in properties and properties[key] is not None
        }
        writable_properties["labels"] = labels
        etag = incident.get("etag")
        body: dict[str, Any] = {"properties": writable_properties}
        if etag:
            body["etag"] = etag
        headers = {"If-Match": etag} if etag else None
        await self._request(
            "PUT",
            incident_url,
            json_body=body,
            extra_headers=headers,
        )

    def _incident_url(self, payload: dict[str, Any]) -> str:
        parts = {
            key: quote(str(payload[key]), safe="")
            for key in (
                "subscription_id",
                "resource_group",
                "workspace_name",
                "incident_name",
            )
        }
        return (
            "https://management.azure.com/subscriptions/"
            f"{parts['subscription_id']}/resourceGroups/{parts['resource_group']}"
            "/providers/Microsoft.OperationalInsights/workspaces/"
            f"{parts['workspace_name']}/providers/Microsoft.SecurityInsights/"
            f"incidents/{parts['incident_name']}"
        )

    async def _request(
        self,
        method: str,
        url: str,
        *,
        json_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        import aiohttp

        token = await asyncio.to_thread(
            self._credential.get_token, self.ARM_SCOPE
        )
        headers = {
            "Authorization": f"Bearer {token.token}",
            "Content-Type": "application/json",
            **(extra_headers or {}),
        }
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method, url, json=json_body, headers=headers
            ) as response:
                if response.status >= 400:
                    message = await response.text()
                    error_cls = (
                        TransientWritebackError
                        if response.status in {408, 409, 412, 429}
                        or response.status >= 500
                        else PermanentWritebackError
                    )
                    raise error_cls(
                        f"Sentinel API {method} failed ({response.status}): {message}"
                    )
                if response.status == 204:
                    return {}
                return await response.json()


class PostgresWritebackOutbox:
    """Claim and update durable Sentinel write-back work items."""

    def __init__(self, db: Any, max_attempts: int = 8) -> None:
        self._db = db
        self._max_attempts = max_attempts

    async def claim(self, batch_size: int = 10) -> list[dict[str, Any]]:
        rows = await self._db.fetch_many(
            """
            WITH candidates AS (
                SELECT outbox_id
                FROM sentinel_writeback_outbox
                WHERE (
                    status IN ('pending', 'failed') AND next_attempt_at <= NOW()
                ) OR (
                    status = 'processing'
                    AND processing_started_at < NOW() - INTERVAL '5 minutes'
                )
                ORDER BY created_at
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE sentinel_writeback_outbox AS outbox
            SET status = 'processing', attempts = attempts + 1,
                processing_started_at = NOW()
            FROM candidates
            WHERE outbox.outbox_id = candidates.outbox_id
            RETURNING outbox.outbox_id, outbox.idempotency_key,
                      outbox.payload, outbox.attempts
            """,
            batch_size,
        )
        result = []
        for row in rows:
            item = dict(row)
            if isinstance(item.get("payload"), str):
                item["payload"] = json.loads(item["payload"])
            result.append(item)
        return result

    async def complete(self, outbox_id: Any) -> None:
        await self._db.execute(
            """
            WITH finished AS (
                UPDATE sentinel_writeback_outbox
                SET status = 'completed', completed_at = NOW(), last_error = NULL,
                    processing_started_at = NULL
                WHERE outbox_id = $1
                RETURNING investigation_id
            )
            UPDATE investigation_state AS investigation
            SET state = 'closed',
                graph_state = jsonb_set(
                    jsonb_set(investigation.graph_state, '{state}', '"closed"'),
                    '{requires_human_approval}', 'false'
                ),
                updated_at = NOW()
            FROM finished
            WHERE investigation.investigation_id = finished.investigation_id
            """,
            outbox_id,
        )

    async def fail(
        self,
        outbox_id: Any,
        error: str,
        attempts: int,
        *,
        permanent: bool = False,
    ) -> None:
        dead_letter = permanent or attempts >= self._max_attempts
        await self._db.execute(
            """
            UPDATE sentinel_writeback_outbox
            SET status = $2,
                last_error = $3,
                processing_started_at = NULL,
                next_attempt_at = NOW() + ($4 * INTERVAL '1 second')
            WHERE outbox_id = $1
            """,
            outbox_id,
            "dead_letter" if dead_letter else "failed",
            error[:4000],
            min(3600, 30 * (2 ** max(0, attempts - 1))),
        )
