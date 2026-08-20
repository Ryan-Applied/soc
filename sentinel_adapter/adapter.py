"""SentinelAdapter — Stories 4.1 & 4.3.

Maps Microsoft Sentinel ``SecurityAlert`` JSON to
:class:`~shared.schemas.alert.CanonicalAlert`.

Azure SDK imports are confined to this adapter — they never appear in
core pipeline code.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from shared.adapters.ingest import IngestAdapter
from shared.schemas.alert import CanonicalAlert

logger = logging.getLogger(__name__)

# Alert names treated as non-actionable heartbeats / health-checks.
_HEARTBEAT_NAMES = frozenset({"heartbeat", "test alert", "health check"})


class SentinelAdapter(IngestAdapter):
    """Microsoft Sentinel adapter — subscribes to SecurityAlert."""

    def source_name(self) -> str:  # noqa: D401
        return "sentinel"

    async def subscribe(self) -> None:
        """Connector logic is delegated to :mod:`sentinel_adapter.connector`."""
        raise NotImplementedError(
            "Use SentinelEventHubConnector or SentinelLogAnalyticsConnector"
        )

    # ------------------------------------------------------------------
    # Field mapping  (Story 4.3)
    # ------------------------------------------------------------------

    def to_canonical(self, raw_event: dict[str, Any]) -> Optional[CanonicalAlert]:
        """Map a Sentinel SecurityAlert dict to a :class:`CanonicalAlert`.

        Returns ``None`` for heartbeat / test events so they are never
        published to ``alerts.raw``.
        """
        alert_name = raw_event.get("AlertName", "")
        if alert_name.lower().strip() in _HEARTBEAT_NAMES:
            logger.debug("Dropping heartbeat event: %s", alert_name)
            return None

        return CanonicalAlert(
            alert_id=raw_event.get("SystemAlertId", ""),
            source="sentinel",
            timestamp=raw_event.get("TimeGenerated", ""),
            title=alert_name,
            description=raw_event.get("Description", ""),
            severity=self._normalise_severity(raw_event.get("Severity")),
            tactics=self._split_csv(raw_event.get("Tactics")),
            techniques=self._split_csv(raw_event.get("Techniques")),
            entities_raw=raw_event.get("Entities", "[]"),
            product=raw_event.get("ProductName", ""),
            tenant_id=raw_event.get("TenantId", "default"),
            source_context={
                key: value
                for key, value in {
                    "connector_id": raw_event.get("_aluskort_connector_id"),
                    "workspace_id": raw_event.get("_aluskort_workspace_id"),
                    "subscription_id": raw_event.get("_aluskort_subscription_id"),
                    "resource_group": raw_event.get("_aluskort_resource_group"),
                    "workspace_name": raw_event.get("_aluskort_workspace_name"),
                    "system_alert_id": raw_event.get("SystemAlertId"),
                    "vendor_original_id": raw_event.get("VendorOriginalId"),
                    "incident_name": raw_event.get("IncidentName"),
                    "incident_number": raw_event.get("IncidentNumber"),
                    "incident_url": raw_event.get("IncidentUrl"),
                    "provider_incident_id": raw_event.get("ProviderIncidentId"),
                }.items()
                if value not in (None, "")
            },
            raw_payload=raw_event,
        )

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_severity(value: str | None) -> str:
        """Lowercase the Sentinel severity; default to ``"medium"``."""
        if not value:
            return "medium"
        return value.strip().lower()

    @staticmethod
    def _split_csv(value: str | None) -> list[str]:
        """Split a comma-separated string into a stripped list."""
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]
