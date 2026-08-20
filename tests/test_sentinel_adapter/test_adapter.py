"""Tests for SentinelAdapter and IngestAdapter ABC — Stories 4.1 & 4.3."""

from __future__ import annotations

import json

import pytest

from shared.adapters.ingest import IngestAdapter
from sentinel_adapter.adapter import SentinelAdapter


# ---- ABC conformance -------------------------------------------------------

class TestIngestAdapterABC:
    def test_sentinel_is_ingest_adapter(self):
        assert issubclass(SentinelAdapter, IngestAdapter)

    def test_source_name(self):
        adapter = SentinelAdapter()
        assert adapter.source_name() == "sentinel"

    @pytest.mark.asyncio
    async def test_subscribe_raises_not_implemented(self):
        adapter = SentinelAdapter()
        with pytest.raises(NotImplementedError):
            await adapter.subscribe()


# ---- heartbeat handling ----------------------------------------------------

class TestHeartbeatHandling:
    def test_heartbeat_returns_none(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "hb-001",
            "AlertName": "Heartbeat",
            "TimeGenerated": "2026-02-14T10:00:00Z",
            "Description": "",
            "Severity": "Informational",
        }
        assert adapter.to_canonical(event) is None

    def test_test_alert_returns_none(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "test-001",
            "AlertName": "Test Alert",
            "TimeGenerated": "2026-02-14T10:00:00Z",
            "Description": "",
            "Severity": "Low",
        }
        assert adapter.to_canonical(event) is None

    def test_health_check_returns_none(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "hc-001",
            "AlertName": "Health Check",
            "TimeGenerated": "2026-02-14T10:00:00Z",
            "Description": "",
            "Severity": "Informational",
        }
        assert adapter.to_canonical(event) is None

    def test_heartbeat_case_insensitive(self):
        adapter = SentinelAdapter()
        event = {
            "SystemAlertId": "hb-002",
            "AlertName": "HEARTBEAT",
            "TimeGenerated": "2026-02-14T10:00:00Z",
            "Description": "",
            "Severity": "Informational",
        }
        assert adapter.to_canonical(event) is None


# ---- severity normalisation -----------------------------------------------

class TestSeverityNormalisation:
    def test_high_lowered(self):
        adapter = SentinelAdapter()
        event = _make_event(Severity="High")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.severity == "high"

    def test_critical_lowered(self):
        adapter = SentinelAdapter()
        event = _make_event(Severity="Critical")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.severity == "critical"

    def test_informational_lowered(self):
        adapter = SentinelAdapter()
        event = _make_event(Severity="Informational")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.severity == "informational"

    def test_missing_severity_defaults_to_medium(self):
        adapter = SentinelAdapter()
        event = _make_event()
        del event["Severity"]
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.severity == "medium"

    def test_empty_severity_defaults_to_medium(self):
        adapter = SentinelAdapter()
        event = _make_event(Severity="")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.severity == "medium"


# ---- tactics / techniques splitting ----------------------------------------

class TestTacticsAndTechniques:
    def test_single_tactic(self):
        adapter = SentinelAdapter()
        event = _make_event(Tactics="Execution")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tactics == ["Execution"]

    def test_multiple_tactics(self):
        adapter = SentinelAdapter()
        event = _make_event(Tactics="Execution, Persistence, Privilege Escalation")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tactics == ["Execution", "Persistence", "Privilege Escalation"]

    def test_empty_tactics(self):
        adapter = SentinelAdapter()
        event = _make_event(Tactics="")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tactics == []

    def test_missing_tactics(self):
        adapter = SentinelAdapter()
        event = _make_event()
        del event["Tactics"]
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tactics == []

    def test_single_technique(self):
        adapter = SentinelAdapter()
        event = _make_event(Techniques="T1059.001")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.techniques == ["T1059.001"]

    def test_multiple_techniques(self):
        adapter = SentinelAdapter()
        event = _make_event(Techniques="T1059.001, T1071.001")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.techniques == ["T1059.001", "T1071.001"]


# ---- field mapping ---------------------------------------------------------

class TestFieldMapping:
    def test_alert_id(self):
        adapter = SentinelAdapter()
        event = _make_event(SystemAlertId="abc-123")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.alert_id == "abc-123"

    def test_source_is_sentinel(self):
        adapter = SentinelAdapter()
        alert = adapter.to_canonical(_make_event())
        assert alert is not None
        assert alert.source == "sentinel"

    def test_timestamp(self):
        adapter = SentinelAdapter()
        event = _make_event(TimeGenerated="2026-02-14T14:32:45.123Z")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.timestamp == "2026-02-14T14:32:45.123Z"

    def test_title(self):
        adapter = SentinelAdapter()
        event = _make_event(AlertName="Suspicious Process")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.title == "Suspicious Process"

    def test_description(self):
        adapter = SentinelAdapter()
        event = _make_event(Description="Something bad happened")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.description == "Something bad happened"

    def test_product(self):
        adapter = SentinelAdapter()
        event = _make_event(ProductName="Microsoft Defender for Endpoint")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.product == "Microsoft Defender for Endpoint"

    def test_tenant_id(self):
        adapter = SentinelAdapter()
        event = _make_event(TenantId="contoso-tenant")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tenant_id == "contoso-tenant"

    def test_tenant_id_defaults_to_default(self):
        adapter = SentinelAdapter()
        event = _make_event()
        del event["TenantId"]
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.tenant_id == "default"

    def test_entities_raw_preserved(self):
        entities = json.dumps([{"$id": "1", "Type": "ip", "Address": "10.0.0.1"}])
        adapter = SentinelAdapter()
        event = _make_event(Entities=entities)
        alert = adapter.to_canonical(event)
        assert alert is not None
        parsed = json.loads(alert.entities_raw)
        assert isinstance(parsed, list)
        assert parsed[0]["Address"] == "10.0.0.1"

    def test_raw_payload_contains_original(self):
        adapter = SentinelAdapter()
        event = _make_event(SystemAlertId="raw-test")
        alert = adapter.to_canonical(event)
        assert alert is not None
        assert alert.raw_payload["SystemAlertId"] == "raw-test"


# ---- helper ----------------------------------------------------------------

def _make_event(**overrides: str) -> dict[str, str]:
    base: dict[str, str] = {
        "SystemAlertId": "test-001",
        "TimeGenerated": "2026-02-14T10:00:00Z",
        "AlertName": "Test Suspicious Activity",
        "Description": "Test description",
        "Severity": "Medium",
        "Tactics": "InitialAccess",
        "Techniques": "T1190",
        "Entities": "[]",
        "ProductName": "Sentinel",
        "TenantId": "test-tenant",
    }
    base.update(overrides)
    return base
