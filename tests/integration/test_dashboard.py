"""Dashboard integration tests — Story 17-9.

End-to-end tests using httpx.AsyncClient with TestClient(app).
Uses a mock PostgresClient to avoid real DB dependency.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from shared.schemas.investigation import GraphState, InvestigationState


# ---- Mock Postgres client ---------------------------------------------------


class MockPostgresClient:
    """In-memory Postgres mock matching the interface used by the dashboard."""

    def __init__(self) -> None:
        self._investigations: dict[str, dict[str, Any]] = {}

    async def execute(self, query: str, *args: Any) -> None:
        # Handle INSERT/UPDATE for investigations
        if "INSERT INTO investigation_state" in query:
            inv_id = args[0]
            self._investigations[inv_id] = {
                "investigation_id": inv_id,
                "alert_id": args[1],
                "tenant_id": args[2],
                "state": args[3],
                "graph_state": json.loads(args[4]) if isinstance(args[4], str) else args[4],
                "updated_at": "2026-02-14T10:00:00Z",
                "created_at": "2026-02-14T09:00:00Z",
            }

    async def fetch_one(self, query: str, *args: Any) -> dict[str, Any] | None:
        if "SELECT graph_state FROM investigation_state" in query:
            inv_id = args[0]
            row = self._investigations.get(inv_id)
            if row:
                return {"graph_state": row["graph_state"]}
            return None
        if "SELECT COUNT(*) AS count FROM kill_switches" in query:
            return {"count": 0}
        if "AVG" in query:
            return {"avg_seconds": None}
        if "FILTER" in query:
            return {"fp_count": 0, "total": 0}
        return None

    async def fetch_many(self, query: str, *args: Any) -> list[dict[str, Any]]:
        if "GROUP BY state" in query:
            state_counts: dict[str, int] = {}
            for inv in self._investigations.values():
                state = inv.get("state", "unknown")
                state_counts[state] = state_counts.get(state, 0) + 1
            return [{"state": key, "count": value} for key, value in state_counts.items()]
        if "FROM investigation_state" in query:
            results = list(self._investigations.values())
            # Apply state filter if present
            if args and "state = $1" in query:
                state_filter = args[0] if args else ""
                if state_filter:
                    results = [r for r in results if r.get("state") == state_filter]
            # Add fields projected from graph_state JSONB by dashboard queries.
            for r in results:
                gs = r.get("graph_state", {})
                if isinstance(gs, dict):
                    r["severity"] = gs.get("severity", "")
                    r["classification"] = gs.get("classification", "")
            return results
        if "GROUP BY" in query:
            return []
        return []


# ---- Fixtures ---------------------------------------------------------------


@pytest.fixture
def mock_db() -> MockPostgresClient:
    return MockPostgresClient()


@pytest.fixture
def client(mock_db: MockPostgresClient) -> TestClient:
    """Build a TestClient with mock dependencies."""
    from services.dashboard.app import app, init_app

    init_app(mock_db)
    return TestClient(app)


def _seed_investigation(
    mock_db: MockPostgresClient,
    inv_id: str = "inv-001",
    state: str = "reasoning",
    severity: str = "high",
    alert_id: str = "alert-001",
    tenant_id: str = "test-tenant",
) -> None:
    """Insert a test investigation into the mock DB."""
    gs = GraphState(
        investigation_id=inv_id,
        state=InvestigationState(state),
        alert_id=alert_id,
        tenant_id=tenant_id,
        severity=severity,
        decision_chain=[
            {"agent": "ioc_extractor", "action": "Extracted 3 IOCs", "confidence": 0.95, "timestamp": "2026-02-14T10:00:00Z"},
            {"agent": "reasoning_agent", "action": "Classified as true positive", "confidence": 0.87, "timestamp": "2026-02-14T10:01:00Z"},
        ],
    )
    mock_db._investigations[inv_id] = {
        "investigation_id": inv_id,
        "alert_id": alert_id,
        "tenant_id": tenant_id,
        "state": state,
        "graph_state": json.loads(gs.model_dump_json()),
        "updated_at": "2026-02-14T10:01:00Z",
        "created_at": "2026-02-14T09:00:00Z",
    }


# ---- Test Scenario 1: List → Detail → Timeline -----------------------------


class TestInvestigationFlow:
    """Create investigation → appears in list → detail → timeline."""

    def test_investigation_appears_in_list(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-flow-001")
        resp = client.get("/investigations", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        assert "inv-flow-001" in resp.text

    def test_detail_page_renders(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-flow-002")
        resp = client.get("/investigations/inv-flow-002", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        assert "inv-flow-002" in resp.text
        assert "reasoning" in resp.text

    def test_detail_404_for_unknown(self, client: TestClient, mock_db: MockPostgresClient):
        resp = client.get("/investigations/nonexistent", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 404

    def test_timeline_renders_entries(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-flow-003")
        resp = client.get("/api/investigations/inv-flow-003/timeline", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        assert "ioc_extractor" in resp.text
        assert "reasoning_agent" in resp.text


# ---- Test Scenario 2: Approval Flow ----------------------------------------


class TestApprovalFlow:
    """AWAITING_HUMAN → approval queue → approve → state changes."""

    def test_awaiting_human_in_queue(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-approve-001", state="awaiting_human")
        resp = client.get("/approvals", headers={"X-User-Role": "senior_analyst"})
        assert resp.status_code == 200
        assert "inv-approve-001" in resp.text

    def test_approve_transitions_to_responding(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-approve-002", state="awaiting_human")
        resp = client.post(
            "/api/investigations/inv-approve-002/approve",
            headers={"X-User-Role": "senior_analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "approved"
        assert data["new_state"] == "responding"

    def test_reject_transitions_to_closed(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-reject-001", state="awaiting_human")
        resp = client.post(
            "/api/investigations/inv-reject-001/reject",
            headers={"X-User-Role": "senior_analyst"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rejected"
        assert data["new_state"] == "closed"


# ---- Test Scenario 3: Overview Metrics --------------------------------------


class TestOverviewMetrics:
    """Overview metrics reflect investigation counts."""

    def test_overview_page_renders(self, client: TestClient, mock_db: MockPostgresClient):
        resp = client.get("/overview", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        assert "System Overview" in resp.text

    def test_metrics_api_returns_data(self, client: TestClient, mock_db: MockPostgresClient):
        _seed_investigation(mock_db, inv_id="inv-metric-001", state="reasoning")
        _seed_investigation(mock_db, inv_id="inv-metric-002", state="closed")
        resp = client.get("/api/metrics", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        data = resp.json()
        assert "by_state" in data
        assert "total_open" in data

    def test_empty_db_returns_zeros(self, client: TestClient, mock_db: MockPostgresClient):
        resp = client.get("/api/metrics", headers={"X-User-Role": "analyst"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_open"] == 0


# ---- Test Scenario 4: RBAC -------------------------------------------------


class TestRBAC:
    """RBAC blocks unauthorized actions."""

    def test_no_header_allows_get(self, client: TestClient, mock_db: MockPostgresClient):
        """GET requests default to analyst role."""
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_no_header_blocks_post(self, client: TestClient, mock_db: MockPostgresClient):
        """POST without role header returns 401."""
        _seed_investigation(mock_db, inv_id="inv-rbac-001", state="awaiting_human")
        resp = client.post("/api/investigations/inv-rbac-001/approve")
        assert resp.status_code == 401

    def test_analyst_cannot_approve(self, client: TestClient, mock_db: MockPostgresClient):
        """Analyst role cannot approve investigations (requires senior_analyst)."""
        _seed_investigation(mock_db, inv_id="inv-rbac-002", state="awaiting_human")
        resp = client.post(
            "/api/investigations/inv-rbac-002/approve",
            headers={"X-User-Role": "analyst"},
        )
        assert resp.status_code == 403

    def test_senior_analyst_can_approve(self, client: TestClient, mock_db: MockPostgresClient):
        """Senior analyst can approve investigations."""
        _seed_investigation(mock_db, inv_id="inv-rbac-003", state="awaiting_human")
        resp = client.post(
            "/api/investigations/inv-rbac-003/approve",
            headers={"X-User-Role": "senior_analyst"},
        )
        assert resp.status_code == 200

    def test_admin_can_approve(self, client: TestClient, mock_db: MockPostgresClient):
        """Admin role inherits senior_analyst permissions."""
        _seed_investigation(mock_db, inv_id="inv-rbac-004", state="awaiting_human")
        resp = client.post(
            "/api/investigations/inv-rbac-004/approve",
            headers={"X-User-Role": "admin"},
        )
        assert resp.status_code == 200
