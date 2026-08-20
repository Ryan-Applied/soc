"""Dashboard Entra authentication and RBAC tests."""

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from services.dashboard.middleware.auth import (
    DashboardAuthenticator,
    _role_from_claims,
)


def test_production_rejects_header_authentication():
    with pytest.raises(RuntimeError, match="must use Entra"):
        DashboardAuthenticator(mode="header", environment="production")


@pytest.mark.asyncio
async def test_entra_bearer_token_maps_application_role():
    validator = MagicMock()
    validator.validate.return_value = {
        "oid": "user-object-id",
        "roles": ["Aluskort.SeniorAnalyst"],
    }
    auth = DashboardAuthenticator(
        mode="entra",
        environment="production",
        token_validator=validator,
    )

    principal = await auth.authenticate({"authorization": "Bearer signed-token"})

    assert principal.user_id == "user-object-id"
    assert principal.role == "senior_analyst"
    validator.validate.assert_called_once_with("signed-token")


@pytest.mark.asyncio
async def test_entra_requires_bearer_token():
    auth = DashboardAuthenticator(
        mode="entra",
        environment="production",
        token_validator=MagicMock(),
    )
    with pytest.raises(HTTPException) as exc:
        await auth.authenticate({})
    assert exc.value.status_code == 401


def test_highest_assigned_role_wins():
    assert _role_from_claims({
        "roles": ["Aluskort.Analyst", "Aluskort.Admin"],
    }) == "admin"


def test_unknown_application_role_is_rejected():
    assert _role_from_claims({"roles": ["Unrelated.Role"]}) is None
