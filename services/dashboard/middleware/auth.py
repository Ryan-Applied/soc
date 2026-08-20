"""Microsoft Entra authentication and role-based dashboard authorization."""

from __future__ import annotations

import asyncio
import functools
import logging
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping

import jwt
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

VALID_ROLES = frozenset({"analyst", "senior_analyst", "admin"})
_PUBLIC_PATHS = frozenset({"/health", "/docs", "/openapi.json", "/redoc"})
_ROLE_HIERARCHY: dict[str, set[str]] = {
    "admin": {"admin", "senior_analyst", "analyst"},
    "senior_analyst": {"senior_analyst", "analyst"},
    "analyst": {"analyst"},
}
_PROTECTED_PATTERNS: list[tuple[str, str, str]] = [
    ("POST", "/api/investigations/", "senior_analyst"),
]
_ENTRA_ROLE_MAP = {
    "aluskort.admin": "admin",
    "aluskort.senioranalyst": "senior_analyst",
    "aluskort.analyst": "analyst",
    "admin": "admin",
    "senior_analyst": "senior_analyst",
    "analyst": "analyst",
}


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: str
    role: str
    claims: dict[str, Any]


class EntraTokenValidator:
    """Validate single-tenant Entra access tokens against Microsoft's JWKS."""

    def __init__(self, tenant_id: str, client_id: str) -> None:
        if not tenant_id or not client_id:
            raise RuntimeError(
                "AZURE_TENANT_ID and DASHBOARD_ENTRA_CLIENT_ID are required"
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._issuer = f"https://login.microsoftonline.com/{tenant_id}/v2.0"
        self._jwks = jwt.PyJWKClient(
            f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys",
            cache_keys=True,
        )

    def validate(self, token: str) -> dict[str, Any]:
        signing_key = self._jwks.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self._client_id,
            issuer=self._issuer,
            options={"require": ["exp", "iat", "iss", "aud", "tid", "oid"]},
        )
        if claims.get("tid") != self._tenant_id:
            raise jwt.InvalidTokenError("Token tenant does not match")
        if claims.get("idtyp") == "app":
            raise jwt.InvalidTokenError("Application tokens cannot access the analyst UI")
        return dict(claims)


class DashboardAuthenticator:
    """Authenticate either Entra bearer tokens or explicit local-dev headers."""

    def __init__(
        self,
        *,
        mode: str | None = None,
        environment: str | None = None,
        token_validator: EntraTokenValidator | None = None,
    ) -> None:
        self.mode = (mode or os.environ.get("DASHBOARD_AUTH_MODE", "header")).lower()
        self.environment = (
            environment or os.environ.get("APP_ENV", "development")
        ).lower()
        if self.mode not in {"entra", "header"}:
            raise RuntimeError(f"Unsupported DASHBOARD_AUTH_MODE: {self.mode}")
        if self.environment == "production" and self.mode != "entra":
            raise RuntimeError("Production dashboard authentication must use Entra")
        self._validator = token_validator
        if self.mode == "entra" and self._validator is None:
            self._validator = EntraTokenValidator(
                os.environ.get("AZURE_TENANT_ID", ""),
                os.environ.get("DASHBOARD_ENTRA_CLIENT_ID", ""),
            )

    async def authenticate(self, headers: Mapping[str, str]) -> AuthPrincipal:
        if self.mode == "header":
            role = headers.get("x-user-role", "").strip().lower()
            if role not in VALID_ROLES:
                raise HTTPException(401, "Authentication required")
            return AuthPrincipal(
                user_id=headers.get("x-user-id", "local-user"),
                role=role,
                claims={},
            )

        authorization = headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(401, "Bearer authentication required")
        try:
            assert self._validator is not None
            claims = await asyncio.to_thread(self._validator.validate, token)
        except (jwt.PyJWTError, ValueError, RuntimeError):
            logger.info("Rejected invalid Entra access token", exc_info=True)
            raise HTTPException(401, "Invalid access token") from None

        role = _role_from_claims(claims)
        if role is None:
            raise HTTPException(403, "No ALUSKORT application role assigned")
        return AuthPrincipal(
            user_id=str(claims.get("oid")),
            role=role,
            claims=claims,
        )


def _role_from_claims(claims: Mapping[str, Any]) -> str | None:
    mapped = {
        _ENTRA_ROLE_MAP.get(str(role).lower())
        for role in claims.get("roles", [])
    }
    for role in ("admin", "senior_analyst", "analyst"):
        if role in mapped:
            return role
    return None


class RBACMiddleware(BaseHTTPMiddleware):
    """Authenticate requests and enforce the dashboard role hierarchy."""

    def __init__(self, app: Any, **kwargs: Any) -> None:
        super().__init__(app)
        self._authenticator = DashboardAuthenticator(**kwargs)
        self._test_harness_enabled = (
            os.environ.get("ENABLE_TEST_HARNESS", "false").lower() == "true"
            and self._authenticator.environment != "production"
        )

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        path = request.url.path
        if path in _PUBLIC_PATHS or path.startswith("/static/"):
            return await call_next(request)
        if path.startswith("/api/test-harness"):
            if not self._test_harness_enabled:
                return JSONResponse(status_code=404, content={"detail": "Not found"})
            request.state.user_role = "admin"
            request.state.user_id = "test-harness"
            return await call_next(request)

        try:
            principal = await self._authenticator.authenticate(request.headers)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        for method, path_prefix, required_role in _PROTECTED_PATTERNS:
            if request.method == method and path.startswith(path_prefix):
                if required_role not in _ROLE_HIERARCHY.get(principal.role, set()):
                    return JSONResponse(
                        status_code=403,
                        content={"detail": f"Requires '{required_role}'."},
                    )

        request.state.user_role = principal.role
        request.state.user_id = principal.user_id
        request.state.user_claims = principal.claims
        return await call_next(request)


def require_role(required_role: str) -> Callable:
    """Route-level decorator to enforce a minimum role."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request: Request | None = kwargs.get("request")
            if request is None:
                request = next(
                    (arg for arg in args if isinstance(arg, Request)), None
                )
            if request is None:
                raise HTTPException(status_code=500, detail="Request not available")
            role = getattr(request.state, "user_role", "")
            if required_role not in _ROLE_HIERARCHY.get(role, set()):
                raise HTTPException(
                    status_code=403,
                    detail=f"Role '{role}' insufficient. Requires '{required_role}'.",
                )
            return await func(*args, **kwargs)

        return wrapper

    return decorator
