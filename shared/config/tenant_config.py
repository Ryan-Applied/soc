"""Tenant configuration — Story 14.8.

Per-tenant config with shadow mode defaults. New tenants always start
in shadow mode and cannot transition to live without explicit sign-off.

NFR-SCL-003: Per-tenant monthly spend caps resolved via ``spend_tier`` and
the optional ``monthly_spend_cap`` override.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

# Imported here so callers can resolve caps without importing spend_guard
from context_gateway.spend_guard import TENANT_MONTHLY_CAPS


@dataclass
class TenantConfig:
    """Per-tenant configuration.

    New tenants default to ``shadow_mode=True``.  Shadow mode cannot be
    disabled without ``go_live_signed_off=True``.

    spend_tier:
        Controls the default monthly LLM spend cap.  Valid values are
        ``"premium"`` ($500), ``"standard"`` ($100), and ``"trial"`` ($20).
    monthly_spend_cap:
        When set, overrides the tier default with an exact USD value.
    """

    tenant_id: str
    shadow_mode: bool = True
    shadow_rule_families: list[str] = field(default_factory=list)
    go_live_signed_off: bool = False
    go_live_signed_off_by: str = ""
    go_live_date: str = ""
    approval_timeout_overrides: dict[str, int] = field(default_factory=dict)
    # NFR-SCL-003 spend cap fields
    spend_tier: str = "standard"
    monthly_spend_cap: float | None = None

    def disable_shadow(self) -> None:
        """Disable shadow mode — requires prior go-live sign-off."""
        if not self.go_live_signed_off:
            raise ValueError(
                "Cannot disable shadow mode without go_live_signed_off=True"
            )
        self.shadow_mode = False

    def get_effective_monthly_cap(self) -> float:
        """Return the monthly LLM spend cap (USD) for this tenant.

        Uses ``monthly_spend_cap`` when explicitly set; otherwise falls back to
        the tier default from :data:`TENANT_MONTHLY_CAPS`.
        """
        if self.monthly_spend_cap is not None:
            return self.monthly_spend_cap
        return TENANT_MONTHLY_CAPS.get(self.spend_tier, TENANT_MONTHLY_CAPS["standard"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "shadow_mode": self.shadow_mode,
            "shadow_rule_families": self.shadow_rule_families,
            "go_live_signed_off": self.go_live_signed_off,
            "go_live_signed_off_by": self.go_live_signed_off_by,
            "go_live_date": self.go_live_date,
            "approval_timeout_overrides": self.approval_timeout_overrides,
            "spend_tier": self.spend_tier,
            "monthly_spend_cap": self.monthly_spend_cap,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TenantConfig:
        return cls(
            tenant_id=data["tenant_id"],
            shadow_mode=data.get("shadow_mode", True),
            shadow_rule_families=data.get("shadow_rule_families", []),
            go_live_signed_off=data.get("go_live_signed_off", False),
            go_live_signed_off_by=data.get("go_live_signed_off_by", ""),
            go_live_date=data.get("go_live_date", ""),
            approval_timeout_overrides=data.get("approval_timeout_overrides", {}),
            spend_tier=data.get("spend_tier", "standard"),
            monthly_spend_cap=data.get("monthly_spend_cap"),
        )


class TenantConfigStore:
    """Redis-backed tenant configuration store."""

    KEY_PREFIX = "tenant_config:"

    def __init__(self, redis_client: Any) -> None:
        self._redis = redis_client

    def _get_client(self) -> Any:
        """Resolve the underlying async Redis client."""
        if hasattr(self._redis, "_client"):
            return self._redis._client
        return self._redis

    async def get_config(self, tenant_id: str) -> TenantConfig:
        """Load tenant config from Redis. Returns default if not found."""
        client = self._get_client()
        raw = await client.get(f"{self.KEY_PREFIX}{tenant_id}")
        if raw is None:
            return TenantConfig(tenant_id=tenant_id)
        data = json.loads(raw)
        return TenantConfig.from_dict(data)

    async def set_config(self, config: TenantConfig) -> None:
        """Persist tenant config to Redis.

        Enforces: cannot set shadow_mode=False without go_live_signed_off.
        """
        if not config.shadow_mode and not config.go_live_signed_off:
            raise ValueError(
                "Cannot persist config with shadow_mode=False "
                "without go_live_signed_off=True"
            )
        client = self._get_client()
        await client.set(
            f"{self.KEY_PREFIX}{config.tenant_id}",
            json.dumps(config.to_dict()),
        )
