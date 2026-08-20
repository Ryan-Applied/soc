"""Spend guard and cost tracking — Story 5.6.

Enforces daily / monthly cost limits and tracks per-call costs by
tier, task type, and tenant.

NFR-SCL-003: Per-tenant monthly spend caps, tracked in Redis with key
``spend:tenant:{tenant_id}:{YYYY-MM}``.  Each key expires after 35 days.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MONTHLY_HARD_CAP = 1000.0  # USD
DEFAULT_MONTHLY_SOFT_ALERT = 500.0  # USD

# Per-tier monthly spend caps (USD) — NFR-SCL-003
TENANT_MONTHLY_CAPS: dict[str, float] = {
    "premium": 500.0,
    "standard": 100.0,
    "trial": 20.0,
}

# Redis key TTL for tenant spend buckets (35 days covers a full month + buffer)
_TENANT_SPEND_TTL = 35 * 24 * 3600


class SpendLimitExceeded(Exception):
    """Raised when the global hard spend cap is hit."""


class TenantBudgetExceeded(SpendLimitExceeded):
    """Raised when a tenant's monthly spend cap is exceeded."""


@dataclass
class CostRecord:
    """A single API call cost record."""

    cost_usd: float
    model_id: str
    task_type: str
    tenant_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class SpendGuard:
    """Enforces spend limits and tracks per-call costs.

    Parameters
    ----------
    monthly_hard_cap:
        Global hard cap (USD) across all tenants.
    monthly_soft_alert:
        Global soft-alert threshold (USD).
    redis_client:
        Optional :class:`shared.db.redis_cache.RedisClient` instance.
        When provided, per-tenant monthly spend is tracked in Redis with key
        ``spend:tenant:{tenant_id}:{YYYY-MM}`` (fail-open: Redis errors are
        logged but never propagate).
    tenant_config_store:
        Optional :class:`shared.config.tenant_config.TenantConfigStore`.
        When provided, ``check_budget`` resolves each tenant's effective cap
        via ``TenantConfig.get_effective_monthly_cap()``.
    """

    def __init__(
        self,
        monthly_hard_cap: float = DEFAULT_MONTHLY_HARD_CAP,
        monthly_soft_alert: float = DEFAULT_MONTHLY_SOFT_ALERT,
        redis_client: Any | None = None,
        tenant_config_store: Any | None = None,
    ) -> None:
        self.monthly_hard_cap = monthly_hard_cap
        self.monthly_soft_alert = monthly_soft_alert
        self._records: list[CostRecord] = []
        self._soft_alert_fired = False
        self._redis = redis_client
        self._tenant_config_store = tenant_config_store

    # ------------------------------------------------------------------
    # recording
    # ------------------------------------------------------------------

    def record(
        self,
        cost_usd: float,
        model_id: str = "",
        task_type: str = "",
        tenant_id: str = "",
    ) -> None:
        """Record a completed API call and check limits."""
        self._records.append(
            CostRecord(
                cost_usd=cost_usd,
                model_id=model_id,
                task_type=task_type,
                tenant_id=tenant_id,
            )
        )
        self._check_soft_alert()

    async def record_async(
        self,
        cost_usd: float,
        model_id: str = "",
        task_type: str = "",
        tenant_id: str = "",
    ) -> None:
        """Record a completed API call and persist spend to Redis (async)."""
        self.record(cost_usd=cost_usd, model_id=model_id, task_type=task_type, tenant_id=tenant_id)
        if tenant_id:
            await self._increment_tenant_spend(tenant_id, cost_usd)

    # ------------------------------------------------------------------
    # guard
    # ------------------------------------------------------------------

    def check_budget(self, tenant_id: str = "", cost_usd: float = 0.0) -> None:
        """Check global hard cap, then per-tenant monthly cap.

        Parameters
        ----------
        tenant_id:
            When provided, the per-tenant monthly spend (from in-memory records)
            is checked against the tier cap.  Pass an empty string to skip the
            per-tenant check.
        cost_usd:
            The cost of the *current* request (not yet recorded).  This is
            added to the running total before comparing against the cap so that
            the check is prospective rather than retrospective.

        Raises
        ------
        SpendLimitExceeded
            If the global monthly hard cap would be exceeded.
        TenantBudgetExceeded
            If the tenant's monthly cap would be exceeded.
        """
        # --- global hard cap -------------------------------------------
        if self.monthly_total + cost_usd >= self.monthly_hard_cap:
            raise SpendLimitExceeded(
                f"Monthly spend ${self.monthly_total + cost_usd:.2f} "
                f"exceeds global hard cap ${self.monthly_hard_cap:.2f}"
            )

        # --- per-tenant cap --------------------------------------------
        if tenant_id:
            tenant_monthly = self._tenant_monthly_spend(tenant_id) + cost_usd
            cap = self._resolve_tenant_cap(tenant_id)
            if tenant_monthly > cap:
                raise TenantBudgetExceeded(
                    f"Tenant {tenant_id!r} monthly spend ${tenant_monthly:.2f} "
                    f"exceeds cap ${cap:.2f}"
                )

    async def check_budget_async(self, tenant_id: str = "", cost_usd: float = 0.0) -> None:
        """Async variant of :meth:`check_budget` that reads Redis for tenant spend.

        Falls back to in-memory totals when Redis is unavailable (fail-open).
        When a ``tenant_config_store`` was supplied, the tenant's
        ``get_effective_monthly_cap()`` is used so per-tenant overrides and
        tier promotions are respected.

        Raises
        ------
        SpendLimitExceeded
            If the global monthly hard cap would be exceeded.
        TenantBudgetExceeded
            If the tenant's monthly cap would be exceeded.
        """
        # --- global hard cap -------------------------------------------
        if self.monthly_total + cost_usd >= self.monthly_hard_cap:
            raise SpendLimitExceeded(
                f"Monthly spend ${self.monthly_total + cost_usd:.2f} "
                f"exceeds global hard cap ${self.monthly_hard_cap:.2f}"
            )

        # --- per-tenant cap (Redis-backed) ------------------------------
        if tenant_id:
            redis_spend = await self.get_tenant_spend(tenant_id)
            tenant_monthly = redis_spend + cost_usd

            # Resolve cap: prefer TenantConfigStore if available
            if self._tenant_config_store is not None:
                try:
                    tenant_cfg = await self._tenant_config_store.get_config(tenant_id)
                    cap = tenant_cfg.get_effective_monthly_cap()
                except Exception:
                    logger.warning(
                        "Failed to resolve tenant config for %s — using tier default",
                        tenant_id,
                        exc_info=True,
                    )
                    cap = self._resolve_tenant_cap(tenant_id)
            else:
                cap = self._resolve_tenant_cap(tenant_id)

            if tenant_monthly > cap:
                raise TenantBudgetExceeded(
                    f"Tenant {tenant_id!r} monthly spend ${tenant_monthly:.2f} "
                    f"exceeds cap ${cap:.2f}"
                )

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------

    @property
    def monthly_total(self) -> float:
        """Total spend for the current calendar month."""
        now = datetime.now(timezone.utc)
        return sum(
            r.cost_usd
            for r in self._records
            if r.timestamp.year == now.year and r.timestamp.month == now.month
        )

    def total_by_model(self) -> dict[str, float]:
        """Aggregate spend per model."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.model_id] = totals.get(r.model_id, 0) + r.cost_usd
        return totals

    def total_by_task_type(self) -> dict[str, float]:
        """Aggregate spend per task type."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.task_type] = totals.get(r.task_type, 0) + r.cost_usd
        return totals

    def total_by_tenant(self) -> dict[str, float]:
        """Aggregate spend per tenant."""
        totals: dict[str, float] = {}
        for r in self._records:
            totals[r.tenant_id] = totals.get(r.tenant_id, 0) + r.cost_usd
        return totals

    @property
    def call_count(self) -> int:
        return len(self._records)

    async def get_tenant_spend(self, tenant_id: str) -> float:
        """Return total spend (USD) for *tenant_id* in the current calendar month.

        Reads from Redis when available; falls back to in-memory records on
        Redis errors (fail-open).
        """
        if self._redis is not None:
            try:
                key = self._tenant_redis_key(tenant_id)
                client = (
                    self._redis._client
                    if hasattr(self._redis, "_client")
                    else self._redis
                )
                raw = await client.get(key)
                if raw is not None:
                    return float(raw)
            except Exception:
                logger.warning(
                    "Redis get failed for tenant spend (tenant=%s) — using in-memory fallback",
                    tenant_id,
                    exc_info=True,
                )
        return self._tenant_monthly_spend(tenant_id)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    @staticmethod
    def _tenant_redis_key(tenant_id: str) -> str:
        """Return the Redis key for this tenant's current-month spend bucket."""
        month = datetime.now(timezone.utc).strftime("%Y-%m")
        return f"spend:tenant:{tenant_id}:{month}"

    def _tenant_monthly_spend(self, tenant_id: str) -> float:
        """Return in-memory spend total for *tenant_id* in the current month."""
        now = datetime.now(timezone.utc)
        return sum(
            r.cost_usd
            for r in self._records
            if r.tenant_id == tenant_id
            and r.timestamp.year == now.year
            and r.timestamp.month == now.month
        )

    def _resolve_tenant_cap(self, tenant_id: str, tier: str = "standard") -> float:
        """Return the effective monthly cap (USD) for *tenant_id*.

        Parameters
        ----------
        tenant_id:
            The tenant whose cap should be resolved (used for logging only in
            the sync path; the async path uses Redis to look up the config).
        tier:
            Spend tier to use when no per-tenant override is available.
            Defaults to ``"standard"``.

        The async paths (``check_budget_async`` / ``record_async``) should
        call ``TenantConfigStore.get_config()`` first and pass the resolved
        tier here, or pass in an explicit cap via ``monthly_spend_cap``.
        """
        return TENANT_MONTHLY_CAPS.get(tier, TENANT_MONTHLY_CAPS["standard"])

    async def _increment_tenant_spend(self, tenant_id: str, cost_usd: float) -> None:
        """Atomically increment the Redis spend counter for *tenant_id* (fail-open)."""
        if self._redis is None:
            return
        try:
            key = self._tenant_redis_key(tenant_id)
            client = (
                self._redis._client
                if hasattr(self._redis, "_client")
                else self._redis
            )
            # INCRBYFLOAT returns the new value as a string
            await client.incrbyfloat(key, cost_usd)
            # Set TTL only if not already set (avoid resetting on every call)
            ttl = await client.ttl(key)
            if ttl < 0:
                await client.expire(key, _TENANT_SPEND_TTL)
        except Exception:
            logger.warning(
                "Redis increment failed for tenant spend (tenant=%s)",
                tenant_id,
                exc_info=True,
            )

    def _check_soft_alert(self) -> None:
        if not self._soft_alert_fired and self.monthly_total >= self.monthly_soft_alert:
            self._soft_alert_fired = True
            logger.warning(
                "SPEND SOFT ALERT: Monthly spend $%.2f reached soft threshold $%.2f",
                self.monthly_total,
                self.monthly_soft_alert,
            )
