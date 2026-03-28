-- ============================================================
-- ALUSKORT Tenant Spend Caps DDL Migration 016
-- NFR-SCL-003: Per-tenant monthly LLM spend caps.
-- ============================================================

-- Create the tenants table if it does not already exist.
-- This is the canonical row for each onboarded tenant and is the
-- source of truth for spend_tier / monthly_spend_cap_usd consumed
-- by TenantConfig.get_effective_monthly_cap().
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id           TEXT PRIMARY KEY,
    display_name        TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- NFR-SCL-003 columns — added idempotently so this migration is
-- safe to re-run against a cluster that already has the table.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS spend_tier          TEXT NOT NULL DEFAULT 'standard',
    ADD COLUMN IF NOT EXISTS monthly_spend_cap_usd DECIMAL(10,2);

-- Enforce only known tier values.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenants_spend_tier_check'
    ) THEN
        ALTER TABLE tenants
            ADD CONSTRAINT tenants_spend_tier_check
            CHECK (spend_tier IN ('premium', 'standard', 'trial'));
    END IF;
END;
$$;

CREATE INDEX IF NOT EXISTS idx_tenants_spend_tier ON tenants(spend_tier);
