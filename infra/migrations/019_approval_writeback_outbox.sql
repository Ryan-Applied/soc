-- Durable analyst decisions and the transactional Sentinel write-back outbox.

CREATE TABLE IF NOT EXISTS approval_decisions (
    approval_id UUID PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigation_state(investigation_id),
    tenant_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    reason TEXT,
    decided_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_context JSONB NOT NULL DEFAULT '{}',
    UNIQUE (investigation_id)
);

CREATE INDEX IF NOT EXISTS idx_approval_decisions_tenant_time
    ON approval_decisions (tenant_id, decided_at DESC);

CREATE TABLE IF NOT EXISTS sentinel_writeback_outbox (
    outbox_id UUID PRIMARY KEY,
    approval_id UUID NOT NULL REFERENCES approval_decisions(approval_id),
    investigation_id TEXT NOT NULL REFERENCES investigation_state(investigation_id),
    tenant_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processing_started_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_sentinel_writeback_pending
    ON sentinel_writeback_outbox (status, next_attempt_at)
    WHERE status IN ('pending', 'failed', 'processing');
