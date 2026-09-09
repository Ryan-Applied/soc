-- ============================================================
-- ALUSKORT Audit DDL Migration 006 — Story 13.3
-- Creates audit_records partitioned table, indexes, and
-- append-only immutability trigger (SOC 2 CC6.8 control).
-- ============================================================

-- ============================================================
-- audit_records — partitioned by month on timestamp
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_records (
    audit_id          TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    sequence_number   BIGINT NOT NULL,
    previous_hash     TEXT NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL,
    ingested_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    event_type        TEXT NOT NULL,
    event_category    TEXT NOT NULL,
    severity          TEXT NOT NULL DEFAULT 'info',

    actor_type        TEXT NOT NULL,
    actor_id          TEXT NOT NULL,
    actor_permissions TEXT[] DEFAULT '{}',

    investigation_id  TEXT DEFAULT '',
    alert_id          TEXT DEFAULT '',
    entity_ids        TEXT[] DEFAULT '{}',

    context           JSONB NOT NULL DEFAULT '{}',
    decision          JSONB NOT NULL DEFAULT '{}',
    outcome           JSONB NOT NULL DEFAULT '{}',

    record_hash       TEXT NOT NULL,
    record_version    TEXT NOT NULL DEFAULT '1.0',

    PRIMARY KEY (tenant_id, sequence_number, timestamp)
) PARTITION BY RANGE (timestamp);

-- ============================================================
-- Monthly partitions (current + 3 forward months)
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_records_2026_02 PARTITION OF audit_records
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE IF NOT EXISTS audit_records_2026_03 PARTITION OF audit_records
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE IF NOT EXISTS audit_records_2026_04 PARTITION OF audit_records
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE IF NOT EXISTS audit_records_2026_05 PARTITION OF audit_records
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

-- ============================================================
-- Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_audit_tenant_ts
    ON audit_records (tenant_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_investigation
    ON audit_records (investigation_id, timestamp)
    WHERE investigation_id != '';

CREATE INDEX IF NOT EXISTS idx_audit_alert
    ON audit_records (alert_id, timestamp)
    WHERE alert_id != '';

CREATE INDEX IF NOT EXISTS idx_audit_event_type
    ON audit_records (event_type, timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_category
    ON audit_records (event_category, timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_records (actor_id, timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_severity
    ON audit_records (severity, timestamp)
    WHERE severity IN ('warning', 'critical');

CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_tenant_seq
    ON audit_records (tenant_id, sequence_number, timestamp);

-- ============================================================
-- Immutability trigger — SOC 2 CC6.8 control
-- Blocks UPDATE and DELETE on audit_records.
-- ============================================================
CREATE OR REPLACE FUNCTION audit_immutable_guard()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_records is append-only: % operations are forbidden', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS enforce_audit_immutability ON audit_records;
CREATE TRIGGER enforce_audit_immutability
    BEFORE UPDATE OR DELETE ON audit_records
    FOR EACH ROW EXECUTE FUNCTION audit_immutable_guard();
