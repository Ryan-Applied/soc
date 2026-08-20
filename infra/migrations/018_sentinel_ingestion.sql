-- Durable Microsoft Sentinel ingestion state.

CREATE TABLE IF NOT EXISTS sentinel_ingestion_checkpoints (
    connector_id TEXT PRIMARY KEY,
    watermark TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sentinel_ingested_alerts (
    connector_id TEXT NOT NULL,
    alert_id TEXT NOT NULL,
    time_generated TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (connector_id, alert_id)
);

CREATE INDEX IF NOT EXISTS idx_sentinel_ingested_alerts_processed
    ON sentinel_ingested_alerts (processed_at);
