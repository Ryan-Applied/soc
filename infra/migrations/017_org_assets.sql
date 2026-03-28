-- Migration 017: org_assets table for Organisational Context Index
-- FR v1.2+ / docs/rag-design.md §6
--
-- Stores CMDB / asset-inventory records that are periodically embedded into
-- the aluskort-org-context Qdrant collection by OrgContextIndexer.
--
-- indexed_at tracks the last time the row was embedded so the weekly batch
-- job can efficiently process only new or changed rows.

CREATE TABLE IF NOT EXISTS org_assets (
    asset_id     TEXT PRIMARY KEY,
    asset_name   TEXT NOT NULL,
    asset_type   TEXT NOT NULL,
    zone         TEXT NOT NULL,
    tags         TEXT[]    DEFAULT '{}',
    owner_team   TEXT,
    criticality  TEXT      DEFAULT 'medium',
    description  TEXT,
    cmdb_source  TEXT,
    indexed_at   TIMESTAMPTZ,
    last_updated TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_org_assets_zone
    ON org_assets (zone);

-- Partial index: quickly locate rows that have never been indexed or are
-- stale (last_updated > indexed_at is checked in application logic).
CREATE INDEX IF NOT EXISTS idx_org_assets_not_indexed
    ON org_assets (indexed_at)
    WHERE indexed_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_org_assets_type
    ON org_assets (asset_type);
