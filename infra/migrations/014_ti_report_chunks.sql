-- 014_ti_report_chunks.sql — FR-RAG-004
-- Stores TI report chunks produced by TIReportChunker before embedding to Qdrant.
-- Tracks per-chunk embedding status so the batch job can resume without re-processing.

CREATE TABLE IF NOT EXISTS ti_report_chunks (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id        UUID        NOT NULL,
    chunk_index      INTEGER     NOT NULL,
    total_chunks     INTEGER     NOT NULL,
    text             TEXT        NOT NULL,
    token_estimate   INTEGER     NOT NULL,
    embedded_at      TIMESTAMPTZ,
    qdrant_point_id  UUID,
    created_at       TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (report_id, chunk_index)
);

CREATE INDEX idx_ti_chunks_report
    ON ti_report_chunks (report_id);

-- Partial index for the batch job to quickly find chunks that still need embedding.
CREATE INDEX idx_ti_chunks_not_embedded
    ON ti_report_chunks (embedded_at)
    WHERE embedded_at IS NULL;
