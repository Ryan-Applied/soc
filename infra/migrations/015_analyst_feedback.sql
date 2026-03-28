-- ============================================================
-- ALUSKORT Analyst Feedback DDL Migration 015
-- FR-CSM-004: Captures structured analyst verdicts on investigation outcomes.
-- ============================================================

CREATE TABLE analyst_feedback (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id            TEXT NOT NULL REFERENCES investigation_state(investigation_id),
    analyst_id                  TEXT NOT NULL,
    verdict                     TEXT NOT NULL CHECK (verdict IN ('correct', 'incorrect', 'partial')),
    severity_agreement          BOOLEAN,
    classification_correct      BOOLEAN,
    recommended_action_correct  BOOLEAN,
    free_text                   TEXT,
    submitted_at                TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_feedback_investigation ON analyst_feedback(investigation_id);
CREATE INDEX idx_feedback_submitted     ON analyst_feedback(submitted_at);

-- ============================================================
-- ATLAS detections persistence table
-- FR-ATL-006: Required by ATLASSafetyGuard to enforce that
-- safety_relevant=TRUE detections cannot be classified as FP.
-- ============================================================

CREATE TABLE IF NOT EXISTS atlas_detections (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id    TEXT NOT NULL REFERENCES investigation_state(investigation_id),
    rule_id             TEXT NOT NULL,
    atlas_technique     TEXT NOT NULL DEFAULT '',
    attack_technique    TEXT NOT NULL DEFAULT '',
    threat_model_ref    TEXT NOT NULL DEFAULT '',
    alert_title         TEXT NOT NULL DEFAULT '',
    alert_severity      TEXT NOT NULL DEFAULT 'Medium',
    confidence          DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    safety_relevant     BOOLEAN NOT NULL DEFAULT FALSE,
    requires_immediate_action BOOLEAN NOT NULL DEFAULT FALSE,
    evidence            JSONB NOT NULL DEFAULT '{}',
    entities            JSONB NOT NULL DEFAULT '[]',
    fired_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id           TEXT NOT NULL DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_atlas_det_investigation ON atlas_detections(investigation_id);
CREATE INDEX IF NOT EXISTS idx_atlas_det_safety        ON atlas_detections(safety_relevant) WHERE safety_relevant = TRUE;
CREATE INDEX IF NOT EXISTS idx_atlas_det_rule          ON atlas_detections(rule_id);
CREATE INDEX IF NOT EXISTS idx_atlas_det_fired_at      ON atlas_detections(fired_at DESC);
