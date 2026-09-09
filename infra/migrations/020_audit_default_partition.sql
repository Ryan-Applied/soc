-- Keep append-only audit ingestion available outside the initially provisioned
-- month partitions. Dedicated monthly partitions can be attached operationally;
-- the default partition prevents current timestamps from failing in the interim.

CREATE TABLE IF NOT EXISTS audit_records_default
    PARTITION OF audit_records DEFAULT;
