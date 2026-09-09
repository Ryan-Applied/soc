"""Tests for the persistent-database migration runner."""

from __future__ import annotations

from pathlib import Path

from infra.scripts.apply_migrations import migration_files


def test_migration_files_are_sorted_and_ignore_non_sql(tmp_path: Path):
    (tmp_path / "019_last.sql").write_text("SELECT 19;")
    (tmp_path / "018_first.sql").write_text("SELECT 18;")
    (tmp_path / "README.md").write_text("not a migration")

    assert [path.name for path in migration_files(tmp_path)] == [
        "018_first.sql",
        "019_last.sql",
    ]


def test_existing_migrations_are_safe_for_initial_baseline_replay():
    root = Path(__file__).resolve().parents[2] / "infra" / "migrations"
    migration_006 = (root / "006_audit_records.sql").read_text()
    migration_014 = (root / "014_ti_report_chunks.sql").read_text()
    migration_015 = (root / "015_analyst_feedback.sql").read_text()

    assert "DROP TRIGGER IF EXISTS enforce_audit_immutability" in migration_006
    assert "CREATE INDEX IF NOT EXISTS idx_ti_chunks_report" in migration_014
    assert "CREATE TABLE IF NOT EXISTS analyst_feedback" in migration_015


def test_current_audit_timestamps_have_a_default_partition():
    root = Path(__file__).resolve().parents[2] / "infra" / "migrations"
    sql = (root / "020_audit_default_partition.sql").read_text()

    assert "PARTITION OF audit_records DEFAULT" in sql
