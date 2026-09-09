"""Apply ordered PostgreSQL migrations to new or persistent databases."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
from pathlib import Path

import asyncpg


LOCK_ID = 2_026_032_900
DEFAULT_MIGRATIONS = Path(__file__).resolve().parents[1] / "migrations"


def migration_files(directory: Path) -> list[Path]:
    """Return migration files in their numeric filename order."""
    return sorted(path for path in directory.glob("*.sql") if path.is_file())


async def apply_migrations(dsn: str, directory: Path = DEFAULT_MIGRATIONS) -> list[str]:
    """Apply each migration once and reject edits to recorded migrations."""
    if not dsn:
        raise RuntimeError("POSTGRES_DSN is required")

    files = migration_files(directory)
    if not files:
        raise RuntimeError(f"No SQL migrations found in {directory}")

    connection = await asyncpg.connect(dsn)
    applied_now: list[str] = []
    try:
        await connection.execute("SELECT pg_advisory_lock($1)", LOCK_ID)
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                filename TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        rows = await connection.fetch("SELECT filename, sha256 FROM schema_migrations")
        applied = {row["filename"]: row["sha256"] for row in rows}

        for path in files:
            sql = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(sql.encode("utf-8")).hexdigest()
            recorded = applied.get(path.name)
            if recorded:
                if recorded != digest:
                    raise RuntimeError(
                        f"Applied migration checksum changed: {path.name}"
                    )
                continue

            async with connection.transaction():
                await connection.execute(sql)
                await connection.execute(
                    "INSERT INTO schema_migrations (filename, sha256) VALUES ($1, $2)",
                    path.name,
                    digest,
                )
            applied_now.append(path.name)
    finally:
        try:
            await connection.execute("SELECT pg_advisory_unlock($1)", LOCK_ID)
        finally:
            await connection.close()

    return applied_now


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("POSTGRES_DSN", ""))
    parser.add_argument("--directory", type=Path, default=DEFAULT_MIGRATIONS)
    args = parser.parse_args()
    applied = asyncio.run(apply_migrations(args.dsn, args.directory))
    if applied:
        print(f"Applied {len(applied)} migration(s): {', '.join(applied)}")
    else:
        print("Database schema is current")


if __name__ == "__main__":
    main()
