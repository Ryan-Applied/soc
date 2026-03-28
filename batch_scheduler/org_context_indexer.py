"""Organisational Context Indexer — FR v1.2+ / docs/rag-design.md §6.

Reads asset records from the ``org_assets`` Postgres table (or the
``ctem_exposures`` table as a proxy when no dedicated table is present),
embeds each asset's description, and upserts the resulting vectors into the
``aluskort-org-context`` Qdrant collection.

Designed to be called weekly from the batch scheduler.

Typical usage::

    indexer = OrgContextIndexer()
    summary = await indexer.index_from_postgres(pg_pool, vector_db)

    results = await indexer.search_relevant_context(
        query="linux server in the DMZ running nginx",
        zone="dmz",
        vector_db=vector_db,
        embed_fn=my_embed_fn,
    )
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from shared.schemas.org_context import AssetType, OrgContextEntry

logger = logging.getLogger(__name__)

# ---- SQL used by this module ----

_FETCH_ORG_ASSETS_SQL = """
    SELECT
        asset_id,
        asset_name,
        asset_type,
        zone,
        tags,
        owner_team,
        criticality,
        description,
        cmdb_source,
        last_updated
    FROM org_assets
    WHERE description IS NOT NULL
      AND description <> ''
      AND (indexed_at IS NULL OR indexed_at < last_updated)
    ORDER BY last_updated ASC
    LIMIT %s
"""

_MARK_INDEXED_SQL = """
    UPDATE org_assets
    SET indexed_at = %s
    WHERE asset_id = %s
"""

# Fallback: use ctem_exposures as a proxy source when org_assets is absent.
_FETCH_CTEM_PROXY_SQL = """
    SELECT
        id::text               AS asset_id,
        asset_name,
        asset_type             AS asset_type,
        zone,
        ARRAY[]::TEXT[]        AS tags,
        NULL::TEXT             AS owner_team,
        severity               AS criticality,
        description,
        'ctem_exposures'       AS cmdb_source,
        updated_at             AS last_updated
    FROM ctem_exposures
    WHERE description IS NOT NULL
      AND description <> ''
    ORDER BY updated_at ASC
    LIMIT %s
"""


class OrgContextIndexer:
    """Index and retrieve organisational asset context from Qdrant.

    This class is stateless — all I/O dependencies are passed as arguments
    to keep it testable and avoid coupling to a specific DI framework.
    """

    COLLECTION = "aluskort-org-context"
    DEFAULT_BATCH_SIZE = 200

    # ------------------------------------------------------------------
    # Indexing
    # ------------------------------------------------------------------

    async def index_from_postgres(
        self,
        pg_pool: Any,
        vector_db: Any,
        embed_fn: Optional[Callable[[str], Any]] = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> dict[str, Any]:
        """Fetch unindexed assets from Postgres, embed, and upsert to Qdrant.

        Reads from ``org_assets`` and falls back to ``ctem_exposures`` if the
        dedicated table is unavailable.  Only rows where ``indexed_at`` is
        NULL or earlier than ``last_updated`` are processed, so re-runs are
        safe and idempotent.

        Args:
            pg_pool: Async Postgres connection pool (asyncpg-compatible).
                Must expose ``fetch(sql, *args)`` and ``execute(sql, *args)``.
            vector_db: :class:`~shared.db.vector.QdrantWrapper` (or compatible
                object with ``upsert_org_context``).
            embed_fn: Async callable ``(text: str) -> list[float]`` that
                produces an embedding vector.  When *None* the method raises
                ``ValueError`` — always required in production.
            batch_size: Maximum number of rows to process per run.

        Returns:
            Summary dict with ``assets_indexed``, ``assets_skipped``, and
            ``status`` keys.
        """
        if embed_fn is None:
            raise ValueError(
                "embed_fn is required for org_context indexing — "
                "provide an async embedding function via the embed_fn argument."
            )

        rows = await self._fetch_rows(pg_pool, batch_size)

        assets_indexed = 0
        assets_skipped = 0
        now_ts = datetime.now(timezone.utc)

        for row in rows:
            asset_id: str = row.get("asset_id") or str(uuid.uuid4())
            description: str = row.get("description") or ""

            if not description.strip():
                assets_skipped += 1
                logger.debug("Skipping asset %s — empty description", asset_id)
                continue

            try:
                embedding = await embed_fn(description)
            except Exception:
                logger.warning(
                    "Embedding failed for asset %s — skipping", asset_id, exc_info=True
                )
                assets_skipped += 1
                continue

            tags = list(row.get("tags") or [])
            asset_type = row.get("asset_type") or AssetType.SERVER.value
            zone = row.get("zone") or "unknown"

            try:
                vector_db.upsert_org_context(
                    asset_id=asset_id,
                    asset_type=asset_type,
                    tags=tags,
                    description=description,
                    zone=zone,
                    embedding=embedding,
                )
            except Exception:
                logger.error(
                    "Qdrant upsert failed for asset %s — skipping", asset_id, exc_info=True
                )
                assets_skipped += 1
                continue

            # Mark as indexed in Postgres (best-effort; don't fail the run)
            try:
                await pg_pool.execute(_MARK_INDEXED_SQL, now_ts, asset_id)
            except Exception:
                logger.warning(
                    "Failed to mark asset %s as indexed in Postgres", asset_id, exc_info=True
                )

            assets_indexed += 1
            logger.debug("Indexed org asset %s (zone=%s, type=%s)", asset_id, zone, asset_type)

        logger.info(
            "OrgContextIndexer run complete: indexed=%d skipped=%d",
            assets_indexed,
            assets_skipped,
        )
        return {
            "assets_indexed": assets_indexed,
            "assets_skipped": assets_skipped,
            "status": "completed",
        }

    async def _fetch_rows(self, pg_pool: Any, batch_size: int) -> list[dict[str, Any]]:
        """Fetch rows from org_assets, falling back to ctem_exposures proxy."""
        try:
            rows = await pg_pool.fetch(_FETCH_ORG_ASSETS_SQL, batch_size)
            if rows is not None:
                return [dict(r) for r in rows]
        except Exception as exc:
            # Table may not exist yet — try the proxy
            logger.warning(
                "org_assets query failed (%s) — trying ctem_exposures proxy", exc
            )

        try:
            rows = await pg_pool.fetch(_FETCH_CTEM_PROXY_SQL, batch_size)
            return [dict(r) for r in rows] if rows else []
        except Exception:
            logger.error("Both org_assets and ctem_exposures proxy queries failed", exc_info=True)
            return []

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    async def search_relevant_context(
        self,
        query: str,
        vector_db: Any,
        embed_fn: Callable[[str], Any],
        zone: Optional[str] = None,
        top_k: int = 10,
    ) -> list[OrgContextEntry]:
        """Embed *query* and retrieve the most relevant org-context entries.

        Args:
            query: Free-text query (e.g. ``"linux host in corp zone running sshd"``).
            vector_db: :class:`~shared.db.vector.QdrantWrapper` with
                ``search_org_context`` method.
            embed_fn: Async callable ``(text: str) -> list[float]``.
            zone: Optional zone filter passed to ``search_org_context``.
            top_k: Maximum number of entries to return.

        Returns:
            List of :class:`~shared.schemas.org_context.OrgContextEntry` objects
            decoded from Qdrant payloads, ordered by cosine similarity descending.
        """
        embedding: list[float] = await embed_fn(query)
        hits = vector_db.search_org_context(
            query_embedding=embedding,
            top_k=top_k,
            asset_zone_filter=zone,
        )

        entries: list[OrgContextEntry] = []
        for hit in hits:
            payload = hit.get("payload", {})
            entry = self._decode_payload(payload)
            if entry is not None:
                entries.append(entry)

        return entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_payload(payload: dict[str, Any]) -> Optional[OrgContextEntry]:
        """Decode a Qdrant payload dict into an :class:`OrgContextEntry`.

        Returns *None* and logs a warning if the payload is missing required
        fields so a single corrupt point never breaks the whole search result.
        """
        try:
            # Normalise asset_type to a valid enum value
            raw_type = payload.get("asset_type", AssetType.SERVER.value)
            try:
                asset_type = AssetType(raw_type)
            except ValueError:
                asset_type = AssetType.SERVER

            # last_updated may be stored as ISO string or datetime
            raw_ts = payload.get("last_updated")
            if isinstance(raw_ts, str):
                last_updated = datetime.fromisoformat(raw_ts)
            elif isinstance(raw_ts, datetime):
                last_updated = raw_ts
            else:
                last_updated = datetime.now(timezone.utc)

            return OrgContextEntry(
                asset_id=payload.get("asset_id", ""),
                asset_name=payload.get("asset_name", payload.get("asset_id", "")),
                asset_type=asset_type,
                zone=payload.get("zone", "unknown"),
                tags=list(payload.get("tags") or []),
                owner_team=payload.get("owner_team"),
                criticality=payload.get("criticality", "medium"),
                description=payload.get("description", ""),
                cmdb_source=payload.get("cmdb_source"),
                last_updated=last_updated,
            )
        except Exception:
            logger.warning("Failed to decode org-context payload: %s", payload, exc_info=True)
            return None
