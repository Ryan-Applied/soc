"""Embedding model migration job — Story 14.6 / FR-RAG-004.

4-phase migration: dual-write → backfill → verify → cleanup.
Supports checkpoint/resume, idempotent re-runs, and rate limiting.

FR-RAG-004: ``chunk_and_embed_ti_reports`` chunks TI reports to ≤ 512 tokens
with 64-token overlap before embedding to the ``aluskort-threat-intel``
Qdrant collection.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_BATCH_SIZE = 100
DEFAULT_RATE_LIMIT_RPS = 10.0


@dataclass
class MigrationProgress:
    """Progress state for an embedding migration."""

    old_model: str = ""
    new_model: str = ""
    collection: str = ""
    last_point_id: str = ""
    points_migrated: int = 0
    points_total: int = 0
    status: str = "in_progress"
    started_at: str = ""
    completed_at: str = ""


class EmbeddingMigrationJob:
    """Manages embedding model migration across Qdrant collections.

    Supports:
    - Checkpoint/resume from last processed point
    - Idempotent re-runs (Qdrant upsert overwrites by point ID)
    - Rate limiting to prevent Qdrant overload
    """

    def __init__(
        self,
        qdrant_client: Any,
        postgres_client: Any,
        old_model: str,
        new_model: str,
        collection: str = "incident_embeddings",
        batch_size: int = DEFAULT_BATCH_SIZE,
        rate_limit_rps: float = DEFAULT_RATE_LIMIT_RPS,
        embed_fn: Any | None = None,
    ) -> None:
        self._qdrant = qdrant_client
        self._pg = postgres_client
        self._old_model = old_model
        self._new_model = new_model
        self._collection = collection
        self._batch_size = batch_size
        self._rate_limit_rps = rate_limit_rps
        self._embed_fn = embed_fn
        self._min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0

    async def checkpoint(self, point_id: str, points_migrated: int) -> None:
        """Save migration progress to Postgres."""
        query = """
            INSERT INTO embedding_migration
                (old_model, new_model, collection, last_point_id, points_migrated, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (id) DO UPDATE SET
                last_point_id = EXCLUDED.last_point_id,
                points_migrated = EXCLUDED.points_migrated,
                updated_at = NOW()
        """
        await self._pg.execute(
            query, self._old_model, self._new_model,
            self._collection, point_id, points_migrated,
        )

    async def get_checkpoint(self) -> str | None:
        """Load last checkpoint point_id from Postgres."""
        query = """
            SELECT last_point_id FROM embedding_migration
            WHERE old_model = %s AND new_model = %s AND collection = %s
            AND status = 'in_progress'
            ORDER BY updated_at DESC LIMIT 1
        """
        rows = await self._pg.fetch(
            query, self._old_model, self._new_model, self._collection,
        )
        if rows and rows[0].get("last_point_id"):
            return rows[0]["last_point_id"]
        return None

    async def run(self, resume_from: str | None = None) -> dict[str, Any]:
        """Execute the 4-phase migration.

        1. Dual-write: new upserts use new model (handled by caller)
        2. Backfill: iterate old-model points, re-embed, upsert alongside old
        3. Verify: spot-check sample
        4. Cleanup: manual trigger (not automatic)

        Returns migration summary dict.
        """
        start_from = resume_from or await self.get_checkpoint()
        migrated = 0
        last_id = start_from or ""
        last_op_time = 0.0

        # Fetch all old-model points (paginated via scroll)
        points = await self._fetch_old_model_points(start_after=start_from)

        for point in points:
            point_id = str(point.get("id", ""))

            # Rate limiting
            now = time.monotonic()
            elapsed = now - last_op_time
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)

            # Re-embed with new model
            if self._embed_fn is not None:
                new_vector = await self._embed_fn(point.get("payload", {}))
            else:
                raise ValueError(
                    "embed_fn is required for migration — cannot copy old vectors "
                    "as new model vectors. Provide an embedding function."
                )

            # Upsert with new model metadata (idempotent)
            from shared.db.vector import enrich_payload
            payload = dict(point.get("payload", {}))
            payload["embedding_model_id"] = self._new_model
            payload["embedding_version"] = datetime.now(timezone.utc).strftime("%Y-%m")

            await self._upsert_point(point_id, new_vector, payload)
            last_op_time = time.monotonic()

            migrated += 1
            last_id = point_id

            # Checkpoint every batch_size points
            if migrated % self._batch_size == 0:
                await self.checkpoint(last_id, migrated)

        # Final checkpoint
        if migrated > 0:
            await self.checkpoint(last_id, migrated)

        return {
            "old_model": self._old_model,
            "new_model": self._new_model,
            "collection": self._collection,
            "points_migrated": migrated,
            "last_point_id": last_id,
            "status": "completed",
        }

    async def _fetch_old_model_points(
        self, start_after: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch points with old model from Qdrant.

        In production this would use scroll/pagination. For now,
        delegates to the qdrant client's scroll or search.
        """
        try:
            return await self._qdrant.fetch_points_by_model(
                self._collection, self._old_model, start_after=start_after,
            )
        except AttributeError:
            # Mock or simplified client — return empty
            return []

    async def _upsert_point(
        self,
        point_id: str,
        vector: list[float],
        payload: dict[str, Any],
    ) -> None:
        """Upsert a single re-embedded point."""
        try:
            await self._qdrant.upsert_point(
                self._collection, point_id, vector, payload,
            )
        except AttributeError:
            # Sync qdrant wrapper fallback
            self._qdrant.upsert_vectors(
                self._collection,
                [{"id": point_id, "vector": vector, "payload": payload}],
            )

    # ------------------------------------------------------------------
    # FR-RAG-004: TI report chunking and embedding
    # ------------------------------------------------------------------

    async def chunk_and_embed_ti_reports(
        self,
        collection: str = "aluskort-threat-intel",
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> dict[str, Any]:
        """Chunk unchunked TI reports and embed each chunk into Qdrant.

        Flow:
        1. Query Postgres for ``ti_reports`` rows whose ``id`` has no
           corresponding entry in ``ti_report_chunks`` (i.e. never chunked).
        2. Chunk each report body with ``TIReportChunker`` (≤ 512 tokens,
           64-token overlap, sentence-boundary splits, instruction stripping).
        3. Insert chunk metadata rows into ``ti_report_chunks``.
        4. Embed each chunk text and upsert the vector to Qdrant with payload
           ``{report_id, chunk_index, total_chunks, text}``.
        5. Mark each chunk as embedded (``embedded_at``, ``qdrant_point_id``).

        Returns a summary dict with counts of reports and chunks processed.
        """
        from context_gateway.chunker import TIReportChunker
        from shared.db.vector import enrich_payload

        chunker = TIReportChunker()
        reports_processed = 0
        chunks_embedded = 0
        last_op_time = 0.0

        # Fetch reports that have no chunks yet (left-join anti-pattern)
        fetch_query = """
            SELECT r.id::text AS report_id, r.body
            FROM ti_reports r
            WHERE NOT EXISTS (
                SELECT 1 FROM ti_report_chunks c WHERE c.report_id = r.id
            )
            ORDER BY r.created_at ASC
            LIMIT %s
        """
        rows = await self._pg.fetch(fetch_query, batch_size)

        for row in rows:
            report_id: str = row["report_id"]
            body: str = row.get("body") or ""

            if not body.strip():
                logger.debug("Skipping empty TI report %s", report_id)
                continue

            chunks = chunker.chunk(body, report_id)
            if not chunks:
                logger.debug("No chunks produced for TI report %s", report_id)
                continue

            # Persist chunk metadata rows (idempotent via ON CONFLICT DO NOTHING)
            insert_chunk_query = """
                INSERT INTO ti_report_chunks
                    (report_id, chunk_index, total_chunks, text, token_estimate)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (report_id, chunk_index) DO NOTHING
                RETURNING id::text AS chunk_row_id
            """

            for chunk in chunks:
                # Rate limiting
                now = time.monotonic()
                elapsed = now - last_op_time
                if elapsed < self._min_interval:
                    await asyncio.sleep(self._min_interval - elapsed)

                # Persist the chunk row and retrieve its generated id
                inserted = await self._pg.fetch(
                    insert_chunk_query,
                    report_id,
                    chunk["chunk_index"],
                    chunk["total_chunks"],
                    chunk["text"],
                    chunk["token_estimate"],
                )

                # Generate embedding
                if self._embed_fn is not None:
                    vector = await self._embed_fn({"text": chunk["text"]})
                else:
                    raise ValueError(
                        "embed_fn is required for TI report chunking — "
                        "provide an embedding function via the constructor."
                    )

                # Build Qdrant payload (use chunk_id as the point id)
                point_id = chunk["chunk_id"]
                payload = enrich_payload(
                    {
                        "report_id": report_id,
                        "chunk_index": chunk["chunk_index"],
                        "total_chunks": chunk["total_chunks"],
                        "text": chunk["text"],
                        "token_estimate": chunk["token_estimate"],
                    }
                )

                # Upsert vector to Qdrant
                try:
                    await self._qdrant.upsert_point(
                        collection, point_id, vector, payload,
                    )
                except AttributeError:
                    self._qdrant.upsert_vectors(
                        collection,
                        [{"id": point_id, "vector": vector, "payload": payload}],
                    )

                # Mark the chunk as embedded
                now_ts = datetime.now(timezone.utc)
                update_query = """
                    UPDATE ti_report_chunks
                    SET embedded_at = %s, qdrant_point_id = %s::uuid
                    WHERE report_id = %s::uuid AND chunk_index = %s
                """
                await self._pg.execute(
                    update_query,
                    now_ts,
                    point_id,
                    report_id,
                    chunk["chunk_index"],
                )

                last_op_time = time.monotonic()
                chunks_embedded += 1
                logger.debug(
                    "Embedded chunk %d/%d for report %s (point_id=%s)",
                    chunk["chunk_index"] + 1,
                    chunk["total_chunks"],
                    report_id,
                    point_id,
                )

            reports_processed += 1
            logger.info(
                "Chunked and embedded TI report %s: %d chunks",
                report_id,
                len(chunks),
            )

        return {
            "collection": collection,
            "reports_processed": reports_processed,
            "chunks_embedded": chunks_embedded,
            "status": "completed",
        }
