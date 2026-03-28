"""
Cross-encoder reranking for vector search results.
Uses sentence-transformers cross-encoder when available,
falls back to BM25-style keyword scoring when not installed.

FR-ENR-007 / Could Have v1.2+
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Callable
from concurrent.futures import Executor
from typing import Any, Optional

logger = logging.getLogger(__name__)


class CrossEncoderReranker:
    """Cross-encoder reranker for vector search candidates.

    When ``sentence-transformers`` is available the cross-encoder runs an
    actual transformer model on (query, passage) pairs and produces real
    relevance scores.  When the library is not installed a lightweight
    BM25-style keyword scorer is used as a zero-dependency fallback so the
    pipeline always produces deterministic, ranked results.

    Instantiation is cheap — the underlying model is loaded lazily on the
    first call to :meth:`rerank`.

    Args:
        model_name: HuggingFace model id for the cross-encoder.  Only used
            when ``sentence-transformers`` is installed.
    """

    def __init__(
        self,
        model_name: str = "cross-encoder/ms-marco-MiniLM-L-12-v2",
    ) -> None:
        self._model_name = model_name
        self._model: Any | None = None
        self._model_loaded: bool = False

    def _load_model(self) -> None:
        """Lazy-load the cross-encoder on first use."""
        if self._model_loaded:
            return
        try:
            from sentence_transformers import CrossEncoder  # type: ignore[import-untyped]

            self._model = CrossEncoder(self._model_name)
            logger.info("Cross-encoder loaded: %s", self._model_name)
        except ImportError:
            logger.warning(
                "sentence-transformers not installed — "
                "falling back to BM25-style keyword reranking. "
                "Install with: pip install sentence-transformers"
            )
            self._model = None
        self._model_loaded = True

    # ------------------------------------------------------------------
    # Internal scoring helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        """Lower-case, split on non-alphanumeric characters."""
        return re.findall(r"[a-z0-9]+", text.lower())

    def _bm25_score(self, query: str, passage: str) -> float:
        """Simple keyword overlap score: |query_terms ∩ passage_terms| / |query_terms|.

        Returns 0.0 when the query has no terms (safe default).
        """
        query_terms = set(self._tokenize(query))
        if not query_terms:
            return 0.0
        passage_terms = set(self._tokenize(passage))
        overlap = query_terms & passage_terms
        return len(overlap) / len(query_terms)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def rerank(
        self,
        query: str,
        candidates: list[dict[str, Any]],
        text_field: str = "text",
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """Rerank *candidates* against *query* and return the top-k.

        Each returned dict is a shallow copy of the original candidate with
        an additional ``rerank_score`` field (float).

        Args:
            query: The user / system query string.
            candidates: List of candidate dicts.  Each must contain the key
                specified by *text_field*.
            text_field: Key inside each candidate dict that holds the passage
                text to score.
            top_k: Maximum number of results to return.

        Returns:
            A list of at most *top_k* candidate dicts sorted by
            ``rerank_score`` descending, each enriched with that field.
        """
        if not candidates:
            return []

        self._load_model()

        if self._model is not None:
            # Full cross-encoder scoring
            pairs = [(query, c.get(text_field, "")) for c in candidates]
            raw_scores: list[float] = self._model.predict(pairs).tolist()
        else:
            # BM25-style fallback
            raw_scores = [
                self._bm25_score(query, c.get(text_field, ""))
                for c in candidates
            ]

        scored: list[dict[str, Any]] = []
        for candidate, score in zip(candidates, raw_scores):
            enriched = dict(candidate)
            enriched["rerank_score"] = float(score)
            scored.append(enriched)

        scored.sort(key=lambda x: x["rerank_score"], reverse=True)
        return scored[:top_k]

    async def rerank_async(
        self,
        query: str,
        candidates: list[dict[str, Any]],
        text_field: str = "text",
        top_k: int = 5,
        executor: Optional[Executor] = None,
    ) -> list[dict[str, Any]]:
        """Async wrapper around :meth:`rerank` — runs in a thread executor.

        Safe to call from an asyncio event loop without blocking it.

        Args:
            query: The user / system query string.
            candidates: List of candidate dicts.
            text_field: Key that holds the passage text in each candidate.
            top_k: Maximum number of results to return.
            executor: Optional custom executor.  Uses the default loop
                executor (thread pool) when *None*.
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            executor,
            lambda: self.rerank(query, candidates, text_field, top_k),
        )
