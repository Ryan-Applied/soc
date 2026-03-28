"""TI report chunker — FR-RAG-004.

Splits threat-intelligence report text into overlapping chunks of at most
512 tokens (≈ 2 048 chars) with a 64-token (≈ 256-char) sliding overlap,
respecting sentence boundaries so embeddings capture complete thoughts.

Instruction-shaped sentences are stripped using the same patterns as
``summarizer.py`` before chunking, so injected content never reaches the
embedding store.
"""

from __future__ import annotations

import re
import uuid
from typing import Optional

from context_gateway.injection_detector import INJECTION_PATTERNS

# ---------- Instruction-verb filter (mirrors summarizer.py) ------------------

_INSTRUCTION_VERBS = re.compile(
    r"\b(?:ignore|pretend|override|forget|reveal|act\s+as)\b",
    re.IGNORECASE,
)

# ---------- Sentence-boundary patterns ---------------------------------------

# Split on ". " / ".\n" / "!\n" / "? " etc. keeping the delimiter with the
# preceding sentence so that sentence text is complete.
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+|\n+")


def _split_sentences(text: str) -> list[str]:
    """Split *text* into sentence fragments on boundary punctuation or newlines."""
    parts = _SENTENCE_SPLIT_RE.split(text)
    return [s.strip() for s in parts if s.strip()]


def _is_instruction_sentence(sentence: str) -> bool:
    """Return True if *sentence* looks like an injected instruction."""
    if _INSTRUCTION_VERBS.search(sentence):
        return True
    if any(p.search(sentence) for p in INJECTION_PATTERNS):
        return True
    return False


class TIReportChunker:
    """Chunk TI report text for embedding into Qdrant.

    Attributes:
        MAX_TOKENS:     Upper token limit per chunk (FR-RAG-004: 512).
        OVERLAP_TOKENS: Token overlap between consecutive chunks (FR-RAG-004: 64).
        CHARS_PER_TOKEN: Character-to-token approximation used across the
                         codebase (prompt_builder.py style: 4 chars ≈ 1 token).
    """

    MAX_TOKENS: int = 512
    OVERLAP_TOKENS: int = 64
    CHARS_PER_TOKEN: int = 4  # consistent with prompt_builder.py approximation

    @property
    def _max_chars(self) -> int:
        return self.MAX_TOKENS * self.CHARS_PER_TOKEN  # 2 048

    @property
    def _overlap_chars(self) -> int:
        return self.OVERLAP_TOKENS * self.CHARS_PER_TOKEN  # 256

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chunk(self, text: str, report_id: str) -> list[dict]:
        """Chunk *text* into overlapping, instruction-free segments.

        Returns a list of dicts, each with:
            chunk_id      – deterministic UUID (report_id + index namespace)
            text          – cleaned chunk text
            token_estimate – approximate token count (len // CHARS_PER_TOKEN)
            chunk_index   – 0-based position
            total_chunks  – total number of chunks in this report
        """
        if not text or not text.strip():
            return []

        cleaned = self._strip_instructions(text)
        if not cleaned.strip():
            return []

        raw_chunks = self._build_chunks(cleaned)
        raw_chunks = self._deduplicate(raw_chunks)

        total = len(raw_chunks)
        result: list[dict] = []
        for idx, chunk_text in enumerate(raw_chunks):
            chunk_uuid = str(
                uuid.uuid5(
                    uuid.UUID(report_id) if _is_valid_uuid(report_id) else uuid.NAMESPACE_URL,
                    f"{report_id}:chunk:{idx}",
                )
            )
            result.append(
                {
                    "chunk_id": chunk_uuid,
                    "text": chunk_text,
                    "token_estimate": max(1, len(chunk_text) // self.CHARS_PER_TOKEN),
                    "chunk_index": idx,
                    "total_chunks": total,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _strip_instructions(self, text: str) -> str:
        """Remove instruction-shaped sentences from *text* (mirrors summarizer.remove_instructions)."""
        sentences = _split_sentences(text)
        kept: list[str] = []
        for s in sentences:
            if not _is_instruction_sentence(s):
                kept.append(s)
        return " ".join(kept)

    def _build_chunks(self, text: str) -> list[str]:
        """Build sliding-window chunks that respect sentence boundaries.

        Algorithm:
        1. Split cleaned text into sentences.
        2. Greedily accumulate sentences until the next one would exceed
           MAX_CHARS.  When that happens, flush the current window as a chunk.
        3. The next window starts by replaying the last OVERLAP_CHARS worth
           of sentences from the flushed window (the overlap tail), then
           continues from where we left off.
        """
        sentences = _split_sentences(text)
        if not sentences:
            return []

        chunks: list[str] = []
        window: list[str] = []  # sentences in the current window
        window_len: int = 0      # char count of current window (approx, with spaces)

        i = 0
        while i < len(sentences):
            sentence = sentences[i]
            # +1 for the space that joins sentences
            added_len = len(sentence) + (1 if window else 0)

            if window_len + added_len > self._max_chars and window:
                # Flush current window
                chunk_text = " ".join(window)
                chunks.append(chunk_text)

                # Build overlap tail: walk backwards through window sentences
                # until we have >= OVERLAP_CHARS characters.
                overlap: list[str] = []
                overlap_len = 0
                for sent in reversed(window):
                    overlap.insert(0, sent)
                    overlap_len += len(sent) + (1 if len(overlap) > 1 else 0)
                    if overlap_len >= self._overlap_chars:
                        break

                # Start new window from the overlap tail (do NOT advance i;
                # the current sentence will be re-evaluated on the next pass).
                window = overlap
                window_len = sum(len(s) for s in window) + max(0, len(window) - 1)
            else:
                window.append(sentence)
                window_len += added_len
                i += 1

        # Flush the final window
        if window:
            chunk_text = " ".join(window)
            # Only add if this is meaningfully different from the last chunk
            # (avoids a tiny trailing fragment that is pure overlap).
            if not chunks or chunk_text != chunks[-1]:
                chunks.append(chunk_text)

        return chunks

    def _deduplicate(self, chunks: list[str]) -> list[str]:
        """Remove near-identical consecutive chunks.

        A chunk is considered a duplicate of a previous one when the first
        50 characters of both (stripped, lowercased) are identical — i.e.
        > 90 % overlap at the start, which indicates the overlap window
        produced a redundant fragment.
        """
        if not chunks:
            return []

        seen_prefixes: list[str] = []
        result: list[str] = []

        for chunk in chunks:
            prefix = chunk.strip().lower()[:50]
            # Check against all previously kept prefixes
            is_dup = any(prefix == p for p in seen_prefixes)
            if not is_dup:
                seen_prefixes.append(prefix)
                result.append(chunk)

        return result


# ---------- Module-level helper ----------------------------------------------

def _is_valid_uuid(value: str) -> bool:
    """Return True if *value* is a parseable UUID string."""
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False
