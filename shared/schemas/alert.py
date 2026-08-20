"""Canonical alert schema — the single source of truth for ingested alerts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

SeverityLevel = Literal["critical", "high", "medium", "low", "informational"]


class CanonicalAlert(BaseModel):
    """ALUSKORT's internal alert representation.

    Every ingest adapter must map source-specific alerts into this schema
    before publishing to ``alerts.normalized`` Kafka topic.
    """

    alert_id: str
    source: str
    timestamp: str
    title: str
    description: str
    severity: SeverityLevel
    tactics: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    entities_raw: str = ""
    product: str = ""
    tenant_id: str = ""
    source_context: dict[str, Any] = Field(default_factory=dict)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _validate_timestamp(cls, v: str) -> str:
        """Ensure timestamp is valid ISO 8601."""
        datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v
