"""Organisational asset context schema — FR v1.2+ / docs/rag-design.md §6.

Defines the canonical in-memory representation of CMDB / asset-inventory
entries that are indexed into the ``aluskort-org-context`` Qdrant collection
and surfaced by the Context Gateway during alert triage.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel


class AssetType(str, Enum):
    """Broad asset category.  Matches the ``asset_type`` column in ``org_assets``."""

    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    DATABASE = "database"
    IDENTITY = "identity"
    CLOUD_RESOURCE = "cloud_resource"


class OrgContextEntry(BaseModel):
    """A single organisational asset record, as stored and retrieved from vector search.

    Instances are produced by :class:`~batch_scheduler.org_context_indexer.OrgContextIndexer`
    when decoding Qdrant payloads.
    """

    asset_id: str
    asset_name: str
    asset_type: AssetType
    zone: str
    tags: list[str] = []
    owner_team: Optional[str] = None
    criticality: str = "medium"  # low, medium, high, critical
    description: str
    cmdb_source: Optional[str] = None  # e.g. "servicenow", "idp", "manual"
    last_updated: datetime
