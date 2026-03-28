"""Weekly asset auto-discovery: scans Postgres telemetry tables to discover
assets not yet tracked in the CTEM exposure inventory, then emits discovery
events to Kafka topic ctem.assets.discovered.

FR-CTM-008
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

DISCOVERY_TOPIC = "ctem.assets.discovered"
REDIS_LAST_SCAN_KEY = "ctem:asset_discovery:last_scan"

# seconds — 35 days; Redis key TTL long enough to survive a full scan cycle
_REDIS_KEY_TTL = 35 * 24 * 3600

# Query: exposures not seen in the last 7 days (stale assets)
_SQL_STALE = """
    SELECT DISTINCT asset_id, asset_zone
    FROM ctem_exposures
    WHERE last_seen < NOW() - INTERVAL '7 days'
"""

# Query: hosts that have been active in the last 7 days (from audit log)
_SQL_RECENT_AUDIT = """
    SELECT DISTINCT source_host AS asset_id
    FROM audit_events
    WHERE created_at > NOW() - INTERVAL '7 days'
"""

# Query: all asset_ids currently tracked in ctem_exposures
_SQL_KNOWN_ASSETS = """
    SELECT DISTINCT asset_id FROM ctem_exposures
"""


class AssetDiscoveryScheduler:
    """Periodically scans Postgres telemetry tables for undiscovered assets
    and emits Kafka events for each net-new asset found.

    Parameters
    ----------
    pg_pool:
        A :class:`shared.db.postgres.PostgresClient` instance (must already be
        connected before ``run_forever()`` is called).
    kafka_producer:
        Any object with an ``async produce(topic, payload)`` method.
    redis_client:
        Optional :class:`shared.db.redis_cache.RedisClient` instance for
        tracking last-scan timestamps.  When ``None``, last-scan tracking is
        skipped (fail-open).
    scan_interval_hours:
        How often to run a full discovery scan.  Defaults to 168 h (weekly).
    """

    def __init__(
        self,
        pg_pool: Any,
        kafka_producer: Any,
        redis_client: Any | None = None,
        scan_interval_hours: float = 168,
    ) -> None:
        self._pg = pg_pool
        self._producer = kafka_producer
        self._redis = redis_client
        self._scan_interval_seconds = scan_interval_hours * 3600

    # ------------------------------------------------------------------
    # public
    # ------------------------------------------------------------------

    async def run_forever(self) -> None:
        """Run discovery scans on the configured interval until cancelled."""
        logger.info(
            "AssetDiscoveryScheduler started (interval=%.1f h)",
            self._scan_interval_seconds / 3600,
        )
        while True:
            try:
                await self._discover_assets()
            except asyncio.CancelledError:
                logger.info("AssetDiscoveryScheduler cancelled — shutting down")
                raise
            except Exception:
                logger.error(
                    "Asset discovery scan failed — will retry next interval",
                    exc_info=True,
                )
            await asyncio.sleep(self._scan_interval_seconds)

    # ------------------------------------------------------------------
    # core scan
    # ------------------------------------------------------------------

    async def _discover_assets(self) -> None:
        """Execute one full discovery scan.

        1. Fetch stale assets from ctem_exposures.
        2. Fetch recently-active hosts from audit_events.
        3. Load the current known-asset set from ctem_exposures.
        4. Compute net-new assets (present in audit log but absent from the
           exposure inventory).
        5. Emit a Kafka event for each net-new asset.
        6. Record the scan timestamp in Redis.
        """
        scan_start = datetime.now(timezone.utc)
        logger.info("Asset discovery scan starting at %s", scan_start.isoformat())

        # --- 1. Stale assets -------------------------------------------
        try:
            stale_rows = await self._pg.fetch_many(_SQL_STALE)
        except Exception:
            logger.error("Failed to query stale assets", exc_info=True)
            stale_rows = []

        stale_assets: dict[str, str] = {
            row["asset_id"]: row.get("asset_zone", "") for row in stale_rows
        }

        # --- 2. Recently-active hosts from audit log -------------------
        try:
            audit_rows = await self._pg.fetch_many(_SQL_RECENT_AUDIT)
        except Exception:
            logger.error("Failed to query audit_events for active hosts", exc_info=True)
            audit_rows = []

        audit_hosts: set[str] = {
            row["asset_id"] for row in audit_rows if row.get("asset_id")
        }

        # --- 3. Known assets currently tracked in ctem_exposures -------
        try:
            known_rows = await self._pg.fetch_many(_SQL_KNOWN_ASSETS)
        except Exception:
            logger.error("Failed to query known assets from ctem_exposures", exc_info=True)
            known_rows = []

        known_assets: set[str] = {row["asset_id"] for row in known_rows}

        # --- 4. Net-new assets -----------------------------------------
        # Assets seen in the audit log that are NOT in the exposure inventory
        net_new_asset_ids: set[str] = audit_hosts - known_assets

        total_found = len(audit_hosts) + len(stale_assets)
        stale_count = len(stale_assets)
        new_count = len(net_new_asset_ids)

        logger.info(
            "Asset discovery scan complete: total_found=%d, new_assets=%d, stale_assets=%d",
            total_found,
            new_count,
            stale_count,
        )

        # --- 5. Emit Kafka events for net-new assets -------------------
        discovered_at = scan_start.isoformat()
        for asset_id in net_new_asset_ids:
            await self._emit_discovery_event(
                asset_id=asset_id,
                asset_zone="",          # zone unknown until onboarded
                discovery_source="audit_events",
                discovered_at=discovered_at,
            )

        # Also emit events for stale assets that may need re-evaluation
        for asset_id, asset_zone in stale_assets.items():
            await self._emit_discovery_event(
                asset_id=asset_id,
                asset_zone=asset_zone,
                discovery_source="ctem_exposures_stale",
                discovered_at=discovered_at,
            )

        # --- 6. Record last-scan timestamp in Redis --------------------
        await self._update_last_scan(discovered_at)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    async def _emit_discovery_event(
        self,
        asset_id: str,
        asset_zone: str,
        discovery_source: str,
        discovered_at: str,
    ) -> None:
        """Publish one discovery event to the Kafka topic."""
        if self._producer is None:
            return
        payload = {
            "asset_id": asset_id,
            "asset_zone": asset_zone,
            "discovery_source": discovery_source,
            "discovered_at": discovered_at,
        }
        try:
            await self._producer.produce(DISCOVERY_TOPIC, payload)
        except Exception:
            logger.warning(
                "Failed to emit discovery event for asset_id=%s", asset_id,
                exc_info=True,
            )

    async def _update_last_scan(self, timestamp_iso: str) -> None:
        """Write last-scan timestamp to Redis (fail-open)."""
        if self._redis is None:
            return
        try:
            client = (
                self._redis._client
                if hasattr(self._redis, "_client")
                else self._redis
            )
            await client.set(REDIS_LAST_SCAN_KEY, timestamp_iso, ex=_REDIS_KEY_TTL)
        except Exception:
            logger.warning("Failed to update last-scan timestamp in Redis", exc_info=True)

    async def get_last_scan(self) -> str | None:
        """Return the ISO timestamp of the last completed scan, or None."""
        if self._redis is None:
            return None
        try:
            client = (
                self._redis._client
                if hasattr(self._redis, "_client")
                else self._redis
            )
            return await client.get(REDIS_LAST_SCAN_KEY)
        except Exception:
            logger.warning("Failed to read last-scan timestamp from Redis", exc_info=True)
            return None
