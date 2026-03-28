"""Entry point for the Wiz Connector service.

Reads connector config from Postgres connectors table,
instantiates WizConnector for each enabled wiz connector,
and runs them as concurrent asyncio tasks.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from typing import Any

logger = logging.getLogger(__name__)

# Required keys expected inside the connector config JSONB column
_REQUIRED_CONFIG_KEYS = ("api_url", "client_id", "client_secret")


def _build_connector(
    row: Any,
    kafka_bootstrap: str,
    pg_pool: Any,
) -> "WizConnector | None":  # noqa: F821 — imported below to avoid circular issues
    """Construct a :class:`WizConnector` from a ``connectors`` table row.

    Returns ``None`` and logs a warning if mandatory config keys are absent.
    """
    from wiz_connector.connector import WizConnector

    config: dict[str, Any] = dict(row["config"] or {})
    connector_id: str = str(row["connector_id"])
    tenant_id: str = row["tenant_id"] or "default"

    for key in _REQUIRED_CONFIG_KEYS:
        if not config.get(key):
            logger.warning(
                "Skipping connector %s — missing required config key '%s'",
                connector_id,
                key,
            )
            return None

    poll_interval: int = int(config.get("poll_interval_seconds", 300))

    return WizConnector(
        api_url=config["api_url"],
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        kafka_bootstrap=kafka_bootstrap,
        pg_pool=pg_pool,
        poll_interval_seconds=poll_interval,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )


async def main() -> None:
    """Read Wiz connector configs from Postgres and run them concurrently."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
    )

    kafka_bootstrap = os.environ.get("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    postgres_dsn = os.environ.get("POSTGRES_DSN", "")

    if not postgres_dsn:
        logger.error(
            "POSTGRES_DSN environment variable is not set — cannot load connector configs"
        )
        return

    # ------------------------------------------------------------------
    # Connect to Postgres
    # ------------------------------------------------------------------
    try:
        import asyncpg  # type: ignore[import-untyped]
    except ImportError:
        logger.error("asyncpg is required but not installed")
        return

    try:
        pool = await asyncpg.create_pool(dsn=postgres_dsn, min_size=1, max_size=5)
    except Exception as exc:
        logger.error("Failed to connect to Postgres: %s", exc, exc_info=True)
        return

    logger.info("Connected to Postgres")

    # ------------------------------------------------------------------
    # Load enabled Wiz connector rows
    # ------------------------------------------------------------------
    try:
        rows = await pool.fetch(
            "SELECT * FROM connectors WHERE adapter_type = 'wiz' AND enabled = TRUE"
        )
    except Exception as exc:
        logger.error("Failed to query connectors table: %s", exc, exc_info=True)
        await pool.close()
        return

    if not rows:
        # Fall back to environment variable configuration
        wiz_client_id = os.environ.get("WIZ_CLIENT_ID", "")
        wiz_client_secret = os.environ.get("WIZ_CLIENT_SECRET", "")
        wiz_api_endpoint = os.environ.get("WIZ_API_ENDPOINT", "https://api.us1.app.wiz.io/graphql")
        poll_interval = int(os.environ.get("WIZ_POLL_INTERVAL_SECONDS", "300"))

        if wiz_client_id and wiz_client_secret:
            logger.info(
                "No database connector records found — using environment variable configuration"
            )
            from wiz_connector.connector import WizConnector

            connector = WizConnector(
                api_url=wiz_api_endpoint,
                client_id=wiz_client_id,
                client_secret=wiz_client_secret,
                kafka_bootstrap=kafka_bootstrap,
                pg_pool=pool,
                poll_interval_seconds=poll_interval,
                tenant_id="default",
                connector_id="env-default",
            )

            loop = asyncio.get_running_loop()
            shutdown_event = asyncio.Event()

            def _handle_signal_env(signum: int) -> None:
                sig_name = signal.Signals(signum).name
                logger.info("Received signal %s — initiating graceful shutdown", sig_name)
                connector.stop()
                shutdown_event.set()

            for sig in (signal.SIGINT, signal.SIGTERM):
                try:
                    loop.add_signal_handler(sig, _handle_signal_env, sig)
                except (NotImplementedError, OSError):
                    signal.signal(sig, lambda signum, _frame: _handle_signal_env(signum))

            try:
                await connector.run_forever()
            except asyncio.CancelledError:
                connector.stop()
            finally:
                await pool.close()
                logger.info("Wiz Connector service stopped")
            return
        else:
            logger.warning(
                "No enabled Wiz connectors in database and WIZ_CLIENT_ID/WIZ_CLIENT_SECRET "
                "env vars not set — exiting"
            )
            await pool.close()
            return

    logger.info("Found %d enabled Wiz connector(s)", len(rows))

    # ------------------------------------------------------------------
    # Build connector instances
    # ------------------------------------------------------------------
    connectors = []
    for row in rows:
        connector = _build_connector(row, kafka_bootstrap, pool)
        if connector is not None:
            connectors.append(connector)

    if not connectors:
        logger.warning("No valid Wiz connectors could be constructed — exiting")
        await pool.close()
        return

    # ------------------------------------------------------------------
    # Signal handling for graceful shutdown
    # ------------------------------------------------------------------
    loop = asyncio.get_running_loop()
    shutdown_event = asyncio.Event()

    def _handle_signal(signum: int) -> None:
        sig_name = signal.Signals(signum).name
        logger.info("Received signal %s — initiating graceful shutdown", sig_name)
        for c in connectors:
            c.stop()
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _handle_signal, sig)
        except (NotImplementedError, OSError):
            # Windows or restricted environments: fall back to synchronous handler
            signal.signal(sig, lambda signum, _frame: _handle_signal(signum))

    # ------------------------------------------------------------------
    # Run all connectors as concurrent tasks
    # ------------------------------------------------------------------
    tasks = [
        asyncio.create_task(connector.run_forever(), name=f"wiz-connector-{connector._connector_id}")
        for connector in connectors
    ]

    logger.info("Starting %d WizConnector task(s)", len(tasks))

    try:
        # Wait for all connectors to finish (they run until stopped)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for connector, result in zip(connectors, results):
            if isinstance(result, Exception):
                logger.error(
                    "Connector %s exited with error: %s",
                    connector._connector_id,
                    result,
                    exc_info=result,
                )
    except asyncio.CancelledError:
        logger.info("Main task cancelled — stopping connectors")
        for connector in connectors:
            connector.stop()
        # Allow tasks to complete their current cycle cleanly
        await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await pool.close()
        logger.info("Wiz Connector service stopped")


if __name__ == "__main__":
    asyncio.run(main())
