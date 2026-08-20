"""WebSocket live updates — Story 17-7.

Broadcasts investigation state changes to connected dashboard clients
via Postgres LISTEN/NOTIFY.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from services.dashboard.middleware.auth import DashboardAuthenticator

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections for broadcast."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)
        logger.info("WebSocket client connected (%d total)", len(self._connections))

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)
        logger.info("WebSocket client disconnected (%d total)", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Send a JSON message to all connected clients."""
        dead: list[WebSocket] = []
        data = json.dumps(message, default=str)
        for ws in self._connections:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


manager = ConnectionManager()


async def websocket_investigations(ws: WebSocket) -> None:
    """WebSocket endpoint: ``/ws/investigations``.

    Clients connect here to receive real-time investigation state changes.
    Uses ``hx-ext="ws"`` with ``ws-connect="/ws/investigations"`` on the
    client side.
    """
    authenticator = DashboardAuthenticator()
    try:
        principal = await authenticator.authenticate(ws.headers)
    except Exception:
        await ws.close(code=1008, reason="Authentication required")
        return
    ws.state.user_id = principal.user_id
    ws.state.user_role = principal.role
    await manager.connect(ws)
    try:
        while True:
            # Keep connection alive; actual broadcasts happen via notify_state_change
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


async def notify_state_change(
    investigation_id: str,
    new_state: str,
    updated_at: str | None = None,
) -> None:
    """Broadcast an investigation state change to all WebSocket clients.

    Called from persistence layer after a state transition.
    """
    if updated_at is None:
        updated_at = datetime.now(timezone.utc).isoformat()

    await manager.broadcast({
        "investigation_id": investigation_id,
        "new_state": new_state,
        "updated_at": updated_at,
    })
