"""Wiz OAuth2 token management.

Wiz uses the client_credentials grant against:
    https://auth.app.wiz.io/oauth/token

Tokens expire in 3600s. This module caches the token and refreshes
it proactively 60 seconds before expiry.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
_EXPIRY_BUFFER_SECONDS = 60  # Refresh this many seconds before actual expiry


class WizTokenManager:
    """Manages Wiz OAuth2 access tokens with proactive refresh.

    Tokens are fetched using the client_credentials grant and cached in
    memory. A refresh is triggered when the cached token is within
    ``_EXPIRY_BUFFER_SECONDS`` of expiry, ensuring callers always receive
    a valid token.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        auth_url: str = _DEFAULT_AUTH_URL,
    ) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._auth_url = auth_url

        self._token: str | None = None
        self._expires_at: float = 0.0  # monotonic timestamp

        # Serialise concurrent refresh attempts
        self._refresh_lock: asyncio.Lock = asyncio.Lock()

    async def get_token(self) -> str:
        """Return a valid access token, refreshing if necessary.

        Concurrent callers that arrive while a refresh is in flight will
        wait on the lock and then use the freshly-fetched token rather
        than issuing redundant requests.
        """
        if self._needs_refresh():
            async with self._refresh_lock:
                # Re-check inside the lock in case another coroutine already
                # completed the refresh while we were waiting.
                if self._needs_refresh():
                    await self._fetch_token()

        assert self._token is not None, "Token unavailable after refresh"
        return self._token

    def _needs_refresh(self) -> bool:
        """Return True if there is no token or it expires within the buffer."""
        return self._token is None or time.monotonic() >= self._expires_at

    async def _fetch_token(self) -> None:
        """POST to the auth endpoint and cache the resulting token.

        Uses ``audience=wiz-api`` as required by the Wiz OAuth2 server.
        The token itself is never written to logs.
        """
        logger.info(
            "Refreshing Wiz OAuth2 token (url=%s, client_id=%s)",
            self._auth_url,
            self._client_id,
        )

        payload: dict[str, Any] = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "audience": "wiz-api",
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                self._auth_url,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

        if response.status_code != 200:
            raise RuntimeError(
                f"Wiz token fetch failed: HTTP {response.status_code} — {response.text[:200]}"
            )

        body = response.json()
        access_token: str | None = body.get("access_token")
        expires_in: int = int(body.get("expires_in", 3600))

        if not access_token:
            raise RuntimeError(
                "Wiz token response did not contain 'access_token'"
            )

        self._token = access_token
        self._expires_at = time.monotonic() + expires_in - _EXPIRY_BUFFER_SECONDS

        logger.info(
            "Wiz OAuth2 token refreshed successfully (expires_in=%ds, "
            "effective_ttl=%ds)",
            expires_in,
            expires_in - _EXPIRY_BUFFER_SECONDS,
        )
