"""Tests for worker process liveness and readiness probes."""

import pytest
from unittest.mock import MagicMock, patch

from shared.worker_health import WorkerHealthServer


@pytest.fixture
def server():
    fake_httpd = MagicMock()
    fake_httpd.server_address = ("127.0.0.1", 12345)
    with patch("shared.worker_health.ThreadingHTTPServer", return_value=fake_httpd):
        yield WorkerHealthServer("worker-a", 0, host="127.0.0.1")


def test_liveness_is_available_before_ready(server):
    assert server.probe("/health") == (200, "ok")
    assert server.probe("/missing") == (404, "not_found")


def test_readiness_tracks_worker_state(server):
    assert server.probe("/ready") == (503, "not_ready")
    server.mark_ready()
    assert server.probe("/ready") == (200, "ready")
    server.mark_not_ready()
    assert server.probe("/ready") == (503, "not_ready")
