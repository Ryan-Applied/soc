"""Small liveness/readiness server for non-HTTP worker processes."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class WorkerHealthServer:
    """Serve ``/health`` and ``/ready`` without adding an async runtime."""

    def __init__(self, service_name: str, port: int, host: str = "0.0.0.0") -> None:
        self.service_name = service_name
        self._ready = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                status, state = owner.probe(self.path)
                self._respond(status, state)

            def _respond(self, status: int, state: str) -> None:
                body = json.dumps({"status": state, "service": owner.service_name}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = ThreadingHTTPServer((host, port), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"{service_name}-health",
            daemon=True,
        )

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> None:
        self._thread.start()

    def probe(self, path: str) -> tuple[int, str]:
        """Return the status code and state used by the HTTP handler."""
        if path == "/health":
            return 200, "ok"
        if path == "/ready":
            return (200, "ready") if self._ready.is_set() else (503, "not_ready")
        return 404, "not_found"

    def mark_ready(self) -> None:
        self._ready.set()

    def mark_not_ready(self) -> None:
        self._ready.clear()

    def close(self) -> None:
        self.mark_not_ready()
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)
