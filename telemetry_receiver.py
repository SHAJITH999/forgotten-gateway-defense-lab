from __future__ import annotations

import json
import socket
import socketserver
import threading
from datetime import datetime, timezone
from typing import Callable

from level2_models import SecurityEvent
from telemetry_transport import verify_envelope


def _valid_event(payload: dict) -> SecurityEvent | None:
    required = ("event_id", "timestamp", "source", "source_type", "event_type", "raw_event")
    if any(not isinstance(payload.get(key), str) or not payload.get(key) for key in required):
        return None
    string_fields = ("source_ip", "destination", "method", "path", "protocol", "referrer", "user_agent", "host", "severity")
    if any(key in payload and not isinstance(payload.get(key), str) for key in string_fields):
        return None
    status = payload.get("status")
    if status is not None and (not isinstance(status, int) or status < 100 or status > 599):
        return None
    response_size = payload.get("response_size")
    if response_size is not None and (not isinstance(response_size, int) or response_size < 0):
        return None
    destination_port = payload.get("destination_port")
    if destination_port is not None and (not isinstance(destination_port, int) or not 1 <= destination_port <= 65535):
        return None
    source_ip = payload.get("source_ip", "")
    if not isinstance(source_ip, str) or len(source_ip) > 255:
        return None
    values = {key: payload.get(key) for key in SecurityEvent.__dataclass_fields__}
    values["event_id"] = payload["event_id"]
    return SecurityEvent(**values)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self):
        server: "TelemetryReceiver" = self.server.receiver  # type: ignore[attr-defined]
        server._client_connected(self.client_address)
        try:
            for raw in self.rfile:
                if len(raw) > 128 * 1024:
                    server._rejected("message too large")
                    continue
                try:
                    envelope = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    server._rejected("invalid JSON")
                    continue
                valid, kind, payload = verify_envelope(envelope, server.token)
                if not valid:
                    server._rejected(payload if isinstance(payload, str) else kind)
                    continue
                if kind == "heartbeat":
                    server._heartbeat()
                    continue
                if kind != "event":
                    server._rejected("unsupported message type")
                    continue
                event = _valid_event(payload)
                if event is None:
                    server._rejected("invalid event payload")
                    continue
                server._event(event)
        finally:
            server._client_disconnected(self.client_address)


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, receiver: "TelemetryReceiver"):
        self.receiver = receiver
        super().__init__(address, _Handler)


class TelemetryReceiver:
    def __init__(self, bind_host: str, port: int, token: str, on_event: Callable[[SecurityEvent], None] | None = None, on_status: Callable[[dict], None] | None = None):
        if not token:
            raise ValueError("A non-empty shared authentication token is required.")
        self.bind_host, self.port, self.token = bind_host, int(port), token
        self.on_event, self.on_status = on_event, on_status
        self.server: _ThreadingTCPServer | None = None
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()
        self.connected_clients = 0
        self.events_received = 0
        self.last_event_received = ""
        self.last_error = ""
        self.seen_ids: set[str] = set()

    def start(self) -> None:
        if self.server: return
        self.server = _ThreadingTCPServer((self.bind_host, self.port), self)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, name="telemetry-receiver", daemon=True)
        self.thread.start(); self._notify()

    def stop(self) -> None:
        if self.server:
            self.server.shutdown(); self.server.server_close(); self.server = None
        self._notify()

    def status(self) -> dict:
        with self.lock:
            return {"connected": self.connected_clients > 0, "last_event_received": self.last_event_received, "events_received": self.events_received, "last_error": self.last_error, "port": self.port}

    def _notify(self):
        if self.on_status: self.on_status(self.status())
    def _client_connected(self, _address):
        with self.lock: self.connected_clients += 1
        self._notify()
    def _client_disconnected(self, _address):
        with self.lock: self.connected_clients = max(0, self.connected_clients - 1)
        self._notify()
    def _heartbeat(self): self._notify()
    def _rejected(self, reason):
        with self.lock: self.last_error = reason
        self._notify()
    def _event(self, event: SecurityEvent):
        with self.lock:
            if event.event_id in self.seen_ids: return
            self.seen_ids.add(event.event_id); self.events_received += 1; self.last_event_received = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if self.on_event: self.on_event(event)
        self._notify()
