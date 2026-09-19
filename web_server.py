from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from level2_models import SecurityEvent
from level2_pipeline import run_investigation
from level2_scenarios import SCENARIOS, parse_scenario_lines
from models import ScanResult, Service
from nginx_parser import parse_access_line, parse_error_line

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"

# In-memory investigation state
investigation_state = {
    "target": "127.0.0.1",
    "services": [
        {"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "nginx", "version": "1.21.6"},
        {"port": 22, "protocol": "TCP", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2"},
        {"port": 443, "protocol": "TCP", "state": "closed", "service": "https", "product": "", "version": ""},
    ],
    "events": [],
}


def _get_mock_level1():
    services = [
        Service(
            port=s["port"],
            protocol=s["protocol"],
            state=s["state"],
            service=s.get("service", ""),
            product=s.get("product", ""),
            version=s.get("version", ""),
        )
        for s in investigation_state["services"]
        if s["state"] == "open"
    ]
    return ScanResult(target_ip=investigation_state["target"], raw_xml="<nmaprun></nmaprun>", services=services)


class LocalhostAppHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        if path == "/api/status":
            level1_ctx = _get_mock_level1()
            inv = run_investigation(
                investigation_state["events"],
                level1_context=level1_ctx,
                target=investigation_state["target"],
            )
            data = {
                "level1": {
                    "target_ip": investigation_state["target"],
                    "services": investigation_state["services"],
                },
                "investigation": inv.to_dict(),
            }
            self._send_json(data)
            return

        if path == "/api/scenarios":
            self._send_json({"scenarios": list(SCENARIOS.keys())})
            return

        # Default static file handler (serves web/index.html)
        if path == "/" or path == "":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path

        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            payload = {}

        if path == "/api/scenario/load":
            scenario_name = payload.get("scenario", "multi_stage")
            if scenario_name in SCENARIOS:
                raw_lines = SCENARIOS[scenario_name]()
                new_events = parse_scenario_lines(raw_lines, destination=investigation_state["target"])
                investigation_state["events"] = new_events
                self._send_json({"status": "ok", "scenario": scenario_name, "count": len(new_events)})
            else:
                self._send_json({"error": "Unknown scenario"}, status=400)
            return

        if path == "/api/logs/ingest":
            log_text = payload.get("log_text", "")
            lines = log_text.splitlines()
            count = 0
            for line in lines:
                ev = parse_access_line(line, destination=investigation_state["target"]) or parse_error_line(line)
                if ev:
                    if not any(item.event_id == ev.event_id for item in investigation_state["events"]):
                        investigation_state["events"].append(ev)
                        count += 1
            investigation_state["events"].sort(key=lambda e: e.timestamp)
            self._send_json({"status": "ok", "ingested": count, "total": len(investigation_state["events"])})
            return

        if path == "/api/clear":
            investigation_state["events"] = []
            self._send_json({"status": "ok", "message": "Investigation events cleared"})
            return

        if path == "/api/scan":
            target = payload.get("target", "127.0.0.1")
            investigation_state["target"] = target
            self._send_json({"status": "ok", "target": target, "services": investigation_state["services"]})
            return

        self._send_json({"error": "Endpoint not found"}, status=404)


def run_server(port: int = 5000):
    # Initialize with default multi-stage scenario so localhost opens with immediate rich data
    initial_lines = SCENARIOS["multi_stage"]()
    investigation_state["events"] = parse_scenario_lines(initial_lines, destination="127.0.0.1")

    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, LocalhostAppHandler)
    print("=" * 60)
    print(f"  FORGOTTEN GATEWAY DEFENSE LAB — LOCALHOST WEB APP")
    print(f"  Running on: http://127.0.0.1:{port}")
    print(f"  API available at: http://127.0.0.1:{port}/api/status")
    print("=" * 60)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server...")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_server(port)
