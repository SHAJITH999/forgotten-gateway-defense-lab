from __future__ import annotations

import unittest
from datetime import datetime

from level2_correlation import calculate_risk, correlate
from level2_detection import detect, map_mitre
from level2_models import SecurityEvent
from level2_pipeline import analyze, run_investigation
from level2_scenarios import SCENARIOS, parse_scenario_lines
from models import ScanResult, Service
from nginx_parser import parse_access_line, parse_error_line
from telemetry_receiver import TelemetryReceiver, _valid_event
from telemetry_transport import encode, make_envelope, verify_envelope


def make_event(
    event_id: str = "evt-test-1",
    timestamp: str = "2026-09-19T10:00:00+05:30",
    ip: str = "192.168.1.10",
    method: str = "GET",
    path: str = "/",
    status: int = 200,
    raw: str = "mock log line",
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="nginx",
        source_type="web_server",
        event_type="http_request",
        source_ip=ip,
        method=method,
        path=path,
        protocol="HTTP/1.1",
        status=status,
        raw_event=raw,
    )


class TestLevel2Comprehensive(unittest.TestCase):

    # --- DETECTION RULES ---
    def test_authentication_detection(self):
        # 3 failed logins from same IP within window -> triggers rule
        events = [
            make_event("e1", "2026-09-19T10:00:00+05:30", "198.51.100.10", "POST", "/login", 401),
            make_event("e2", "2026-09-19T10:00:10+05:30", "198.51.100.10", "POST", "/login", 401),
            make_event("e3", "2026-09-19T10:00:20+05:30", "198.51.100.10", "POST", "/login", 403),
        ]
        detections = detect(events)
        auth_dets = [d for d in detections if d.rule == "repeated-failed-authentication"]
        self.assertEqual(len(auth_dets), 1)
        self.assertEqual(auth_dets[0].severity, "high")
        self.assertEqual(auth_dets[0].source_ip, "198.51.100.10")
        self.assertEqual(auth_dets[0].related_event_ids, ["e1", "e2", "e3"])

    def test_account_discovery_detection(self):
        paths = ["/users", "/user", "/accounts", "/account", "/api/users", "/api/accounts"]
        for idx, path in enumerate(paths):
            ev = make_event(f"e-disc-{idx}", "2026-09-19T10:00:00+05:30", "203.0.113.1", "GET", path, 200)
            dets = detect([ev])
            self.assertTrue(any(d.rule == "account-discovery-path" for d in dets), f"Failed for {path}")
            self.assertIn("logs alone do not establish successful discovery", dets[0].reason)

    def test_admin_detection(self):
        paths = ["/admin", "/administrator", "/management", "/actuator", "/wp-admin"]
        for idx, path in enumerate(paths):
            ev = make_event(f"e-adm-{idx}", "2026-09-19T10:00:00+05:30", "203.0.113.2", "GET", path, 404)
            dets = detect([ev])
            self.assertTrue(any(d.rule == "admin-path-access" for d in dets), f"Failed for {path}")
            self.assertIn("suspicious activity, not proof of compromise", dets[0].reason)

    def test_transfer_detection(self):
        # 200 OK to transfer hint triggers rule; 404 does not
        ev_ok = make_event("e-trans-1", "2026-09-19T10:00:00+05:30", "203.0.113.3", "GET", "/export/data.zip", 200)
        ev_404 = make_event("e-trans-2", "2026-09-19T10:00:05+05:30", "203.0.113.3", "GET", "/backup", 404)
        dets_ok = detect([ev_ok])
        dets_404 = detect([ev_404])
        self.assertTrue(any(d.rule == "transfer-path-observed" for d in dets_ok))
        self.assertFalse(any(d.rule == "transfer-path-observed" for d in dets_404))

    # --- FALSE POSITIVES & THRESHOLDS ---
    def test_normal_traffic(self):
        raw_lines = SCENARIOS["normal"]()
        events = parse_scenario_lines(raw_lines)
        detections = detect(events)
        # Normal browsing should trigger 0 detections
        self.assertEqual(len(detections), 0)

    def test_threshold_behavior(self):
        # 1 failed login -> no alert
        e1 = [make_event("e1", "2026-09-19T10:00:00+05:30", "198.51.100.20", "POST", "/login", 401)]
        self.assertEqual(len(detect(e1)), 0)

        # 2 failed logins -> no threshold alert
        e2 = e1 + [make_event("e2", "2026-09-19T10:00:10+05:30", "198.51.100.20", "POST", "/login", 401)]
        self.assertEqual(len(detect(e2)), 0)

        # 3 failed logins -> triggers alert
        e3 = e2 + [make_event("e3", "2026-09-19T10:00:20+05:30", "198.51.100.20", "POST", "/login", 401)]
        self.assertEqual(len(detect(e3)), 1)

    def test_time_window_behavior(self):
        # 3 failed logins spaced 10 minutes (600s) apart with default 300s window -> no alert
        events = [
            make_event("e1", "2026-09-19T10:00:00+05:30", "198.51.100.20", "POST", "/login", 401),
            make_event("e2", "2026-09-19T10:10:00+05:30", "198.51.100.20", "POST", "/login", 401),
            make_event("e3", "2026-09-19T10:20:00+05:30", "198.51.100.20", "POST", "/login", 401),
        ]
        self.assertEqual(len(detect(events, auth_window_seconds=300)), 0)

    def test_multiple_source_ips(self):
        # 2 failed logins on IP 1, 2 on IP 2 -> neither reaches threshold of 3
        events = [
            make_event("e1", "2026-09-19T10:00:00+05:30", "10.0.0.1", "POST", "/login", 401),
            make_event("e2", "2026-09-19T10:00:05+05:30", "10.0.0.1", "POST", "/login", 401),
            make_event("e3", "2026-09-19T10:00:10+05:30", "10.0.0.2", "POST", "/login", 401),
            make_event("e4", "2026-09-19T10:00:15+05:30", "10.0.0.2", "POST", "/login", 401),
        ]
        self.assertEqual(len(detect(events)), 0)

    # --- TIMELINE & EVIDENCE ---
    def test_timeline_order_and_evidence(self):
        events = [
            make_event("e1", "2026-09-19T10:05:00+05:30", "1.1.1.1", "GET", "/admin", 404),
            make_event("e2", "2026-09-19T10:01:00+05:30", "1.1.1.1", "GET", "/", 200),
        ]
        dets, mappings, timeline = analyze(events)
        # Should be strictly chronologically sorted
        timestamps = [t.timestamp for t in timeline]
        self.assertEqual(timestamps, sorted(timestamps))
        # Evidence references preserved
        for entry in timeline:
            self.assertTrue(len(entry.evidence_event_ids) > 0)

    # --- MITRE MAPPING ---
    def test_mitre_mapping(self):
        events = [
            make_event("e1", "2026-09-19T10:00:00+05:30", "1.1.1.1", "GET", "/admin", 404),
            make_event("e2", "2026-09-19T10:01:00+05:30", "1.1.1.1", "GET", "/users", 200),
        ]
        dets = detect(events)
        mappings = map_mitre(events, dets)
        technique_ids = {m.technique_id for m in mappings}
        self.assertIn("T1071.001", technique_ids)
        self.assertIn("T1087", technique_ids)
        # T1190 must explicitly remain marked insufficient evidence
        t1190 = next(m for m in mappings if m.technique_id == "T1190")
        self.assertEqual(t1190.status, "insufficient evidence")
        self.assertEqual(t1190.confidence, "none")

    # --- TELEMETRY SECURITY ---
    def test_telemetry_transport_and_validation(self):
        token = "secret-token-12345"
        payload = make_event("e-tel", "2026-09-19T10:00:00+05:30", "1.2.3.4", "GET", "/").to_dict()

        # Valid envelope
        valid_env = make_envelope("event", token, payload)
        valid, kind, data = verify_envelope(valid_env, token)
        self.assertTrue(valid)
        self.assertEqual(kind, "event")
        self.assertEqual(data["event_id"], "e-tel")

        # Invalid token
        valid, kind, _ = verify_envelope(valid_env, "wrong-token")
        self.assertFalse(valid)

        # Tampered signature
        tampered_env = dict(valid_env)
        tampered_env["signature"] = "bad-sig"
        valid, _, _ = verify_envelope(tampered_env, token)
        self.assertFalse(valid)

        # Malformed event payload (missing required field)
        bad_payload = {"event_id": "test"}
        self.assertIsNone(_valid_event(bad_payload))

    # --- CORRELATION ENGINE ---
    def test_correlation(self):
        raw_lines = SCENARIOS["multi_stage"]()
        events = parse_scenario_lines(raw_lines)
        dets = detect(events)
        corrs = correlate(events, dets, correlation_window_seconds=600)
        self.assertTrue(len(corrs) >= 1)
        corr = corrs[0]
        self.assertEqual(corr.source_ip, "198.51.100.99")
        self.assertEqual(corr.severity, "critical")
        self.assertTrue(len(corr.stages_observed) >= 3)
        self.assertTrue(len(corr.related_event_ids) >= 4)

    # --- RISK SCORING ---
    def test_risk_score(self):
        # Test normal traffic risk
        normal_events = parse_scenario_lines(SCENARIOS["normal"]())
        normal_dets = detect(normal_events)
        normal_corrs = correlate(normal_events, normal_dets)
        risk_normal = calculate_risk(normal_dets, normal_corrs)
        self.assertEqual(risk_normal.score, 0)
        self.assertEqual(risk_normal.severity, "Low")

        # Test multi-stage attack risk
        multi_events = parse_scenario_lines(SCENARIOS["multi_stage"]())
        multi_dets = detect(multi_events)
        multi_corrs = correlate(multi_events, multi_dets)
        mock_level1 = ScanResult(
            target_ip="127.0.0.1",
            raw_xml="<xml/>",
            services=[Service(port=80, protocol="TCP", state="open", service="http")],
        )
        risk_multi = calculate_risk(multi_dets, multi_corrs, level1_context=mock_level1)
        self.assertEqual(risk_multi.score, 100)
        self.assertEqual(risk_multi.severity, "Critical")
        self.assertTrue(len(risk_multi.breakdown) >= 5)

    # --- EDGE CASES ---
    def test_edge_cases(self):
        # Empty events
        res_empty = run_investigation([])
        self.assertEqual(len(res_empty.events), 0)
        self.assertEqual(len(res_empty.detections), 0)
        self.assertEqual(res_empty.risk.score, 0)

        # Missing or invalid timestamp in event
        bad_time_ev = SecurityEvent(
            event_id="bad-time",
            timestamp="INVALID_DATE_FORMAT",
            source_ip="10.0.0.5",
            method="POST",
            path="/login",
            status=401,
            raw_event="invalid time log",
        )
        # Must not crash
        dets = detect([bad_time_ev])
        self.assertEqual(len(dets), 0)

        # Unknown HTTP methods or unusual endpoints
        weird_ev = SecurityEvent(
            event_id="weird-1",
            timestamp="2026-09-19T10:00:00+05:30",
            source_ip="10.0.0.6",
            method="PROPFIND",
            path="/some/random/path",
            status=405,
            raw_event="weird log",
        )
        dets_weird = detect([weird_ev])
        self.assertEqual(len(dets_weird), 0)

    # --- END TO END PIPELINE ---
    def test_end_to_end_pipeline(self):
        raw_lines = SCENARIOS["multi_stage"]()
        events = parse_scenario_lines(raw_lines, destination="10.10.10.5", destination_port=80)
        self.assertEqual(len(events), 6)

        level1_ctx = ScanResult(
            target_ip="10.10.10.5",
            raw_xml="<nmaprun></nmaprun>",
            services=[Service(port=80, protocol="TCP", state="open", service="http")],
        )
        inv = run_investigation(events, level1_context=level1_ctx, target="10.10.10.5")

        self.assertTrue(inv.investigation_id.startswith("inv-"))
        self.assertEqual(inv.target, "10.10.10.5")
        self.assertEqual(len(inv.events), 6)
        self.assertTrue(len(inv.detections) >= 4)
        self.assertTrue(len(inv.correlations) >= 1)
        self.assertEqual(inv.risk.score, 100)
        self.assertEqual(inv.risk.severity, "Critical")
        self.assertTrue(len(inv.timeline) >= 10)
        self.assertIsNotNone(inv.level1_context)


if __name__ == "__main__":
    unittest.main()
