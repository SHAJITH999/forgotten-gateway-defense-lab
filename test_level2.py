import socket
import time

from level2_detection import detect, map_mitre
from level2_models import SecurityEvent
from level2_pipeline import analyze
from telemetry_receiver import TelemetryReceiver
from telemetry_transport import encode, make_envelope


def event(event_id, timestamp, ip, method, path, status, raw):
    return SecurityEvent(event_id=event_id, timestamp=timestamp, source="nginx", source_type="web_server", event_type="http_request", source_ip=ip, method=method, path=path, protocol="HTTP/1.1", status=status, raw_event=raw)


observed = [
    event("evt-1", "2026-09-17T13:15:00+05:30", "198.51.100.20", "POST", "/login", 401, "real nginx line 1"),
    event("evt-2", "2026-09-17T13:15:10+05:30", "198.51.100.20", "POST", "/login", 403, "real nginx line 2"),
    event("evt-3", "2026-09-17T13:15:20+05:30", "198.51.100.20", "POST", "/login", 401, "real nginx line 3"),
    event("evt-4", "2026-09-17T13:16:00+05:30", "203.0.113.45", "GET", "/api/users", 200, "real nginx line 4"),
]
detections = detect(observed)
assert any(item.rule == "repeated-failed-authentication" for item in detections)
assert any(item.rule == "account-discovery-path" for item in detections)
mappings = map_mitre(observed, detections)
assert any(item.technique_id == "T1190" and item.status == "insufficient evidence" for item in mappings)
_, _, timeline = analyze(observed)
assert timeline == sorted(timeline, key=lambda item: item.timestamp)
assert all(item.evidence_event_ids for item in timeline)

received = []
receiver = TelemetryReceiver("127.0.0.1", 0, "test-token", received.append)
receiver.start()
with socket.create_connection(("127.0.0.1", receiver.port), timeout=2) as connection:
    connection.sendall(encode(make_envelope("event", "test-token", observed[0].to_dict())))
    connection.sendall(encode(make_envelope("event", "wrong-token", observed[1].to_dict())))
    time.sleep(0.1)
receiver.stop()
assert len(received) == 1 and received[0].event_id == "evt-1"
assert receiver.events_received == 1
print("level 2 transport and detection tests passed")
