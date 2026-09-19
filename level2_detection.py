from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from level2_models import Detection, MitreMapping, SecurityEvent, detection_id

TECHNIQUES = {
    "T1190": "Exploit Public-Facing Application",
    "T1087": "Account Discovery",
    "T1041": "Exfiltration Over C2 Channel",
    "T1071.001": "Web Protocols",
}

ADMIN_PATHS = ("/admin", "/administrator", "/management", "/actuator", "/wp-admin")
DISCOVERY_PATHS = ("/users", "/user", "/accounts", "/account", "/api/users", "/api/accounts")
TRANSFER_HINTS = ("/export", "/download", "/backup", "/dump", "/exfil")


def _timestamp(value: str | None) -> datetime:
    if not value or not isinstance(value, str):
        return datetime.min
    try:
        clean = value.replace("Z", "+00:00")
        return datetime.fromisoformat(clean).replace(tzinfo=None)
    except (ValueError, TypeError):
        try:
            return datetime.strptime(value.split(".")[0], "%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            return datetime.min



def _detection(rule: str, severity: str, reason: str, events: list[SecurityEvent], confidence: str, technique: str | None) -> Detection:
    ids = [event.event_id for event in events]
    return Detection(detection_id(rule, ids), max((event.timestamp for event in events), default=""), severity, reason, ids, events[0].source_ip if events else "", rule, confidence, technique, "\n".join(event.raw_event for event in events))


def detect(events: list[SecurityEvent], auth_window_seconds: int = 300) -> list[Detection]:
    detections: list[Detection] = []
    failed_by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        path = urlsplit(event.path).path.lower()
        if event.method.upper() == "POST" and path == "/login" and event.status in (401, 403):
            failed_by_ip[event.source_ip].append(event)
        if any(path == prefix or path.startswith(prefix + "/") for prefix in ADMIN_PATHS):
            detections.append(_detection("admin-path-access", "medium", f"Request accessed administrative path {path}; this is suspicious activity, not proof of compromise.", [event], "medium", "T1071.001"))
        if any(path == prefix or path.startswith(prefix + "/") for prefix in DISCOVERY_PATHS):
            detections.append(_detection("account-discovery-path", "medium", f"Request accessed an account or user discovery path {path}; logs alone do not establish successful discovery.", [event], "medium", "T1087"))
        if any(path == prefix or path.startswith(prefix + "/") for prefix in TRANSFER_HINTS) and event.status == 200:
            detections.append(_detection("transfer-path-observed", "medium", f"Successful request to transfer-like path {path}; no exfiltration is claimed without application or network evidence.", [event], "low", "T1041"))
    for source_ip, candidates in failed_by_ip.items():
        candidates.sort(key=lambda item: _timestamp(item.timestamp))
        for index in range(len(candidates)):
            window = [candidate for candidate in candidates[index:] if _timestamp(candidate.timestamp) - _timestamp(candidates[index].timestamp) <= timedelta(seconds=auth_window_seconds)]
            if len(window) >= 3:
                detections.append(_detection("repeated-failed-authentication", "high", f"{len(window)} failed POST /login requests from {source_ip} within {auth_window_seconds} seconds.", window, "high", "T1071.001"))
                break
    unique: dict[str, Detection] = {item.detection_id: item for item in detections}
    return sorted(unique.values(), key=lambda item: _timestamp(item.timestamp))


def map_mitre(events: list[SecurityEvent], detections: list[Detection]) -> list[MitreMapping]:
    mappings: list[MitreMapping] = []
    for detection in detections:
        if not detection.mitre_technique:
            continue
        technique = detection.mitre_technique
        mappings.append(MitreMapping(technique, TECHNIQUES[technique], detection.reason, detection.related_event_ids, detection.timestamp, detection.confidence, "observed"))
    # The requested scenario techniques that cannot be established from Nginx-only evidence remain explicitly insufficient.
    observed = {mapping.technique_id for mapping in mappings}
    if "T1190" not in observed:
        mappings.append(MitreMapping("T1190", TECHNIQUES["T1190"], "Nginx HTTP logs alone cannot establish that a public-facing application was successfully exploited.", [], "", "none", "insufficient evidence"))
    return mappings
