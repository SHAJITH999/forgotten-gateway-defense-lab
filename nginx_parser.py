from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime

from level2_models import SecurityEvent, stable_event_id

# Compatible with the default combined Nginx access format.
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^]]+)\]\s+'
    r'"(?P<request>[^"\\]*(?:\\.[^"\\]*)*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?(?:\s+.*)?$'
)
REQUEST_RE = re.compile(r"^(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>\S+)$")
ERROR_TIME_RE = re.compile(r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d+)")


def _iso_access_timestamp(value: str) -> str:
    try:
        return parsedate_to_datetime(value.replace("/", " ", 1)).isoformat()
    except (TypeError, ValueError, IndexError):
        # Nginx's format is close to email's date format after normalizing the first separator.
        try:
            parsed = datetime.strptime(value.split()[0], "%d/%b/%Y")
            return parsed.date().isoformat() + "T" + value.split(":", 1)[1].strip()
        except (ValueError, IndexError):
            return value


def parse_access_line(raw_line: str, destination: str = "", destination_port: int | None = None) -> SecurityEvent | None:
    line = raw_line.rstrip("\r\n")
    match = ACCESS_RE.match(line)
    if not match:
        return None
    request = REQUEST_RE.match(match.group("request"))
    if not request:
        return None
    size = None if match.group("size") == "-" else int(match.group("size"))
    return SecurityEvent(
        event_id=stable_event_id(line),
        timestamp=_iso_access_timestamp(match.group("timestamp")),
        source_ip=match.group("ip"), destination=destination, destination_port=destination_port,
        method=request.group("method"), path=request.group("path"), protocol=request.group("protocol"),
        status=int(match.group("status")), response_size=size,
        referrer=match.group("referrer") or "", user_agent=match.group("agent") or "", raw_event=line,
    )


def parse_error_line(raw_line: str) -> SecurityEvent | None:
    line = raw_line.rstrip("\r\n")
    match = ERROR_TIME_RE.match(line)
    if not match:
        return None
    return SecurityEvent(
        event_id=stable_event_id(line, "nginx-error"), timestamp=match.group("timestamp").replace("/", "-"),
        source="nginx", source_type="web_server", event_type="nginx_error", severity="medium", raw_event=line,
        detection_reason="Nginx error log observation",
    )
