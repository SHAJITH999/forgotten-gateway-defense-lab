from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from level2_models import SecurityEvent
from nginx_parser import parse_access_line, parse_error_line


@dataclass
class FileCursor:
    inode: int = 0
    offset: int = 0


class NginxLogCollector:
    """Incrementally reads configured Nginx logs; it never executes log content."""

    def __init__(self, access_path: str = "", error_path: str = ""):
        self.access_path = Path(access_path).expanduser() if access_path else None
        self.error_path = Path(error_path).expanduser() if error_path else None
        self.cursors: dict[str, FileCursor] = {}
        self.seen_ids: set[str] = set()

    def configure(self, access_path: str, error_path: str) -> None:
        self.access_path = Path(access_path).expanduser() if access_path else None
        self.error_path = Path(error_path).expanduser() if error_path else None

    def _read_new(self, path: Path, parser: Callable[[str], SecurityEvent | None]) -> list[SecurityEvent]:
        key = str(path.resolve())
        try:
            stat = path.stat()
            cursor = self.cursors.setdefault(key, FileCursor())
            if cursor.inode != stat.st_ino or stat.st_size < cursor.offset:
                cursor.inode, cursor.offset = stat.st_ino, 0
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(cursor.offset)
                lines = handle.readlines()
                cursor.offset = handle.tell()
                cursor.inode = stat.st_ino
        except (OSError, UnicodeError):
            return []
        events: list[SecurityEvent] = []
        for line in lines:
            event = parser(line)
            if event and event.event_id not in self.seen_ids:
                self.seen_ids.add(event.event_id)
                events.append(event)
        return events

    def collect(self) -> list[SecurityEvent]:
        events: list[SecurityEvent] = []
        if self.access_path:
            events.extend(self._read_new(self.access_path, parse_access_line))
        if self.error_path:
            events.extend(self._read_new(self.error_path, parse_error_line))
        return sorted(events, key=lambda item: item.timestamp)
