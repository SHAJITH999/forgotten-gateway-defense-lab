from __future__ import annotations

import json
from pathlib import Path

from models import ScanHistory


class HistoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> list[ScanHistory]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, list):
                return []
            return [ScanHistory.from_dict(item) for item in data if isinstance(item, dict)]
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return []

    def save(self, entries: list[ScanHistory]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self.path.with_suffix(".tmp")
        temp_path.write_text(json.dumps([entry.to_dict() for entry in entries], indent=2), encoding="utf-8")
        temp_path.replace(self.path)

    def add(self, entry: ScanHistory, limit: int = 50) -> list[ScanHistory]:
        entries = self.load()
        entries.insert(0, entry)
        entries = entries[:limit]
        self.save(entries)
        return entries
