from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
import hashlib
import json


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    source: str = "nginx"
    source_type: str = "web_server"
    event_type: str = "http_request"
    source_ip: str = ""
    destination: str = ""
    destination_port: int | None = None
    method: str = ""
    path: str = ""
    protocol: str = ""
    status: int | None = None
    response_size: int | None = None
    referrer: str = ""
    user_agent: str = ""
    host: str = ""
    severity: str = "low"
    raw_event: str = ""
    mitre_technique: str | None = None
    detection_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Detection:
    detection_id: str
    timestamp: str
    severity: str
    reason: str
    related_event_ids: list[str] = field(default_factory=list)
    source_ip: str = ""
    rule: str = ""
    confidence: str = "medium"
    mitre_technique: str | None = None
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MitreMapping:
    technique_id: str
    technique_name: str
    why: str
    supporting_event_ids: list[str] = field(default_factory=list)
    timestamp: str = ""
    confidence: str = "medium"
    status: str = "observed"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TimelineEntry:
    timestamp: str
    event: str
    source: str
    severity: str
    description: str
    mitre_technique: str = ""
    evidence_event_ids: list[str] = field(default_factory=list)
    demo: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def stable_event_id(raw_line: str, source: str = "nginx") -> str:
    digest = hashlib.sha256(f"{source}\0{raw_line}".encode("utf-8", "replace")).hexdigest()
    return f"evt-{digest[:16]}"


def detection_id(rule: str, event_ids: list[str]) -> str:
    payload = json.dumps([rule, *sorted(event_ids)], separators=(",", ":"))
    return "det-" + hashlib.sha256(payload.encode()).hexdigest()[:16]


def correlation_id(source_ip: str, detection_ids: list[str]) -> str:
    payload = json.dumps([source_ip, *sorted(detection_ids)], separators=(",", ":"))
    return "cor-" + hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class Correlation:
    correlation_id: str
    source_ip: str
    start_time: str
    end_time: str
    related_event_ids: list[str] = field(default_factory=list)
    related_detection_ids: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "medium"
    confidence: str = "medium"
    stages_observed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskAssessment:
    score: int
    severity: str
    breakdown: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationResult:
    investigation_id: str
    target: str
    start_time: str
    end_time: str
    events: list[SecurityEvent] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    correlations: list[Correlation] = field(default_factory=list)
    mappings: list[MitreMapping] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    risk: RiskAssessment = field(default_factory=lambda: RiskAssessment(0, "Low"))
    level1_context: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_id": self.investigation_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "events": [event.to_dict() for event in self.events],
            "detections": [detection.to_dict() for detection in self.detections],
            "correlations": [corr.to_dict() for corr in self.correlations],
            "mappings": [mapping.to_dict() for mapping in self.mappings],
            "timeline": [entry.to_dict() for entry in self.timeline],
            "risk": self.risk.to_dict(),
            "level1_context": self.level1_context,
        }

