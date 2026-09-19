from __future__ import annotations

from level2_detection import detect, map_mitre
from level2_models import Detection, MitreMapping, SecurityEvent, TimelineEntry


def build_timeline(events: list[SecurityEvent], detections: list[Detection], mappings: list[MitreMapping]) -> list[TimelineEntry]:
    timeline: list[TimelineEntry] = []
    for event in events:
        timeline.append(TimelineEntry(event.timestamp, "Observed web activity", event.source, event.severity, f"{event.method} {event.path} returned HTTP {event.status if event.status is not None else '—'} from {event.source_ip or 'unknown source'}.", event.mitre_technique or "", [event.event_id]))
    for detection in detections:
        technique = detection.mitre_technique or ""
        timeline.append(TimelineEntry(detection.timestamp, "Security detection", "detection-engine", detection.severity, detection.reason, technique, detection.related_event_ids))
    return sorted(timeline, key=lambda item: item.timestamp)


def analyze(events: list[SecurityEvent]) -> tuple[list[Detection], list[MitreMapping], list[TimelineEntry]]:
    detections = detect(events)
    mappings = map_mitre(events, detections)
    return detections, mappings, build_timeline(events, detections, mappings)
