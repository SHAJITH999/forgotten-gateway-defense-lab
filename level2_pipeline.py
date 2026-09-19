from __future__ import annotations

import hashlib
from typing import Any

from level2_correlation import calculate_risk, correlate
from level2_detection import detect, map_mitre
from level2_models import (
    Correlation,
    Detection,
    InvestigationResult,
    MitreMapping,
    RiskAssessment,
    SecurityEvent,
    TimelineEntry,
)


def build_timeline(
    events: list[SecurityEvent],
    detections: list[Detection],
    mappings: list[MitreMapping],
    correlations: list[Correlation] | None = None,
) -> list[TimelineEntry]:
    timeline: list[TimelineEntry] = []

    # Map raw observed events
    for event in events:
        timeline.append(
            TimelineEntry(
                event.timestamp,
                "Observed web activity",
                event.source,
                event.severity,
                f"{event.method} {event.path} returned HTTP {event.status if event.status is not None else '—'} from {event.source_ip or 'unknown source'}.",
                event.mitre_technique or "",
                [event.event_id],
            )
        )

    # Map individual security detections
    for detection in detections:
        technique = detection.mitre_technique or ""
        timeline.append(
            TimelineEntry(
                detection.timestamp,
                "Security detection",
                "detection-engine",
                detection.severity,
                detection.reason,
                technique,
                detection.related_event_ids,
            )
        )

    # Map correlated attack chain milestones
    if correlations:
        for corr in correlations:
            if len(corr.stages_observed) >= 2:
                timeline.append(
                    TimelineEntry(
                        corr.end_time,
                        "Correlated Attack Chain",
                        "correlation-engine",
                        corr.severity,
                        corr.summary,
                        "",
                        corr.related_event_ids,
                    )
                )

    return sorted(timeline, key=lambda item: item.timestamp)


def analyze(
    events: list[SecurityEvent],
    level1_context: Any = None,
    correlation_window_seconds: int = 900,
) -> tuple[list[Detection], list[MitreMapping], list[TimelineEntry]]:
    """
    Legacy 3-tuple return for backwards compatibility with existing callers.
    """
    detections = detect(events)
    correlations = correlate(events, detections, correlation_window_seconds=correlation_window_seconds)
    mappings = map_mitre(events, detections)
    timeline = build_timeline(events, detections, mappings, correlations)
    return detections, mappings, timeline


def run_investigation(
    events: list[SecurityEvent],
    level1_context: Any = None,
    target: str = "",
    correlation_window_seconds: int = 900,
) -> InvestigationResult:
    """
    Full end-to-end investigation pipeline returning an InvestigationResult.
    """
    detections = detect(events)
    correlations = correlate(events, detections, correlation_window_seconds=correlation_window_seconds)
    mappings = map_mitre(events, detections)
    timeline = build_timeline(events, detections, mappings, correlations)
    risk = calculate_risk(detections, correlations, level1_context=level1_context)

    target_ip = target
    if not target_ip and level1_context:
        target_ip = getattr(level1_context, "target_ip", "")
    if not target_ip and events:
        target_ip = events[0].destination or events[0].host or events[0].source_ip or "127.0.0.1"

    start_time = events[0].timestamp if events else ""
    end_time = events[-1].timestamp if events else ""

    inv_hash = hashlib.sha256(f"{target_ip}:{start_time}:{len(events)}".encode()).hexdigest()[:12]
    inv_id = f"inv-{inv_hash}"

    level1_dict = None
    if level1_context:
        if hasattr(level1_context, "to_dict"):
            level1_dict = level1_context.to_dict()
        elif isinstance(level1_context, dict):
            level1_dict = level1_context

    return InvestigationResult(
        investigation_id=inv_id,
        target=target_ip,
        start_time=start_time,
        end_time=end_time,
        events=events,
        detections=detections,
        correlations=correlations,
        mappings=mappings,
        timeline=timeline,
        risk=risk,
        level1_context=level1_dict,
    )
