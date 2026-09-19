from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from level2_detection import _timestamp
from level2_models import Correlation, Detection, RiskAssessment, SecurityEvent, correlation_id


STAGE_NAMES = {
    "admin-path-access": "Reconnaissance / Probing",
    "account-discovery-path": "Account Discovery",
    "repeated-failed-authentication": "Authentication Anomaly",
    "transfer-path-observed": "Sensitive Resource Access",
}


def correlate(
    events: list[SecurityEvent],
    detections: list[Detection],
    correlation_window_seconds: int = 900,
) -> list[Correlation]:
    """
    Correlates security events and detections by source IP within a sliding time window.
    Groups multi-stage activities into a cohesive investigation chain.
    """
    if not detections:
        return []

    # Group detections by source_ip
    by_ip: dict[str, list[Detection]] = defaultdict(list)
    for det in detections:
        ip = det.source_ip or "unknown"
        by_ip[ip].append(det)

    correlations: list[Correlation] = []

    for ip, dets in by_ip.items():
        dets.sort(key=lambda d: _timestamp(d.timestamp))
        
        # Partition into time windows
        windows: list[list[Detection]] = []
        current_cluster: list[Detection] = []
        cluster_start = None

        for det in dets:
            det_dt = _timestamp(det.timestamp)
            if not current_cluster:
                current_cluster.append(det)
                cluster_start = det_dt
            else:
                if cluster_start and (det_dt - cluster_start) <= timedelta(seconds=correlation_window_seconds):
                    current_cluster.append(det)
                else:
                    windows.append(current_cluster)
                    current_cluster = [det]
                    cluster_start = det_dt
        if current_cluster:
            windows.append(current_cluster)

        for cluster in windows:
            # Collect unique event IDs
            related_event_ids: list[str] = []
            for d in cluster:
                for eid in d.related_event_ids:
                    if eid not in related_event_ids:
                        related_event_ids.append(eid)

            det_ids = [d.detection_id for d in cluster]
            rules_seen = list(dict.fromkeys(d.rule for d in cluster))
            stages = [STAGE_NAMES.get(r, r) for r in rules_seen]

            start_time = cluster[0].timestamp
            end_time = cluster[-1].timestamp
            cid = correlation_id(ip, det_ids)

            # Determine severity & confidence based on multi-stage progression
            if len(rules_seen) >= 3 or ("repeated-failed-authentication" in rules_seen and len(rules_seen) >= 2):
                severity = "critical" if len(rules_seen) >= 3 else "high"
                confidence = "high"
                summary = (
                    f"Multi-stage attack chain observed from {ip}: "
                    + " -> ".join(stages)
                    + f" ({len(cluster)} detections, {len(related_event_ids)} events)."
                )
            elif len(rules_seen) == 2:
                severity = "high"
                confidence = "medium"
                summary = (
                    f"Correlated suspicious activity sequence from {ip}: "
                    + " -> ".join(stages)
                    + f" ({len(cluster)} detections)."
                )
            else:
                severity = cluster[0].severity
                confidence = cluster[0].confidence
                summary = (
                    f"Clustered activity for rule '{rules_seen[0]}' from {ip} "
                    + f"({len(cluster)} detections across {len(related_event_ids)} events)."
                )

            correlations.append(
                Correlation(
                    correlation_id=cid,
                    source_ip=ip,
                    start_time=start_time,
                    end_time=end_time,
                    related_event_ids=related_event_ids,
                    related_detection_ids=det_ids,
                    summary=summary,
                    severity=severity,
                    confidence=confidence,
                    stages_observed=stages,
                )
            )

    return sorted(correlations, key=lambda c: _timestamp(c.start_time))


def calculate_risk(
    detections: list[Detection],
    correlations: list[Correlation],
    level1_context: Any = None,
) -> RiskAssessment:
    """
    Calculates a project-specific, evidence-based risk score (0-100).

    Scoring model:
    - Administrative endpoint probing: +15
    - Account discovery: +20
    - Repeated authentication failure: +30
    - Sensitive resource / transfer access: +25
    - Multi-stage correlation chain: +10 per multi-stage correlation
    - Level 1 exposure context (open web ports 80/443/8080/3000): +5
    """
    score = 0
    breakdown: list[dict[str, Any]] = []

    # Rule points mapping
    rule_weights = {
        "admin-path-access": (15, "Administrative endpoint probing observed"),
        "account-discovery-path": (20, "Account discovery activity observed"),
        "repeated-failed-authentication": (30, "Repeated failed authentication attempts within window"),
        "transfer-path-observed": (25, "Sensitive resource / transfer endpoint accessed"),
    }

    seen_rules = set()
    for det in detections:
        if det.rule in rule_weights and det.rule not in seen_rules:
            pts, desc = rule_weights[det.rule]
            score += pts
            breakdown.append({"factor": det.rule, "points": pts, "rationale": desc})
            seen_rules.add(det.rule)

    # Multi-stage correlation bonus
    multi_stage_correlations = [c for c in correlations if len(c.stages_observed) >= 2]
    if multi_stage_correlations:
        pts = min(20, len(multi_stage_correlations) * 10)
        score += pts
        breakdown.append({
            "factor": "multi_stage_correlation",
            "points": pts,
            "rationale": f"Correlated multi-stage attack chain(s) identified ({len(multi_stage_correlations)} chain(s))",
        })

    # Level 1 infrastructure context bonus
    if level1_context is not None:
        services = getattr(level1_context, "services", [])
        web_ports_open = any(
            getattr(s, "port", 0) in (80, 443, 8080, 3000, 8443) or "http" in getattr(s, "service", "").lower()
            for s in services
        )
        if web_ports_open:
            score += 5
            breakdown.append({
                "factor": "level1_exposed_service",
                "points": 5,
                "rationale": "Level 1 scan confirmed public web service is open and exposed on target",
            })

    # Cap at 100
    final_score = min(100, max(0, score))

    if final_score >= 80:
        severity = "Critical"
    elif final_score >= 60:
        severity = "High"
    elif final_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    return RiskAssessment(score=final_score, severity=severity, breakdown=breakdown)
