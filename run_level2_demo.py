from __future__ import annotations

import argparse
import json
import sys

from level2_models import SecurityEvent
from level2_pipeline import run_investigation
from level2_scenarios import SCENARIOS, parse_scenario_lines
from models import ScanResult, Service


def run_demo(scenario_name: str = "multi_stage") -> None:
    print("=" * 70)
    print("  FORGOTTEN GATEWAY DEFENSE LAB — LEVEL 2 DEMONSTRATION")
    print("=" * 70)

    if scenario_name not in SCENARIOS:
        print(f"Unknown scenario '{scenario_name}'. Available: {list(SCENARIOS.keys())}")
        sys.exit(1)

    print(f"\n[1] Generating Scenario: {scenario_name.upper()}")
    raw_lines = SCENARIOS[scenario_name]()
    for line in raw_lines:
        print(f"    LOG > {line}")

    print(f"\n[2] Executing Real Parser Pipeline (nginx_parser -> SecurityEvent)")
    events = parse_scenario_lines(raw_lines, destination="127.0.0.1", destination_port=80)
    print(f"    Normalized into {len(events)} SecurityEvent object(s).")

    # Mock Level 1 scan context for correlation & risk scoring
    mock_level1 = ScanResult(
        target_ip="127.0.0.1",
        raw_xml="<nmaprun></nmaprun>",
        services=[
            Service(port=80, protocol="TCP", state="open", service="http", product="nginx", version="1.21.6"),
            Service(port=22, protocol="TCP", state="open", service="ssh", product="OpenSSH", version="8.2"),
        ],
    )
    print(f"\n[3] Integrated Level 1 Context: Target {mock_level1.target_ip} with open ports "
          f"{[f'{s.port}/{s.protocol}' for s in mock_level1.services]}")

    print(f"\n[4] Running Level 2 Investigation Engine (Detection + Correlation + MITRE + Risk + Timeline)")
    result = run_investigation(events, level1_context=mock_level1, target=mock_level1.target_ip)

    print("\n" + "-" * 70)
    print("  LEVEL 2 INVESTIGATION SUMMARY")
    print("-" * 70)
    print(f"  Investigation ID : {result.investigation_id}")
    print(f"  Target           : {result.target}")
    print(f"  Time Window      : {result.start_time} -> {result.end_time}")
    print(f"  Events Parsed    : {len(result.events)}")
    print(f"  Detections       : {len(result.detections)}")
    print(f"  Correlations     : {len(result.correlations)}")
    print(f"  Risk Score       : {result.risk.score}/100 [{result.risk.severity.upper()}]")

    print("\n[5] Risk Score Breakdown:")
    for item in result.risk.breakdown:
        print(f"    + {item['points']} pts | {item['factor']} : {item['rationale']}")

    if result.correlations:
        print(f"\n[6] Attack Correlation Chains ({len(result.correlations)}):")
        for corr in result.correlations:
            print(f"    * [{corr.correlation_id}] {corr.source_ip} ({corr.severity.upper()})")
            print(f"      Summary: {corr.summary}")
            print(f"      Stages : {' -> '.join(corr.stages_observed)}")
            print(f"      Window : {corr.start_time} to {corr.end_time}")

    print(f"\n[7] Security Detections ({len(result.detections)}):")
    for det in result.detections:
        print(f"    * [{det.detection_id}] [{det.severity.upper()}] {det.rule}")
        print(f"      Reason     : {det.reason}")
        print(f"      Source IP  : {det.source_ip}")
        print(f"      Technique  : {det.mitre_technique or '—'}")
        print(f"      Evidence   : {len(det.related_event_ids)} event(s) -> {det.related_event_ids}")

    print(f"\n[8] MITRE ATT&CK Mapping ({len(result.mappings)}):")
    for m in result.mappings:
        print(f"    * [{m.technique_id}] {m.technique_name} | Status: {m.status} | Confidence: {m.confidence}")
        print(f"      Why: {m.why}")

    print(f"\n[9] Reconstructed Incident Timeline ({len(result.timeline)} items):")
    for t in result.timeline:
        ev_str = f" [evidence: {', '.join(t.evidence_event_ids)}]" if t.evidence_event_ids else ""
        print(f"    {t.timestamp} | {t.source:18} | [{t.severity.upper():8}] {t.description}{ev_str}")

    print("\n" + "=" * 70)
    print("  DEMO EXECUTION COMPLETE: LEVEL 2 PIPELINE VERIFIED")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Forgotten Gateway Defense Lab - Level 2 Attack Reconstruction Demo")
    parser.add_argument(
        "--scenario",
        default="multi_stage",
        choices=["normal", "auth_anomaly", "account_discovery", "admin_probing", "multi_stage", "all"],
        help="Test scenario to execute (default: multi_stage)",
    )
    args = parser.parse_args()

    if args.scenario == "all":
        for sc in ["normal", "auth_anomaly", "account_discovery", "admin_probing", "multi_stage"]:
            run_demo(sc)
            print("\n\n")
    else:
        run_demo(args.scenario)


if __name__ == "__main__":
    main()
