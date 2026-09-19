from __future__ import annotations

from datetime import datetime, timedelta
from typing import Callable

from level2_models import SecurityEvent
from nginx_parser import parse_access_line


def generate_scenario_a_normal_traffic(
    source_ip: str = "192.168.1.55",
    base_time: str = "2026-09-19T09:00:00+05:30",
) -> list[str]:
    """
    Scenario A: Normal traffic.
    Expected: Zero high-severity detections, low risk score.
    """
    dt = datetime.fromisoformat(base_time)
    lines = [
        f'{source_ip} - - [{(dt + timedelta(seconds=0)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=5)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /products HTTP/1.1" 200 4500 "-" "Mozilla/5.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=12)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /login HTTP/1.1" 200 850 "-" "Mozilla/5.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=20)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 200 120 "-" "Mozilla/5.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=25)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /profile HTTP/1.1" 200 2300 "-" "Mozilla/5.0"',
    ]
    return lines


def generate_scenario_b_auth_anomaly(
    source_ip: str = "198.51.100.20",
    base_time: str = "2026-09-19T09:10:00+05:30",
) -> list[str]:
    """
    Scenario B: Authentication anomaly.
    Repeated POST /login failures (401/403) within threshold.
    Expected: repeated-failed-authentication detection.
    """
    dt = datetime.fromisoformat(base_time)
    lines = [
        f'{source_ip} - - [{(dt + timedelta(seconds=0)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 401 128 "-" "Python-Requests/2.28"',
        f'{source_ip} - - [{(dt + timedelta(seconds=10)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 401 128 "-" "Python-Requests/2.28"',
        f'{source_ip} - - [{(dt + timedelta(seconds=20)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 403 128 "-" "Python-Requests/2.28"',
    ]
    return lines


def generate_scenario_c_account_discovery(
    source_ip: str = "203.0.113.45",
    base_time: str = "2026-09-19T09:15:00+05:30",
) -> list[str]:
    """
    Scenario C: Account discovery probing.
    Expected: account-discovery-path detections.
    """
    dt = datetime.fromisoformat(base_time)
    lines = [
        f'{source_ip} - - [{(dt + timedelta(seconds=0)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /users HTTP/1.1" 200 450 "-" "curl/7.68.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=8)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /accounts HTTP/1.1" 200 620 "-" "curl/7.68.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=15)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /api/users HTTP/1.1" 200 1200 "-" "curl/7.68.0"',
    ]
    return lines


def generate_scenario_d_admin_probing(
    source_ip: str = "203.0.113.88",
    base_time: str = "2026-09-19T09:20:00+05:30",
) -> list[str]:
    """
    Scenario D: Administrative endpoint probing.
    Expected: admin-path-access detections.
    """
    dt = datetime.fromisoformat(base_time)
    lines = [
        f'{source_ip} - - [{(dt + timedelta(seconds=0)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /admin HTTP/1.1" 404 321 "-" "Go-http-client/1.1"',
        f'{source_ip} - - [{(dt + timedelta(seconds=6)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /management HTTP/1.1" 404 321 "-" "Go-http-client/1.1"',
        f'{source_ip} - - [{(dt + timedelta(seconds=14)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /actuator HTTP/1.1" 404 321 "-" "Go-http-client/1.1"',
    ]
    return lines


def generate_scenario_e_multi_stage(
    source_ip: str = "198.51.100.99",
    base_time: str = "2026-09-19T09:30:00+05:30",
) -> list[str]:
    """
    Scenario E: Multi-stage suspicious activity sequence.
    Probing -> Account discovery -> Credential brute force -> Sensitive resource access attempt.
    Expected: Multiple detections, correlated attack chain, High/Critical risk score.
    """
    dt = datetime.fromisoformat(base_time)
    lines = [
        f'{source_ip} - - [{(dt + timedelta(seconds=0)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /admin HTTP/1.1" 404 321 "-" "CustomScanner/1.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=15)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /users HTTP/1.1" 200 550 "-" "CustomScanner/1.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=30)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 401 128 "-" "CustomScanner/1.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=35)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 401 128 "-" "CustomScanner/1.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=40)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "POST /login HTTP/1.1" 403 128 "-" "CustomScanner/1.0"',
        f'{source_ip} - - [{(dt + timedelta(seconds=60)).strftime("%d/%b/%Y:%H:%M:%S +0530")}] "GET /backup HTTP/1.1" 200 8192 "-" "CustomScanner/1.0"',
    ]
    return lines


SCENARIOS: dict[str, Callable[[], list[str]]] = {
    "normal": generate_scenario_a_normal_traffic,
    "auth_anomaly": generate_scenario_b_auth_anomaly,
    "account_discovery": generate_scenario_c_account_discovery,
    "admin_probing": generate_scenario_d_admin_probing,
    "multi_stage": generate_scenario_e_multi_stage,
}


def parse_scenario_lines(lines: list[str], destination: str = "127.0.0.1", destination_port: int = 80) -> list[SecurityEvent]:
    """
    Passes raw synthetic Nginx log lines through the real Nginx parser.
    Ensures real parsing pipeline execution.
    """
    events: list[SecurityEvent] = []
    for line in lines:
        ev = parse_access_line(line, destination=destination, destination_port=destination_port)
        if ev:
            events.append(ev)
    return events
