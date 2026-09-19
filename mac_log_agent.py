from __future__ import annotations

import argparse
import socket
import time

from nginx_collector import NginxLogCollector
from telemetry_transport import encode, make_envelope


def send_message(sock: socket.socket, message_type: str, token: str, payload: dict) -> None:
    sock.sendall(encode(make_envelope(message_type, token, payload)))


def run(args: argparse.Namespace) -> None:
    collector = NginxLogCollector(args.access_log, args.error_log)
    print(f"Following Nginx logs: access={args.access_log!r}, error={args.error_log!r}")
    print(f"Sending authenticated telemetry to {args.receiver_host}:{args.receiver_port}")
    while True:
        try:
            with socket.create_connection((args.receiver_host, args.receiver_port), timeout=10) as sock:
                sock.settimeout(None)
                print("Connected to receiver")
                while True:
                    for event in collector.collect():
                        send_message(sock, "event", args.token, event.to_dict())
                        print(f"Sent {event.event_id} {event.timestamp} {event.method} {event.path}", flush=True)
                    send_message(sock, "heartbeat", args.token, {"agent": "nginx-log-agent"})
                    time.sleep(args.interval)
        except (OSError, ConnectionError) as exc:
            print(f"Receiver unavailable ({exc}); retrying in {args.retry_seconds}s", flush=True)
            time.sleep(args.retry_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Authenticated Nginx access/error log telemetry agent")
    parser.add_argument("--access-log", required=True, help="Mac-side Nginx access.log path")
    parser.add_argument("--error-log", required=True, help="Mac-side Nginx error.log path")
    parser.add_argument("--receiver-host", required=True, help="Windows receiver IP or hostname")
    parser.add_argument("--receiver-port", type=int, default=8765)
    parser.add_argument("--token", required=True, help="Shared authentication token; keep it private")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between incremental reads")
    parser.add_argument("--retry-seconds", type=float, default=5.0)
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
