from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

PROTOCOL_VERSION = 1


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def make_envelope(message_type: str, token: str, payload: dict[str, Any]) -> dict[str, Any]:
    signed = {"version": PROTOCOL_VERSION, "type": message_type, "token": token, "payload": payload}
    signed["signature"] = hmac.new(token.encode("utf-8"), _canonical(signed), hashlib.sha256).hexdigest()
    return signed


def verify_envelope(envelope: Any, token: str) -> tuple[bool, str, dict[str, Any]]:
    if not isinstance(envelope, dict):
        return False, "message is not an object", {}
    supplied = envelope.get("signature")
    message_type = envelope.get("type")
    payload = envelope.get("payload")
    if envelope.get("version") != PROTOCOL_VERSION or not isinstance(message_type, str) or not isinstance(payload, dict) or not isinstance(supplied, str):
        return False, "invalid protocol envelope", {}
    if not hmac.compare_digest(str(envelope.get("token", "")), token):
        return False, "invalid shared token", {}
    signed = {"version": envelope["version"], "type": message_type, "token": envelope["token"], "payload": payload}
    expected = hmac.new(token.encode("utf-8"), _canonical(signed), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        return False, "invalid message signature", {}
    return True, message_type, payload


def encode(envelope: dict[str, Any]) -> bytes:
    return (_canonical(envelope) + b"\n")
