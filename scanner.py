from __future__ import annotations

import ipaddress
import shutil
import subprocess

NMAP_ARGUMENTS = [
    "sudo", "-n", "nmap", "-sS", "-sU", "-sV", "-p",
    "T:22,80,443,3000,445,49152,U:53", "-oX", "-",
]
SCAN_TIMEOUT_SECONDS = 180


class ScanError(RuntimeError):
    """A safe, user-facing scan failure."""


def validate_target(target: str) -> str:
    candidate = target.strip()
    try:
        ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ScanError("Enter a valid IP address.") from exc
    return candidate


def nmap_command(target_ip: str) -> list[str]:
    return [*NMAP_ARGUMENTS, validate_target(target_ip)]


def run_nmap(target_ip: str) -> str:
    target = validate_target(target_ip)
    if shutil.which("nmap") is None:
        raise ScanError("Nmap was not found on this system.")

    try:
        process = subprocess.Popen(
            nmap_command(target),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        stdout, stderr = process.communicate(timeout=SCAN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.communicate()
        raise ScanError("Nmap scan timed out after 180 seconds.") from exc
    except PermissionError as exc:
        raise ScanError("Nmap requires elevated privileges. Configure passwordless execution for Nmap or run the scanner with appropriate privileges.") from exc
    except OSError as exc:
        raise ScanError(f"Unable to start Nmap: {exc}") from exc

    if process.returncode != 0:
        error = (stderr or "").lower()
        if "password" in error or "sudo" in error or "permission" in error:
            raise ScanError("Nmap requires elevated privileges. Configure passwordless execution for Nmap or run the scanner with appropriate privileges.")
        raise ScanError("Target could not be reached or returned no usable scan results.")
    if not stdout.strip():
        raise ScanError("Target could not be reached or returned no usable scan results.")
    return stdout
