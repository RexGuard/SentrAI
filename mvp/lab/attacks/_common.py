"""Shared helpers for the lab attack scripts.

SAFETY: every attack script targets ONLY the local demo app. Any host other
than localhost is hard-refused before a single request is sent. These scripts
generate log noise against our own target app; they are not general-purpose
attack tools.
"""
from __future__ import annotations

import argparse
import sys

import requests

# The only hosts an attack script may ever touch.
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1"}
TARGET_PORT = 5000


class NonLocalTargetError(ValueError):
    """Raised when an attack script is pointed at anything but localhost."""


def require_localhost(host: str, port: int = TARGET_PORT) -> None:
    """Refuse any non-localhost target. Raises NonLocalTargetError."""
    if host not in ALLOWED_HOSTS:
        raise NonLocalTargetError(
            f"refusing to target host {host!r}: attack scripts may only hit "
            f"{sorted(ALLOWED_HOSTS)} (the local demo app)."
        )
    if int(port) != TARGET_PORT:
        raise NonLocalTargetError(
            f"refusing port {port}: the demo target app only runs on :{TARGET_PORT}."
        )


def base_url(host: str, port: int = TARGET_PORT) -> str:
    require_localhost(host, port)
    return f"http://{host}:{port}"


def build_parser(description: str, default_count: int, default_delay: float,
                 default_src: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--host", default="127.0.0.1",
                    help="target host (localhost only; anything else is refused)")
    ap.add_argument("--port", type=int, default=TARGET_PORT)
    ap.add_argument("--count", type=int, default=default_count,
                    help="number of requests to send")
    ap.add_argument("--delay", type=float, default=default_delay,
                    help="seconds between requests")
    ap.add_argument("--src-ip", default=default_src,
                    help="value for the X-Demo-Src-IP header (demo attacker IP)")
    return ap


def make_session(src_ip: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "X-Demo-Src-IP": src_ip,
        "User-Agent": "cactai-lab-attack/1.0",
    })
    return s


def guard_or_exit(host: str, port: int) -> str:
    """Validate the target and return the base URL, or exit(2) with a message."""
    try:
        return base_url(host, port)
    except NonLocalTargetError as exc:
        print(f"[REFUSED] {exc}", file=sys.stderr)
        raise SystemExit(2)


def banner(name: str, base: str, src_ip: str, count: int, delay: float) -> None:
    print("=" * 62)
    print(f"  CactAI lab attack: {name}")
    print(f"  target   : {base}")
    print(f"  attacker : {src_ip}  (X-Demo-Src-IP)")
    print(f"  count    : {count}   delay: {delay}s")
    print("=" * 62)
