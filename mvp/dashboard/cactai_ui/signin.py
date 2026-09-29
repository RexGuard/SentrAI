"""Failed dashboard sign-ins per address.

Kept in this imported module, not in the page script: Streamlit re-runs app.py on every click, but
imports it only once per process, so every browser session of the dashboard shares these counts.
"""
from __future__ import annotations

import threading
import time

FAIL_LIMIT = 5  # wrong tries from one address ...
FAIL_WINDOW_S = 300  # ... within this many seconds, then it waits until the oldest one is this old

_fails: dict[str, list[float]] = {}
_lock = threading.Lock()


def _recent(ip: str, now: float) -> list[float]:
    kept = [t for t in _fails.get(ip, []) if now - t < FAIL_WINDOW_S]
    if kept:
        _fails[ip] = kept
    else:
        _fails.pop(ip, None)
    return kept


def wait_seconds(ip: str, now: float | None = None) -> float:
    """0 when this address may try again, else how long it has to wait."""
    now = time.time() if now is None else now
    with _lock:
        fails = _recent(ip, now)
        return 0.0 if len(fails) < FAIL_LIMIT else FAIL_WINDOW_S - (now - fails[0])


def failed(ip: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    with _lock:
        _fails[ip] = _recent(ip, now) + [now]


def succeeded(ip: str) -> None:
    with _lock:
        _fails.pop(ip, None)
