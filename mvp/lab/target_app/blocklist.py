"""Containment enforcement: the target app polls core ``GET /blocklist``.

The blocklist holds IPs and users currently under temporary containment.
A background thread refreshes it every 2 seconds. If core is unreachable we
*fail open* (allow traffic) as required by the contract, so a dead core can
never lock out the demo.
"""
from __future__ import annotations

import threading
import time

import requests


class Blocklist:
    """Thread-safe snapshot of contained IPs / users."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._ips: set[str] = set()
        self._users: set[str] = set()
        self.last_ok: float | None = None
        self.core_reachable: bool = False

    def update(self, ips=None, users=None) -> None:
        with self._lock:
            self._ips = set(ips or [])
            self._users = set(users or [])

    def is_blocked(self, ip: str | None, user: str | None) -> bool:
        with self._lock:
            if ip and ip in self._ips:
                return True
            if user and user in self._users:
                return True
            return False

    def snapshot(self) -> dict:
        with self._lock:
            return {"ips": sorted(self._ips), "users": sorted(self._users)}


# Process-wide instance shared by the Flask app and the poller.
blocklist = Blocklist()


def poll_once(core_url: str, timeout: float = 1.5) -> bool:
    """Fetch the blocklist once. Returns True if core answered."""
    try:
        resp = requests.get(f"{core_url.rstrip('/')}/blocklist", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        blocklist.update(ips=data.get("ips", []), users=data.get("users", []))
        blocklist.last_ok = time.time()
        blocklist.core_reachable = True
        return True
    except Exception:
        # Fail open: keep whatever we had but mark core unreachable. We do NOT
        # clear the list on a transient blip; a full outage still allows
        # traffic because is_blocked only trips on an explicit entry.
        blocklist.core_reachable = False
        return False


def start_poller(core_url: str, interval: float = 2.0) -> threading.Thread:
    """Start the background blocklist poller (daemon thread)."""

    def _loop() -> None:
        while True:
            poll_once(core_url)
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="blocklist-poller", daemon=True)
    t.start()
    return t
