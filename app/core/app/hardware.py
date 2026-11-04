"""Each machine's hardware, as its agent sees it: CPU, memory, disks, network, uptime and temperatures.

The agent sends a reading every 30 seconds (lab/agent/hardware.py, POST /fleet/hardware). The panel keeps
the latest one and about an hour of history per machine, in memory only: a restart starts the charts
again, which is fine for numbers that change every few seconds anyway.

A reading over a limit for long enough tells the on-duty person once ("web-01: disk / is 93% full"), and
again only after it has come back down. Limits (SENTRAI_HW_*):

  SENTRAI_HW_ALERTS    on       off: show the numbers, never send an alert
  SENTRAI_HW_CPU_PCT   90       CPU use
  SENTRAI_HW_MEM_PCT   90       memory use
  SENTRAI_HW_DISK_PCT  90       any one disk's use
  SENTRAI_HW_TEMP_C    85       the hottest sensor, in degrees Celsius
  SENTRAI_HW_FOR_MIN   5        how long CPU, memory or heat must stay over before it counts (disks count at once)
"""
from __future__ import annotations

import os
import threading
from collections import deque
from typing import Any, Callable

HISTORY = 120  # readings kept per machine: an hour at one every 30 s
CLEAR_BY = 5.0  # a limit is clear again once the reading is this far under it, so a value on the line does not flap
OFF = {"0", "off", "false", "no"}


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "") or default)
    except ValueError:
        return default


def limits() -> dict[str, Any]:
    return {"alerts": os.getenv("SENTRAI_HW_ALERTS", "on").strip().lower() not in OFF,
            "cpu": _f("SENTRAI_HW_CPU_PCT", 90), "memory": _f("SENTRAI_HW_MEM_PCT", 90),
            "disk": _f("SENTRAI_HW_DISK_PCT", 90), "temp": _f("SENTRAI_HW_TEMP_C", 85),
            "for_min": _f("SENTRAI_HW_FOR_MIN", 5)}


def hottest(reading: dict[str, Any]) -> dict[str, Any] | None:
    temps = [t for t in reading.get("temps") or [] if t.get("current") is not None]
    return max(temps, key=lambda t: t["current"]) if temps else None


def fullest(reading: dict[str, Any]) -> dict[str, Any] | None:
    disks = [d for d in reading.get("disks") or [] if d.get("percent") is not None]
    return max(disks, key=lambda d: d["percent"]) if disks else None


def point(reading: dict[str, Any], at: str) -> dict[str, Any]:
    """One reading cut down for the charts."""
    net, disk, temp = reading.get("net") or {}, fullest(reading), hottest(reading)
    return {"t": at, "cpu": (reading.get("cpu") or {}).get("percent"),
            "memory": (reading.get("memory") or {}).get("percent"),
            "disk": disk["percent"] if disk else None, "temp": temp["current"] if temp else None,
            "net_in": net.get("recv_rate"), "net_out": net.get("sent_rate")}


def _checks(reading: dict[str, Any], lim: dict[str, Any]) -> list[tuple[str, float | None, float, bool, str]]:
    """(key, value, limit, waits, what) for every limit a reading can cross. waits: must stay over for_min."""
    out: list[tuple[str, float | None, float, bool, str]] = [
        ("cpu", (reading.get("cpu") or {}).get("percent"), lim["cpu"], True, "CPU"),
        ("memory", (reading.get("memory") or {}).get("percent"), lim["memory"], True, "memory"),
    ]
    for d in reading.get("disks") or []:
        out.append((f"disk:{d.get('mount')}", d.get("percent"), lim["disk"], False, f"disk {d.get('mount')}"))
    t = hottest(reading)
    if t:
        out.append(("temp", t["current"], lim["temp"], True, f"{t.get('label') or 'sensor'} temperature"))
    return out


def _say(what: str, key: str, value: float, limit: float) -> str:
    if key == "temp":
        return f"{what} is {value:.0f} °C (limit {limit:.0f} °C)"
    if key.startswith("disk:"):
        return f"{what} is {value:.0f}% full (limit {limit:.0f}%)"
    return f"{what} at {value:.0f}% (limit {limit:.0f}%)"


class Health:
    """Latest reading, short history and limit state for every machine that reports its hardware."""

    def __init__(self, clock: Callable[[], float], iso: Callable[[float], str],
                 limits_fn: Callable[[], dict[str, Any]] = limits) -> None:
        self.clock, self.iso, self.limits = clock, iso, limits_fn
        self.lock = threading.Lock()
        self._latest: dict[str, dict[str, Any]] = {}
        self._history: dict[str, deque] = {}
        self._over: dict[str, dict[str, float]] = {}  # host -> limit key -> when it first went over
        self._told: dict[str, dict[str, str]] = {}  # host -> limit key -> the alert line already sent

    def record(self, host: str, reading: dict[str, Any]) -> dict[str, list[str]]:
        """Keep a reading. Returns {"alerts": lines newly over a limit, "cleared": lines back under}."""
        now = self.clock()
        at = self.iso(now)
        lim = self.limits()
        alerts, cleared = [], []
        with self.lock:
            self._latest[host] = {**reading, "at": at}
            self._history.setdefault(host, deque(maxlen=HISTORY)).append(point(reading, at))
            over, told = self._over.setdefault(host, {}), self._told.setdefault(host, {})
            seen = set()
            for key, value, limit, waits, what in _checks(reading, lim):
                if value is None:
                    continue
                seen.add(key)
                if value >= limit:
                    since = over.setdefault(key, now)
                    if key not in told and (not waits or now - since >= lim["for_min"] * 60):
                        told[key] = _say(what, key, value, limit)
                        alerts.append(told[key])
                elif value < limit - CLEAR_BY:
                    over.pop(key, None)
                    if key in told:
                        cleared.append(told.pop(key))
                else:
                    over.pop(key, None)  # under the limit but not clear yet: the wait starts again next time
            for key in [k for k in told if k not in seen]:  # a disk that is gone, a sensor that stopped answering
                over.pop(key, None)
                cleared.append(told.pop(key))
        return {"alerts": alerts if lim["alerts"] else [], "cleared": cleared}

    def latest(self, host: str) -> dict[str, Any] | None:
        with self.lock:
            r = self._latest.get(host)
            return dict(r, warnings=sorted(self._told.get(host, {}).values())) if r else None

    def view(self, host: str) -> dict[str, Any]:
        """GET /fleet/hardware: one machine's latest reading, its history and the limits in use."""
        with self.lock:
            hist = list(self._history.get(host, ()))
        return {"host": host, "latest": self.latest(host), "history": hist, "limits": self.limits()}

    def forget(self, host: str) -> None:
        with self.lock:
            for d in (self._latest, self._history, self._over, self._told):
                d.pop(host, None)
