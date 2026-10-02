"""Integrity guard: notices that the record itself was tampered with.

The rules engine catches wiping commands in the logs it reads, and the collector reports a log that
shrinks or vanishes without being rotated. This part watches what only the core can see:

* the audit chain: a record changed or removed outside SentrAI breaks it (audit.py), and a deleted
  database file means the record on disk is gone;
* the clock: a wall-clock jump on the core host, or a sudden change in how far a collector's clock
  is from the core's, moves new log lines into the wrong time window.

Each finding becomes an ordinary event (source ``audit_integrity``) that the rules classify as
``log_tampering``, so it opens an incident, is audited and notified like any other.
"""

from __future__ import annotations

import socket
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit import AuditLog


def integrity_event(text: str, host: str | None = None) -> dict[str, Any]:
    return {
        "event_id": f"evt-integrity-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": host or socket.gethostname() or "sentrai-core",
        "layer": "os",
        "source": "audit_integrity",
        "src_ip": None,
        "user": None,
        "raw": f"audit-integrity {text}",
        "asset_criticality": 1.0,
    }


def _parse_ts(value: Any) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


def _steady() -> tuple[float, bool]:
    """A clock that never jumps when the wall clock is changed, and whether it also counts time
    spent suspended. Without that (macOS, Windows), a laptop waking from sleep would look like a
    forward jump, so only backward jumps are reported there."""
    boottime = getattr(time, "CLOCK_BOOTTIME", None)
    if boottime is not None:
        try:
            return time.clock_gettime(boottime), True
        except OSError:
            pass
    return time.monotonic(), False


class IntegrityGuard:
    def __init__(self, audit: AuditLog, every_s: float = 30.0, clock_jump_s: float = 120.0) -> None:
        self.audit = audit
        self.every_s = every_s
        self.clock_jump_s = clock_jump_s
        self._next = 0.0
        self._reported_seq: int | None = None
        self._reported_missing = False
        self._offset = time.time() - _steady()[0]
        self._beats: dict[str, tuple[float, float]] = {}  # host -> (sent ts, arrival on the steady clock)

    def check(self, force: bool = False) -> list[dict[str, Any]]:
        """Audit chain, audit file and core clock; at most every ``every_s`` seconds unless forced."""
        mono = time.monotonic()
        if not force and mono < self._next:
            return []
        self._next = mono + self.every_s
        out: list[dict[str, Any]] = []
        if not self.audit.path.exists():
            if not self._reported_missing:
                self._reported_missing = True
                out.append(integrity_event(f"deleted: the audit database {self.audit.path.name} was removed from "
                                           f"disk while SentrAI was running"))
        else:
            self._reported_missing = False
        valid, bad = self.audit.verify()
        if not valid and bad != self._reported_seq:
            self._reported_seq = bad
            out.append(integrity_event(f"chain broken at record {bad}: a record was changed or removed outside "
                                       f"SentrAI"))
        elif valid:
            self._reported_seq = None
        steady, counts_sleep = _steady()
        offset = time.time() - steady
        jump = offset - self._offset
        self._offset = offset
        if jump < -self.clock_jump_s or (counts_sleep and jump > self.clock_jump_s):
            out.append(integrity_event(f"clock jumped {'forward' if jump > 0 else 'back'} by {abs(jump):.0f} s on "
                                       f"the core host"))
        return out

    def heartbeat(self, host: str, timestamp: Any) -> dict[str, Any] | None:
        """A collector's clock moved sharply between two heartbeats.

        Forward: its timestamps advanced much more than the time between their arrivals. Back: a
        heartbeat is stamped well before the one before it. Heartbeats held back while the core was
        unreachable arrive close together but stamped in order, so they never look like a jump."""
        sent = _parse_ts(timestamp)
        if sent is None:
            return None
        arrived, counts_sleep = _steady()
        last = self._beats.get(host)
        self._beats[host] = (sent, arrived)
        if last is None:
            return None
        d_sent, d_arrived = sent - last[0], arrived - last[1]
        if counts_sleep and d_sent - d_arrived > self.clock_jump_s:
            jump = d_sent - d_arrived
            return integrity_event(f"clock jumped forward by {jump:.0f} s on {host} (collector heartbeat)", host)
        if d_sent < -self.clock_jump_s:
            return integrity_event(f"clock jumped back by {-d_sent:.0f} s on {host} (collector heartbeat)", host)
        return None
