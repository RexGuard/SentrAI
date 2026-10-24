"""Integrity guard: notices that the record itself was tampered with.

The rules engine catches wiping commands in the logs it reads, and the collector reports a log that
shrinks or vanishes without being rotated. This part watches what only the core can see:

* the audit chain: a record changed or removed outside SentrAI breaks it (audit.py), and a deleted
  database file means the record on disk is gone;
* the collector's line chain: every event a collector sends is sealed to the one before it
  (CONTRACT.md "Line chain"), so a missing batch or a line changed after it was read shows up;
* the clock: a wall-clock jump on the core host, or a sudden change in how far a collector's clock
  is from the core's, moves new log lines into the wrong time window.

Each finding becomes an ordinary event (source ``audit_integrity``) that the rules classify as
``log_tampering``, so it opens an incident, is audited and notified like any other.
"""

from __future__ import annotations

import hashlib
import json
import socket
import time
import uuid
from collections import OrderedDict
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


CHAIN_FIELDS = ("event_id", "timestamp", "host", "layer", "source", "raw")  # same as the collector's
GENESIS = "0" * 64
CHAIN_MEMORY = 2000  # recent (seq -> hash) per stream, to recognise a collector replaying after a crash


def chain_hash(prev: str, event: dict[str, Any]) -> str:
    body = json.dumps([event.get(k) for k in CHAIN_FIELDS], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


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
        self._streams: dict[str, OrderedDict[int, str]] = {}  # collector stream -> recent seq -> hash

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

    def chained(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Checks the seal on one event from a collector (in arrival order). None when it fits.

        Starts trusting a stream at the first event it sees (the core keeps this in memory, so a
        core restart starts over). A collector that crashed before saving its place re-sends
        lines sealed from an earlier record: that fits a hash still remembered, so it is accepted."""
        c = event.get("chain")
        if not isinstance(c, dict):
            return None
        stream, host = str(c.get("stream") or "?"), str(event.get("host") or "unknown")
        try:
            seq = int(c.get("seq"))
        except (TypeError, ValueError):
            return integrity_event(f"altered: an event from collector {stream} has an unreadable seal", host)
        prev, sealed = str(c.get("prev") or ""), str(c.get("hash") or "")
        if chain_hash(prev, event) != sealed:
            return integrity_event(f"altered: event #{seq} from collector {stream} does not match its seal "
                                   f"(changed after the collector read it)", host)
        seen = self._streams.setdefault(stream, OrderedDict())
        last = next(reversed(seen), None)
        fits = (last is None or (seq == 1 and prev == GENESIS) or seen.get(seq - 1) == prev)
        seen[seq] = sealed
        seen.move_to_end(seq)
        while len(seen) > CHAIN_MEMORY:
            seen.popitem(last=False)
        if fits:
            return None
        if last is not None and seq > last + 1:
            return integrity_event(f"gap: collector {stream} jumped from record #{last} to #{seq}: "
                                   f"{seq - last - 1} event(s) never arrived", host)
        return integrity_event(f"altered: event #{seq} from collector {stream} does not follow the one before "
                               f"it (inserted, reordered or rewritten)", host)
