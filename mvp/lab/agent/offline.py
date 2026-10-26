"""Local rules: the agent keeps guarding its machine while the panel cannot be reached.

Normally the panel scores and decides. The agent still runs the core's own rules (app/rules.py, the
same signatures and thresholds, no AI) over every line it sends, so their windows are warm. Once the
panel has not answered for ``offline_after_s`` seconds the agent acts on them by itself, within tight
limits, because no person can be asked:

  * only "block this address", never locking accounts or stopping programs
  * only attacks that name an outside address: brute force, SQL injection, XSS, port scans, privilege
    escalation, data exfiltration and prompt injection
  * an address is blocked when its score in the last ``window_s`` seconds reaches the panel's own
    autonomous line (RISK_THRESHOLD, 80), using the panel's severity points (app/risk.py)
  * never private, shared or protected addresses (PROTECTED_NETS, PROTECTED_IPS, the panel itself)
  * each block lasts ``ttl_s`` (CACTAI_AGENT_LOCAL_TTL_MIN, 60 minutes) and ends by itself
  * at most ``max_per_hour`` new blocks an hour (CACTAI_AGENT_LOCAL_MAX_PER_HOUR, 10)

When the panel answers again, the agent sends it a report of what it scored and blocked (POST
/fleet/offline-report). The logs themselves were held by the collector and reach the panel as usual,
where they are scored properly. CACTAI_AGENT_LOCAL_RULES=off turns local rules off.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

_CORE = str(Path(__file__).resolve().parents[2] / "core")
if _CORE not in sys.path:
    sys.path.append(_CORE)  # the core's rules, scores and safety checks, as in agent.py
from app import firewall, protect  # noqa: E402
from app.risk import SEVERITY, risk_index  # noqa: E402
from app.rules import RulesEngine  # noqa: E402

# Attacks that come from an address, so blocking that address is the right answer.
BLOCKABLE = frozenset({"brute_force", "sql_injection", "xss", "port_scan", "privilege_escalation",
                       "data_exfiltration", "prompt_injection"})
OFFLINE_AFTER_S = 30.0
MAX_REPORT_ACTIONS = 500


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def enabled() -> bool:
    return os.environ.get("CACTAI_AGENT_LOCAL_RULES", "on").strip().lower() not in protect.OFF


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


class LocalGuard:
    def __init__(self, protected: set[str], *, block_at: int | None = None, ttl_s: float | None = None,
                 max_per_hour: int | None = None, window_s: float = 600.0, offline_after_s: float = OFFLINE_AFTER_S,
                 private_nets: set[str] | None = None, clock: Callable[[], float] = time.time,
                 saved: dict[str, Any] | None = None, on: bool = True) -> None:
        self.on = on
        self.protected = set(protected)
        self.private_nets = protect.nets(os.environ.get("PROTECTED_NETS", protect.PRIVATE_NETS)) \
            if private_nets is None else set(private_nets)
        self.block_at = block_at if block_at is not None else int(_env_float("RISK_THRESHOLD", 80))
        self.ttl_s = ttl_s if ttl_s is not None else _env_float("CACTAI_AGENT_LOCAL_TTL_MIN", 60) * 60
        self.max_per_hour = max_per_hour if max_per_hour is not None else int(
            _env_float("CACTAI_AGENT_LOCAL_MAX_PER_HOUR", 10))
        self.window_s = window_s
        self.offline_after_s = offline_after_s
        self.clock = clock
        self.rules = RulesEngine()
        self.lock = threading.Lock()
        self.points: dict[str, deque[tuple[float, float, str, str, str]]] = {}  # ip -> (ts, points, eid, cat, why)
        saved = saved or {}
        self.blocks: dict[str, dict[str, Any]] = dict(saved.get("blocks") or {})  # in force, ip -> action
        self.report: dict[str, Any] | None = saved.get("report")  # waiting to reach the panel
        self.offline_since: float | None = saved.get("offline_since")
        self._made: deque[float] = deque(saved.get("made") or [])
        self.log: list[str] = []

    # ------------------------------------------------------------------ state
    def state(self) -> dict[str, Any]:
        """What survives an agent restart (kept in the agent file)."""
        with self.lock:
            return {"blocks": dict(self.blocks), "report": self.report, "offline_since": self.offline_since,
                    "made": list(self._made)}

    def is_offline(self, last_ok: float, now: float | None = None) -> bool:
        return (now if now is not None else self.clock()) - last_ok >= self.offline_after_s

    def link(self, last_ok: float) -> dict[str, Any] | None:
        """Called after each try to reach the panel. Marks the start of an offline spell, and at its end
        returns the report to send (also kept in ``self.report`` until ``reported()``)."""
        now = self.clock()
        with self.lock:
            if self.is_offline(last_ok, now):
                if self.offline_since is None:
                    self.offline_since = last_ok
                    if self.report is None:  # an undelivered report from a short return carries on
                        self.report = {"from": _iso(last_ok), "scored": 0, "actions": []}
                    self.log.append(f"panel unreachable for {now - last_ok:.0f} s: local rules now decide"
                                    + ("" if self.on else " (off: CACTAI_AGENT_LOCAL_RULES)"))
                return None
            if self.offline_since is not None:
                away = now - self.offline_since
                spell = self.report or {"from": _iso(self.offline_since), "scored": 0, "actions": []}
                spell["to"] = _iso(now)
                self.report, self.offline_since = spell, None
                self.log.append(f"panel back after {away:.0f} s: reporting {len(spell['actions'])} local blocks")
            return self.report

    def reported(self) -> None:
        with self.lock:
            self.report = None

    # ---------------------------------------------------------------- scoring
    def _blockable(self, ip: str) -> str | None:
        """Why this address may not be blocked without a person, or None."""
        if firewall.unsafe_reason(ip, self.protected):
            return firewall.unsafe_reason(ip, self.protected)
        if protect.matches(ip, self.private_nets):
            return "private or shared address (a person decides on those)"
        return None

    def observe(self, events: Iterable[dict[str, Any]], held: set[str] | frozenset[str] = frozenset()
                ) -> list[dict[str, Any]]:
        """Run the rules over events the collector is about to send; while the panel is out of reach,
        block addresses that reach the line. ``held`` are blocks already in force from the panel.
        Returns the new blocks."""
        made: list[dict[str, Any]] = []
        now = self.clock()
        with self.lock:
            offline = self.offline_since is not None
            for ev in events:
                if ev.get("source") == "heartbeat":
                    continue
                try:
                    hit = self.rules.check(ev, now)
                except Exception:  # a rule must never stop the collector
                    continue
                if offline and self.report is not None:
                    self.report["scored"] += 1
                ip = str(ev.get("src_ip") or "")
                if hit is None or hit.category not in BLOCKABLE or not ip:
                    continue
                q = self.points.setdefault(ip, deque(maxlen=200))
                crit = float(ev.get("asset_criticality") or 1.0)
                q.append((now, SEVERITY[hit.category][1] * crit, str(ev.get("event_id") or ""), hit.category,
                          hit.reason))
                while q and now - q[0][0] > self.window_s:
                    q.popleft()
                if not (offline and self.on) or ip in self.blocks or ip in held:
                    continue
                score = risk_index(sum(p for _, p, *_ in q))
                if score < self.block_at:
                    continue
                why_not = self._blockable(ip)
                if why_not:
                    if not any(f"not blocking {ip}:" in line for line in self.log):
                        self.log.append(f"not blocking {ip}: {why_not}")
                    continue
                while self._made and now - self._made[0] > 3600:
                    self._made.popleft()
                if len(self._made) >= self.max_per_hour:
                    self.log.append(f"would block {ip} (score {score}) but {self.max_per_hour} local blocks were "
                                    f"already made this hour")
                    continue
                self._made.append(now)
                cats = sorted({c for *_, c, _ in q})
                action = {"ip": ip, "category": hit.category, "reason": f"{', '.join(cats)}: {hit.reason}"[:300],
                          "score": score, "at": _iso(now), "until": _iso(now + self.ttl_s),
                          "until_ts": now + self.ttl_s, "applied": False,
                          "event_ids": [e for _, _, e, *_ in q if e][-50:]}
                self.blocks[ip] = action
                if self.report is not None and len(self.report["actions"]) < MAX_REPORT_ACTIONS:
                    self.report["actions"].append(action)
                self.log.append(f"local rules: blocking {ip} for {self.ttl_s / 60:g} min (score {score}, "
                                f"{', '.join(cats)})")
                made.append(action)
            if len(self.points) > 5000:  # a scan from many addresses: keep the busiest
                for ip in sorted(self.points, key=lambda k: self.points[k][-1][0] if self.points[k] else 0)[:2500]:
                    del self.points[ip]
        return made

    def wanted(self) -> set[str]:
        """Local blocks still in force; expired ones are dropped here."""
        now = self.clock()
        with self.lock:
            for ip in [ip for ip, a in self.blocks.items() if a.get("until_ts", 0) <= now]:
                del self.blocks[ip]
                self.log.append(f"local block on {ip} expired")
            return set(self.blocks)

    def applied(self, ips: Iterable[str]) -> None:
        """The firewall now holds these: mark them in the report."""
        with self.lock:
            for ip in ips:
                if ip in self.blocks:
                    self.blocks[ip]["applied"] = True
