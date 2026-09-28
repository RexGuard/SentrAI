"""Saguaro: lead orchestrator. Owns incidents, the risk index, notifications and the hotpatch workflow.

All state is in memory (fresh per process / per /demo/reset); the audit chain is in SQLite.
"""

from __future__ import annotations

import copy
import json
import math
import threading
import time
import uuid
from collections import deque
from typing import Any

from .agents import (
    Agent,
    AreoleLinux,
    AreoleWin,
    HelpDesk,
    LayerAgent,
    Needle,
    Proposal,
    Reservoir,
    Root,
    Scribe,
    SpineNet,
    Watchdog,
)
from .audit import AuditLog
from .classifier import Classification, default_chain
from .clock import DemoClock, fmt_demo_hours
from .config import Settings
from .jev_client import JevClient
from .responders import BlocklistResponder, Responders, SimulatedResponder
from .risk import SEVERITY, band, band_rank, inaction_penalty, risk_index
from .rules import RulesEngine

RISK_STATUSES = ("open", "acknowledged")  # count toward raw score
MERGE_STATUSES = ("open", "acknowledged", "contained")  # new events attach to these
CLOSED_STATUSES = ("resolved", "rejected")

TITLES = {
    "brute_force": "Brute force",
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "port_scan": "Port scan",
    "privilege_escalation": "Shell spawned / privilege escalation",
    "data_exfiltration": "Bulk data export",
    "misconfiguration": "Misconfiguration",
}

BUTTONS_DECIDE = [
    {"label": "Approve & Patch", "action": "approve"},
    {"label": "Reject with Justification", "action": "reject"},
    {"label": "Acknowledge", "action": "ack"},
]
BUTTONS_AFTER_ACTION = [
    {"label": "Rollback", "action": "rollback"},
    {"label": "Make Permanent", "action": "permanent"},
    {"label": "Acknowledge", "action": "ack"},
]


class ConflictError(Exception):
    pass


class BadRequestError(Exception):
    pass


def public(obj: Any) -> Any:
    """Deep copy without internal keys (leading underscore)."""
    if isinstance(obj, dict):
        return {k: public(v) for k, v in obj.items() if not k.startswith("_")}
    if isinstance(obj, list):
        return [public(v) for v in obj]
    return copy.deepcopy(obj)


class Saguaro(Agent):
    name = "Saguaro"
    role = "lead orchestrator: routes events, merges findings, owns the risk index"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = s = settings or Settings()
        self.clock = DemoClock(s.demo_speed)
        self.audit = AuditLog(s.db_path)
        self.rules = RulesEngine(s.brute_force_count, s.brute_force_window_s, s.export_rows_threshold)
        self.jev = JevClient(s.jev_timeout_s)
        # The three parts: events arrive from collectors via POST /events, the classifier
        # chain labels them, and the responders carry out approved containment.
        self.classifier, self.jev_step = default_chain(self.rules, self.jev)
        self.blocklist_responder = BlocklistResponder()
        self.responders = Responders(self.blocklist_responder, SimulatedResponder())
        self.root = Root(self.classifier)
        self.reservoir = Reservoir(self.classifier)
        self.spinenet = SpineNet(self.classifier)
        self.areole_linux = AreoleLinux(self.classifier, self.responders)
        self.areole_win = AreoleWin(self.classifier, self.responders)
        self.needle = Needle(s.needle_min_confidence, self.responders.allowlist, s.protected_ips, s.protected_users)
        self.watchdog = Watchdog(s.watchdog_silence_s)
        self.scribe = Scribe(self.audit, self.clock)
        self.helpdesk = HelpDesk()
        self.lock = threading.RLock()
        self._protection_file = s.db_path.parent / "protection.json"
        self._load_protection()
        self._init_state()
        self.scribe.record(self.name, "core_started", self._config_summary())

    # ------------------------------------------------------------------ state
    def _init_state(self) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.actions: list[dict[str, Any]] = []
        self.notifications: list[dict[str, Any]] = []
        self.history: deque[dict[str, Any]] = deque(maxlen=self.settings.history_len)
        self._next_incident = self._next_incident_from_audit()
        self._next_action = 1
        self._next_notif = 1
        self._last_band = "green"
        self._above_threshold = False
        self._started_ts = self.clock.now()
        self._last_risk: dict[str, Any] = {"risk_index": 0, "band": "green", "raw_score": 0.0}
        self._reported: set[str] = set()

    def _next_incident_from_audit(self) -> int:
        best = self.settings.id_start - 1
        for rec in self.audit.records():
            if rec["type"] == "incident_opened":
                try:
                    best = max(best, int(str(rec["data"].get("incident", "")).rsplit("-", 1)[1]))
                except (IndexError, ValueError):
                    pass
        return best + 1

    def _config_summary(self) -> dict[str, Any]:
        s = self.settings
        return {
            "demo_speed": s.demo_speed,
            "threshold": s.threshold,
            "sla_hours": s.sla_hours,
            "ttl_hours": s.ttl_hours,
            "on_duty": s.on_duty,
            "jev": self.jev.status,
            "monitor_only": self.monitor_only,
        }

    def layer_agents(self) -> list[LayerAgent]:
        return [self.root, self.reservoir, self.spinenet, self.areole_linux, self.areole_win]

    def all_agents(self) -> list[Agent]:
        return [self, *self.layer_agents(), self.needle, self.watchdog, self.scribe, self.helpdesk]

    def _route(self, event: dict[str, Any]) -> LayerAgent:
        layer = str(event.get("layer") or "web")
        if layer == "os":
            hint = f"{event.get('host', '')} {event.get('source', '')}".lower()
            return self.areole_win if "win" in hint else self.areole_linux
        if layer == "db":
            return self.reservoir
        if layer in ("network", "cloud"):
            return self.spinenet
        return self.root

    def _agent(self, name: str) -> LayerAgent:
        for a in self.layer_agents():
            if a.name == name:
                return a
        return self.root

    # --------------------------------------------------------------- ingestion
    def ingest(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        accepted = 0
        # Cap the total time one request may spend waiting on Jev; the rest use the fallback.
        self.jev_step.deadline = time.monotonic() + self.settings.jev_budget_s
        for raw_ev in events:
            ev = dict(raw_ev)
            now = self.clock.now()
            ev["event_id"] = str(ev.get("event_id") or f"evt-core-{uuid.uuid4().hex[:12]}")
            ev["host"] = ev.get("host") or "unknown"
            ev["layer"] = ev.get("layer") or "web"
            try:
                ev["asset_criticality"] = float(ev.get("asset_criticality") or 1.0)
            except (TypeError, ValueError):
                ev["asset_criticality"] = 1.0
            heartbeat = ev.get("source") == "heartbeat"
            with self.lock:
                if ev["event_id"] in self.events:
                    continue  # duplicate delivery
                self.events[ev["event_id"]] = {**ev, "category": None}
                recovered = self.watchdog.observe(str(ev["host"]), now, heartbeat)
                if recovered:
                    self.scribe.record(self.watchdog.name, "collector_recovered", recovered)
            accepted += 1
            if heartbeat:
                with self.lock:
                    self.events[ev["event_id"]].update(category="benign", classified_by="rules", reason="heartbeat")
                continue
            agent = self._route(ev)
            cls = agent.analyze(ev, now)  # may call Jev: done outside the lock
            with self.lock:
                self._apply_classification(ev, cls, agent, now)
        with self.lock:
            self._trim_events()
            now = self.clock.now()
            self._evaluate(now)
            self._record_history(now)
            return {"accepted": accepted, "risk_index": self._last_risk["risk_index"]}

    def _trim_events(self, limit: int = 20000) -> None:
        while len(self.events) > limit:
            self.events.pop(next(iter(self.events)))

    def _apply_classification(self, ev: dict[str, Any], cls: Classification, agent: LayerAgent, now: float) -> None:
        rec = self.events[ev["event_id"]]
        rec.update(
            category=cls.category,
            confidence=cls.confidence,
            malicious=cls.malicious,
            classified_by=cls.classified_by,
            reason=cls.reason,
            analyzed_by=agent.name,
            incident=None,
        )
        if cls.category == "benign" or cls.malicious < 0.4:
            return
        needs_review = 0.4 <= cls.malicious <= 0.6
        key = ev.get("src_ip") or ev.get("user") or ev.get("host")
        inc = next(
            (
                i
                for i in self.incidents.values()
                if i["category"] == cls.category
                and i["status"] in MERGE_STATUSES
                and (i.get("src_ip") or i.get("user") or i.get("host")) == key
            ),
            None,
        )
        if inc is None:
            inc = self._open_incident(ev, cls, agent, needs_review, now)
        else:
            self._attach(inc, ev, cls, needs_review, now)
        self.scribe.record(
            agent.name,
            "event_classified",
            {
                "event_id": ev["event_id"],
                "raw": ev.get("raw"),
                "category": cls.category,
                "confidence": cls.confidence,
                "malicious": cls.malicious,
                "classified_by": cls.classified_by,
                "reason": cls.reason,
                "needs_review": needs_review,
                "incident": inc["id"],
            },
        )

    def _open_incident(self, ev: dict[str, Any], cls: Classification, agent: LayerAgent, needs_review: bool, now: float) -> dict[str, Any]:
        iid = f"RSK-{self.settings.id_year}-{self._next_incident:03d}"
        self._next_incident += 1
        severity, base = SEVERITY[cls.category]
        crit = float(ev.get("asset_criticality") or 1.0)
        event_ids = list(dict.fromkeys([*cls.related_event_ids, ev["event_id"]]))
        inc: dict[str, Any] = {
            "id": iid,
            "category": cls.category,
            "severity": severity,
            "base_points": base,
            "ai_confidence": cls.confidence,
            "asset_criticality": crit,
            "points": round(base * cls.confidence * crit, 1),
            "classified_by": cls.classified_by,
            "classification_reason": cls.reason,
            "malicious_probability": cls.malicious,
            "needs_review": needs_review,
            "src_ip": ev.get("src_ip"),
            "user": ev.get("user"),
            "host": ev.get("host"),
            "layer": ev.get("layer"),
            "opened_at": self.clock.iso(now),
            "status": "open",
            "acked": False,
            "acked_by": None,
            "acked_at": None,
            "ack_channel": None,
            "inaction_penalty": 0.0,
            "time_unaddressed_hours": 0.0,
            "sla_breached": False,
            "contribution": 0.0,
            "recommended_action": "",
            "explanation": "",
            "analyzed_by": agent.name,
            "actions": [],
            "event_ids": event_ids,
            "notifications": [],
            "timeline": [],
            "decisions": [],
            "_opened_ts": now,
            "_acked_ts": None,
            "_reminders": 0,
            "_sla_flag": False,
            "_notified_open": False,
            "_autonomous_denied": False,
        }
        self._describe(inc, agent)
        self.incidents[iid] = inc
        for eid in event_ids:
            if eid in self.events:
                self.events[eid]["incident"] = iid
        self._refresh_incident(inc, now)
        self._timeline(inc, now, "detected",
                       f"{TITLES.get(inc['category'], inc['category'])} detected by {agent.name} "
                       f"({cls.classified_by}, confidence {cls.confidence})", inc["points"])
        self.scribe.record(self.name, "incident_opened", {
            "incident": iid, **{k: inc[k] for k in (
                "category", "severity", "base_points", "ai_confidence", "asset_criticality", "points",
                "classified_by", "needs_review", "src_ip", "user", "host", "layer", "opened_at",
                "recommended_action", "event_ids")},
            "analyst": agent.name,
        })
        return inc

    def _proposals(self, inc: dict[str, Any], agent: LayerAgent) -> list[Proposal]:
        """The containment steps for an incident. Cyanide overrides this with its own plan."""
        return agent.propose(inc, self.settings.ttl_hours)

    def _describe(self, inc: dict[str, Any], agent: LayerAgent) -> None:
        proposals = self._proposals(inc, agent)
        inc["recommended_action"] = agent.recommended_text(proposals, self.settings.ttl_hours)
        inc["explanation"] = agent.explain(inc)
        if inc.get("needs_review"):
            inc["explanation"] += " The classifier is uncertain: needs human review (never auto-contained)."

    def _attach(self, inc: dict[str, Any], ev: dict[str, Any], cls: Classification, needs_review: bool, now: float) -> None:
        for eid in [*cls.related_event_ids, ev["event_id"]]:
            if eid not in inc["event_ids"]:
                inc["event_ids"].append(eid)
            if eid in self.events:
                self.events[eid]["incident"] = inc["id"]
        changed = False
        if cls.confidence > inc["ai_confidence"]:
            inc["ai_confidence"] = cls.confidence
            changed = True
        crit = float(ev.get("asset_criticality") or 1.0)
        if crit > inc["asset_criticality"]:
            inc["asset_criticality"] = crit
            changed = True
        if inc["needs_review"] and not needs_review:
            inc["needs_review"] = False
            inc["malicious_probability"] = max(inc["malicious_probability"], cls.malicious)
            inc["_autonomous_denied"] = False
            changed = True
        if changed:
            inc["points"] = round(inc["base_points"] * inc["ai_confidence"] * inc["asset_criticality"], 1)
        self._describe(inc, self._agent(inc["analyzed_by"]))

    # ------------------------------------------------------------- risk engine
    def _refresh_incident(self, inc: dict[str, Any], now: float) -> None:
        end = inc["_acked_ts"] if inc["_acked_ts"] is not None else now
        hours = self.clock.demo_hours(inc["_opened_ts"], end)
        inc["time_unaddressed_hours"] = round(hours, 2)
        inc["inaction_penalty"] = inaction_penalty(hours, self.settings.penalty_per_hour, self.settings.penalty_cap)
        if hours > self.settings.sla_hours:
            inc["sla_breached"] = True
        inc["contribution"] = round(inc["points"] + inc["inaction_penalty"], 1) if inc["status"] in RISK_STATUSES else 0.0

    def _compute(self, now: float) -> dict[str, Any]:
        for inc in self.incidents.values():
            self._refresh_incident(inc, now)
        raw = round(sum(i["contribution"] for i in self.incidents.values()), 1)
        idx = risk_index(raw)
        self._last_risk = {"risk_index": idx, "band": band(idx), "raw_score": raw}
        return self._last_risk

    def _record_history(self, now: float) -> None:
        r = self._last_risk
        self.history.append({"t": self.clock.iso(now), "risk_index": r["risk_index"], "raw": r["raw_score"], "band": r["band"]})

    def tick(self) -> None:
        """Background step (every TICK_S real seconds)."""
        with self.lock:
            now = self.clock.now()
            for flagged in self.watchdog.check(now):
                self.scribe.record(self.watchdog.name, "collector_silent", flagged)
                self._notify(now, "watchdog", None, [self.settings.on_duty],
                             f"Collector silent: {flagged['collector']}",
                             f"Watchdog: collector {flagged['collector']} sent nothing for {flagged['silent_for_s']} s. "
                             f"Monitoring on that host may be blind.", [])
            self._evaluate(now)
            self._record_history(now)

    def _evaluate(self, now: float) -> None:
        self._expire_actions(now)
        r = self._compute(now)
        self._sla_reminders(now, r)
        self._notify_open_incidents(now, r)
        self._band_changes(now, r)
        if r["risk_index"] >= self.settings.threshold:
            if not self._above_threshold:
                self._above_threshold = True
                # Keep the peak on the chart even when containment drops the index in the same step.
                self._record_history(now)
                self.scribe.record(self.name, "threshold_crossed", {
                    "risk_index": r["risk_index"], "threshold": self.settings.threshold, "raw_score": r["raw_score"],
                    "open_incidents": [i["id"] for i in self.incidents.values() if i["status"] in RISK_STATUSES]})
                for inc in self.incidents.values():
                    if inc["status"] in RISK_STATUSES:
                        self._timeline(inc, now, "threshold_crossed",
                                       f"Risk index {r['risk_index']} crossed threshold {self.settings.threshold}")
            candidates = [
                i for i in self.incidents.values()
                if i["status"] == "open" and not i["acked"] and not i["needs_review"]
                and not i["_autonomous_denied"] and not self._active_actions(i, now)
            ]
            if self.monitor_only:
                for inc in candidates:
                    if inc.get("_monitor_skipped"):
                        continue
                    inc["_monitor_skipped"] = True
                    self.scribe.record(self.name, "containment_skipped", {
                        "incident": inc["id"], "risk_index": r["risk_index"], "threshold": self.settings.threshold,
                        "reason": "monitor-only mode", "would_apply": inc["recommended_action"]})
                    self._timeline(inc, now, "monitor_only", f"Monitor-only: would have contained "
                                                             f"({inc['recommended_action']}), nothing applied")
                candidates = []
            for inc in candidates:
                self._contain(inc, "autonomous", self.needle.name, now, r["risk_index"])
            if candidates:
                r = self._compute(now)
                self._band_changes(now, r)
        if r["risk_index"] < self.settings.threshold:
            self._above_threshold = False

    # -------------------------------------------------------------- protection
    def _load_protection(self) -> None:
        """Start in the mode the operator last chose (kept across restarts and demo resets)."""
        saved: dict[str, Any] = {}
        try:
            saved = json.loads(self._protection_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        env = self.settings.monitor_only
        if env is not None and env.strip() != "":
            self.monitor_only = env.strip().lower() in ("1", "true", "yes", "on")
            saved = {"changed_by": "CACTAI_MONITOR_ONLY", "reason": "set in the environment"}
        else:
            self.monitor_only = bool(saved.get("monitor_only", False))
        self._protection_meta = {k: saved.get(k) for k in ("changed_at", "changed_by", "reason")}

    def protection(self) -> dict[str, Any]:
        with self.lock:
            now = self.clock.now()
            return {
                "protection": "off" if self.monitor_only else "on",
                "monitor_only": self.monitor_only,
                **self._protection_meta,
                "active_actions": sorted(a["action_id"] for a in self.actions if self._is_active(a, now)),
            }

    def set_protection(self, on: bool, operator: str, reason: str | None) -> dict[str, Any]:
        """The operator switch. Off = monitor-only: collect, classify and score, but apply no containment."""
        reason = (reason or "").strip()
        with self.lock:
            if not on and not reason:
                raise BadRequestError("turning protection off requires a reason")
            if self.monitor_only == (not on):
                return self.protection()
            now = self.clock.now()
            s = self.settings
            self.monitor_only = not on
            self._protection_meta = {"changed_at": self.clock.iso(now), "changed_by": operator, "reason": reason or None}
            try:
                self._protection_file.parent.mkdir(parents=True, exist_ok=True)
                self._protection_file.write_text(json.dumps({"monitor_only": self.monitor_only, **self._protection_meta},
                                                            indent=2) + "\n", encoding="utf-8")
            except OSError:
                pass  # still switched for this run; the audit record below is the proof
            still = [a["action_id"] for a in self.actions if self._is_active(a, now)]
            self.scribe.record(self.name, "protection_changed", {
                "protection": "on" if on else "off", "monitor_only": self.monitor_only, "operator": operator,
                "reason": reason or None, "active_actions_left_in_force": still})
            open_ids = [i["id"] for i in self.incidents.values() if i["status"] in RISK_STATUSES]
            for inc in self.incidents.values():
                if inc["status"] in RISK_STATUSES:
                    inc["_monitor_skipped"] = False
                    self._timeline(inc, now, "protection", f"Protection turned {'on' if on else 'off'} by {operator}"
                                                           + (f": {reason}" if reason else ""))
            if on:
                self._notify(now, "protection_on", None, [s.on_duty, s.it_manager], "Protection is back on",
                             f"{operator} turned CactAI protection back on. Incidents over the threshold "
                             f"({len(open_ids)} open) can be contained again.", [])
            else:
                self._notify(now, "protection_off", None, [s.on_duty, s.it_manager, s.cxo],
                             "Protection is off: monitor-only mode",
                             f"{operator} turned CactAI protection off: {reason}\nCactAI keeps collecting, classifying "
                             f"and scoring, but applies no containment, autonomous or approved, until it is turned "
                             f"back on. {len(still)} action(s) already in force stay until they expire or are rolled back.",
                             [])
            self._evaluate(now)
        return self.protection()

    def _refuse_if_monitor_only(self, what: str) -> None:
        if self.monitor_only:
            raise ConflictError(f"Protection is off (monitor-only mode), so {what} is not applied. "
                                f"Turn protection back on first.")

    # ----------------------------------------------------------- notifications
    def _notify(self, now: float, kind: str, incident_id: str | None, recipients: list[str], title: str,
                text: str, buttons: list[dict[str, str]]) -> dict[str, Any]:
        nid = f"ntf-{self._next_notif:04d}"
        self._next_notif += 1
        r = self._last_risk
        n = {
            "id": nid,
            "incident": incident_id,
            "kind": kind,
            "title": title,
            "text": text,
            "recipients": recipients,
            "risk_index": r["risk_index"],
            "band": r["band"],
            "buttons": buttons,
            "report_url": f"{self.settings.public_url}/reports/{incident_id}.md" if incident_id else None,
            "created_at": self.clock.iso(now),
            "delivered": False,
            "delivered_at": None,
            "channel": None,
            "message_id": None,
            "deliveries": [],
        }
        self.notifications.append(n)
        self.scribe.record(self.name, "notification_queued", {
            "notification": nid, "incident": incident_id, "kind": kind, "recipients": recipients, "title": title})
        if incident_id and incident_id in self.incidents:
            inc = self.incidents[incident_id]
            inc["notifications"].append(nid)
            self._timeline(inc, now, "notified", f"{kind.replace('_', ' ')} queued for {', '.join(recipients)} ({nid})")
        return n

    def _headline(self, inc: dict[str, Any], r: dict[str, Any]) -> str:
        where = f"{inc['host']}"
        who = f", account '{inc['user']}'" if inc.get("user") else ""
        return (f"⚠️ {inc['id']} · {TITLES.get(inc['category'], inc['category'])} ({where}{who}) "
                f"· Risk {r['risk_index']}/100")

    def _notify_open_incidents(self, now: float, r: dict[str, Any]) -> None:
        for inc in self.incidents.values():
            if inc["_notified_open"] or inc["status"] != "open":
                continue
            if inc["needs_review"] or band_rank(r["band"]) >= band_rank("amber"):
                inc["_notified_open"] = True
                kind = "needs_review" if inc["needs_review"] else "incident_opened"
                extra = "\nClassifier uncertain: needs review, no automatic action will be taken." if inc["needs_review"] else ""
                self._notify(now, kind, inc["id"], [self.settings.on_duty], self._headline(inc, r),
                             f"{self._headline(inc, r)}\n{inc['explanation']}\nRecommended: {inc['recommended_action']}.{extra}",
                             BUTTONS_DECIDE)

    def _band_changes(self, now: float, r: dict[str, Any]) -> None:
        new, old = r["band"], self._last_band
        if new == old:
            return
        self.scribe.record(self.name, "band_changed", {"from": old, "to": new, "risk_index": r["risk_index"]})
        if band_rank(new) > band_rank(old):
            open_ids = [i["id"] for i in self.incidents.values() if i["status"] in RISK_STATUSES]
            s = self.settings
            if band_rank(old) < band_rank("red") <= band_rank(new):
                self._notify(now, "escalation", None, [s.on_duty, s.team_lead],
                             f"Risk RED ({r['risk_index']}/100): team lead copied",
                             f"Risk index is {r['risk_index']}/100 (red). Open incidents: {', '.join(open_ids) or 'none'}. "
                             f"Operator on duty: {s.on_duty}. Team lead copied per escalation policy.", [])
            if new == "critical":
                self._notify(now, "escalation", None, [s.it_manager, s.cxo],
                             f"Risk CRITICAL ({r['risk_index']}/100): IT manager + CXO",
                             f"Risk index is {r['risk_index']}/100 (critical, threshold {s.threshold}). "
                             f"Open incidents: {', '.join(open_ids) or 'none'}. Autonomous temporary containment "
                             f"is engaged for unacknowledged incidents; negligence reports are available.", [])
        self._last_band = new

    def _sla_reminders(self, now: float, r: dict[str, Any]) -> None:
        s = self.settings
        for inc in self.incidents.values():
            if inc["acked"] or inc["status"] in CLOSED_STATUSES:
                continue
            hours = self.clock.demo_hours(inc["_opened_ts"], now)
            if hours < s.sla_hours:
                continue
            if not inc["_sla_flag"]:
                inc["_sla_flag"] = True
                inc["sla_breached"] = True
                self.scribe.record(self.name, "sla_breached", {"incident": inc["id"], "sla_hours": s.sla_hours,
                                                               "responsible": s.on_duty})
                self._timeline(inc, now, "sla_breached", f"SLA of {s.sla_hours:g} h passed without acknowledgement")
            due = min(s.max_reminders, int(math.floor(hours - s.sla_hours)) + 1)
            while inc["_reminders"] < due:
                inc["_reminders"] += 1
                n = inc["_reminders"]
                overdue = fmt_demo_hours(max(0.0, hours - s.sla_hours))
                self._notify(now, "sla_reminder", inc["id"], [s.on_duty, s.team_lead],
                             f"Reminder {n}: {inc['id']} unacknowledged",
                             f"Reminder {n}: {self._headline(inc, r)} is still unacknowledged, "
                             f"overdue by {overdue} (Policy SLA: {s.sla_hours:g} hrs). "
                             f"Inaction penalty so far: +{inc['inaction_penalty']:g}.\nRecommended: {inc['recommended_action']}.",
                             BUTTONS_DECIDE)

    def pending_notifications(self) -> list[dict[str, Any]]:
        with self.lock:
            return public([n for n in self.notifications if not n["delivered"]])

    def mark_delivered(self, nid: str, channel: str, message_id: str | None) -> dict[str, Any]:
        with self.lock:
            n = next((x for x in self.notifications if x["id"] == nid), None)
            if n is None:
                raise KeyError(nid)
            now = self.clock.now()
            ts = self.clock.iso(now)
            n["deliveries"].append({"channel": channel, "message_id": message_id, "delivered_at": ts})
            if not n["delivered"]:
                n.update(delivered=True, delivered_at=ts, channel=channel, message_id=message_id)
            self.scribe.record(self.scribe.name, "notification_delivered", {
                "notification": nid, "incident": n["incident"], "channel": channel, "message_id": message_id,
                "recipients": n["recipients"], "kind": n["kind"]})
            if n["incident"] in self.incidents:
                self._timeline(self.incidents[n["incident"]], now, "delivered",
                               f"{nid} delivered via {channel} (message_id {message_id})")
            return public(n)

    # --------------------------------------------------------- hotpatch / TTL
    def _is_active(self, a: dict[str, Any], now: float) -> bool:
        return a["status"] == "permanent" or (a["status"] == "active" and a["_expires_ts"] > now)

    def _active_actions(self, inc: dict[str, Any], now: float) -> list[dict[str, Any]]:
        return [a for a in inc["actions"] if self._is_active(a, now)]

    def blocklist(self) -> dict[str, list[str]]:
        with self.lock:
            return self.blocklist_responder.blocklist()

    def _end_action(self, a: dict[str, Any], status: str) -> None:
        """Every way an action stops (expired, rolled back) goes through here, so the responder undoes it."""
        if a["status"] in ("active", "permanent"):  # still in force: undo it
            self.responders.revert(a)
        a["status"] = status

    def _state_for_snapshot(self, now: float) -> dict[str, Any]:
        bl = self.blocklist()
        return {**bl, "active_actions": sorted(a["action_id"] for a in self.actions if self._is_active(a, now))}

    def _contain(self, inc: dict[str, Any], mode: str, approver: str, now: float, risk_idx: int,
                 justification: str | None = None) -> bool:
        s = self.settings
        analyst = self._agent(inc["analyzed_by"])
        proposals = self._proposals(inc, analyst)
        executor = self.areole_win if "win" in str(inc.get("host") or "").lower() else self.areole_linux
        # 1. Snapshot
        pre = self._state_for_snapshot(now)
        snap = Scribe.snapshot_hash(pre)
        self.scribe.record(executor.name, "snapshot", {"incident": inc["id"], "snapshot_hash": snap, "state": pre})
        # 2. Review (two-key rule)
        if mode == "autonomous":
            review = self.needle.review(inc, proposals, risk_idx, s.threshold)
            self.scribe.record(self.needle.name, "needle_review", {
                "incident": inc["id"], "approved": review.approved, "reasoning": review.reasoning,
                "proposals": [p.__dict__ for p in proposals], "denied": review.denied})
            if not review.approved:
                inc["_autonomous_denied"] = True
                self._timeline(inc, now, "needle_denied", review.reasoning)
                self._notify(now, "needs_operator", inc["id"], [s.on_duty, s.team_lead],
                             f"{inc['id']}: autonomous action denied by Needle",
                             f"{self._headline(inc, self._last_risk)}\nNeedle denied autonomous action: {review.reasoning}\n"
                             f"A human must decide. Recommended: {inc['recommended_action']}.", BUTTONS_DECIDE)
                return False
            approved = review.approved_proposals
        else:
            approved, _ = self.needle.screen(proposals)
            self.scribe.record(self.needle.name, "needle_review", {
                "incident": inc["id"], "approved": True, "operator": approver,
                "reasoning": f"Operator {approver} approved; the human decision is the second key. "
                             f"Needle checked the allowlist only ({len(approved)} action(s)).",
                "justification": justification})
        if not approved:
            self._timeline(inc, now, "no_playbook", "No allowlisted playbook applies")
            return False
        # 3. Apply with TTL
        new_actions = []
        for p in approved:
            aid = f"act-{self._next_action:04d}"
            self._next_action += 1
            a = executor.apply(p, inc["id"], aid, mode, approver, now, self.clock, s.ttl_hours, snap)
            self.actions.append(a)
            inc["actions"].append(a)
            new_actions.append(a)
            self.scribe.record(executor.name, "action_applied", a)
        # 4. Verify (each responder reported whether its action is in force)
        results = [{"action_id": a["action_id"], "type": a["type"], "target": a["target"], "verified": a["verified"]}
                   for a in new_actions]
        self.scribe.record(executor.name, "verify", {"incident": inc["id"], "results": results})
        for a in new_actions:
            if not a["verified"]:
                self._end_action(a, "rolled_back")
                self.scribe.record(executor.name, "auto_rollback", {"incident": inc["id"], "action_id": a["action_id"],
                                                                    "snapshot_hash": snap, "why": "verification failed"})
        inc["status"] = "contained"
        inc["contained_at"] = self.clock.iso(now)
        summary = "; ".join(f"{a['type']} {a['target']}" for a in new_actions)
        self._timeline(inc, now, "action", f"{'Autonomous override' if mode == 'autonomous' else 'Operator-approved hotpatch'}"
                                           f" ({approver}): {summary}; TTL {s.ttl_hours:g} h; snapshot {snap[:12]}", -inc["points"])
        # 5. Notify
        if mode == "autonomous":
            self._notify(now, "autonomous_action", inc["id"], [s.on_duty, s.it_manager, s.cxo],
                         f"{inc['id']}: autonomous containment engaged",
                         f"\U0001f335 CactAI autonomous override on {inc['id']} (risk {risk_idx}/100 >= {s.threshold}, "
                         f"no acknowledgement). Approved by Needle. Applied for {s.ttl_hours:g} h: {summary}.\n"
                         f"Negligence report: {s.public_url}/reports/{inc['id']}.md", BUTTONS_AFTER_ACTION)
        else:
            self._notify(now, "operator_action", inc["id"], [s.on_duty],
                         f"{inc['id']}: hotpatch applied by {approver}",
                         f"{approver} approved the hotpatch for {inc['id']}. Applied for {s.ttl_hours:g} h: {summary}.",
                         BUTTONS_AFTER_ACTION)
        return True

    def _expire_actions(self, now: float) -> None:
        for a in self.actions:
            if a["status"] == "active" and a["_expires_ts"] <= now:
                self._end_action(a, "expired")
                self.scribe.record(a["executed_by"], "action_expired", {"incident": a["incident"], "action_id": a["action_id"],
                                                                       "type": a["type"], "target": a["target"]})
                inc = self.incidents.get(a["incident"])
                if inc:
                    self._timeline(inc, now, "expired", f"TTL expired: {a['type']} {a['target']} ({a['action_id']})")
                    if not any(x["status"] == "active" for x in inc["actions"]):
                        self._notify(now, "action_expired", inc["id"], [self.settings.on_duty],
                                     f"{inc['id']}: temporary hotpatch expired",
                                     f"The temporary hotpatch for {inc['id']} expired after {a['ttl_hours']:g} h. "
                                     f"Make it permanent or leave it expired.", BUTTONS_AFTER_ACTION)

    # --------------------------------------------------------- operator verbs
    def _get(self, iid: str) -> dict[str, Any]:
        inc = self.incidents.get(iid)
        if inc is None:
            raise KeyError(iid)
        return inc

    def _set_acked(self, inc: dict[str, Any], operator: str, channel: str, now: float) -> None:
        if inc["acked"]:
            return
        self._refresh_incident(inc, now)  # freeze penalty at ack time
        inc.update(acked=True, acked_by=operator, acked_at=self.clock.iso(now), ack_channel=channel, _acked_ts=now)
        if inc["status"] == "open":
            inc["status"] = "acknowledged"
        self.scribe.record(self.name, "acknowledged", {"incident": inc["id"], "operator": operator, "channel": channel,
                                                       "inaction_penalty_frozen": inc["inaction_penalty"]})
        self._timeline(inc, now, "ack", f"Acknowledged by {operator} via {channel}")

    def ack(self, iid: str, operator: str, channel: str) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            self._set_acked(inc, operator, channel, now)
            self._evaluate(now)
            return self.incident_public(inc)

    def decision(self, iid: str, operator: str, decision: str, justification: str | None) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            if inc["status"] in CLOSED_STATUSES:
                raise ConflictError(f"{iid} is already {inc['status']}")
            if decision == "reject":
                if not (justification or "").strip():
                    raise BadRequestError("reject requires a justification")
                self._set_acked(inc, operator, "decision", now)
                for a in self._active_actions(inc, now):
                    self._end_action(a, "rolled_back")
                    self.scribe.record(self.name, "action_rolled_back", {"incident": iid, "action_id": a["action_id"],
                                                                         "operator": operator, "reason": "incident rejected"})
                inc["status"] = "rejected"
                inc["closed_at"] = self.clock.iso(now)
                inc["decisions"].append({"operator": operator, "decision": "reject", "justification": justification,
                                         "at": inc["closed_at"]})
                self.scribe.record(self.name, "decision", {"incident": iid, "operator": operator, "decision": "reject",
                                                           "justification": justification})
                self._timeline(inc, now, "decision", f"Rejected by {operator}: {justification}", -inc["points"])
            elif decision == "approve":
                if not self._active_actions(inc, now):
                    self._refuse_if_monitor_only("an approved hotpatch")
                self._set_acked(inc, operator, "decision", now)
                inc["decisions"].append({"operator": operator, "decision": "approve", "justification": justification,
                                         "at": self.clock.iso(now)})
                self.scribe.record(self.name, "decision", {"incident": iid, "operator": operator, "decision": "approve",
                                                           "justification": justification})
                self._timeline(inc, now, "decision", f"Approve & Patch pressed by {operator}")
                if self._active_actions(inc, now):
                    self._timeline(inc, now, "decision", "Containment already active; operator endorsed it")
                else:
                    self._contain(inc, "operator", operator, now, self._last_risk["risk_index"], justification)
            else:
                raise BadRequestError("decision must be 'approve' or 'reject'")
            self._evaluate(now)
            return self.incident_public(inc)

    def rollback(self, iid: str, operator: str, justification: str | None) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            active = [a for a in self._active_actions(inc, now)]
            if not active:
                raise ConflictError(f"{iid} has no active containment to roll back")
            self._set_acked(inc, operator, "rollback", now)
            snap = Scribe.snapshot_hash(self._state_for_snapshot(now))
            for a in active:
                self._end_action(a, "rolled_back")
                a["rolled_back_at"] = self.clock.iso(now)
                self.scribe.record(self.name, "action_rolled_back", {
                    "incident": iid, "action_id": a["action_id"], "operator": operator, "justification": justification,
                    "restored_snapshot_hash": a["snapshot_hash"], "state_before_rollback_hash": snap})
            if inc["status"] == "contained":
                inc["status"] = "acknowledged"
            inc["decisions"].append({"operator": operator, "decision": "rollback", "justification": justification,
                                     "at": self.clock.iso(now)})
            self._timeline(inc, now, "rollback", f"Rolled back by {operator}: {justification or 'no justification given'}")
            self._evaluate(now)
            return self.incident_public(inc)

    def make_permanent(self, iid: str, operator: str, justification: str | None) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            targets = [a for a in inc["actions"] if a["status"] in ("active", "expired")]
            if not targets:
                raise ConflictError(f"{iid} has no active or expired hotpatch to make permanent")
            if any(a["status"] == "expired" for a in targets):
                self._refuse_if_monitor_only("putting an expired hotpatch back in force")
            self._set_acked(inc, operator, "permanent", now)
            for a in targets:
                if a["status"] == "expired":
                    self.responders.apply(a)  # an expired block goes back in force
                a["status"] = "permanent"
                a["expires_at"] = None
                a["_expires_ts"] = math.inf
                self.scribe.record(self.name, "action_made_permanent", {"incident": iid, "action_id": a["action_id"],
                                                                         "operator": operator, "justification": justification})
            inc["status"] = "resolved"
            inc["closed_at"] = self.clock.iso(now)
            inc["decisions"].append({"operator": operator, "decision": "permanent", "justification": justification,
                                     "at": inc["closed_at"]})
            self._timeline(inc, now, "permanent", f"Made permanent by {operator}: {justification or 'no justification given'}")
            self._evaluate(now)
            return self.incident_public(inc)

    # ---------------------------------------------------------------- queries
    def _timeline(self, inc: dict[str, Any], now: float, kind: str, text: str, points: float | None = None) -> None:
        inc["timeline"].append({
            "ts": self.clock.iso(now),
            "demo_hours": round(self.clock.demo_hours(inc["_opened_ts"], now), 2),
            "kind": kind,
            "text": text,
            "points": points,
            "_ts": now,
        })

    def incident_public(self, inc: dict[str, Any]) -> dict[str, Any]:
        return public(inc)

    def list_incidents(self) -> list[dict[str, Any]]:
        with self.lock:
            now = self.clock.now()
            self._compute(now)
            return [public(i) for i in self.incidents.values()]

    def get_incident(self, iid: str) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            self._refresh_incident(inc, self.clock.now())
            return public(inc)

    def risk(self, history: int = 600) -> dict[str, Any]:
        with self.lock:
            now = self.clock.now()
            r = self._compute(now)
            hist = list(self.history)[-history:] if history > 0 else []
            return {
                "risk_index": r["risk_index"],
                "band": r["band"],
                "raw_score": r["raw_score"],
                "threshold": self.settings.threshold,
                "open_incidents": [i["id"] for i in self.incidents.values() if i["status"] in RISK_STATUSES],
                "needs_review": [i["id"] for i in self.incidents.values() if i["needs_review"] and i["status"] in RISK_STATUSES],
                "contained_incidents": [i["id"] for i in self.incidents.values() if i["status"] == "contained"],
                "monitor_only": self.monitor_only,
                "demo_speed": self.settings.demo_speed,
                "demo_hours_elapsed": round(self.clock.demo_hours(self._started_ts, now), 2),
                "timestamp": self.clock.iso(now),
                "history": hist,
            }

    def why(self, iid: str) -> str:
        with self.lock:
            inc = self._get(iid)
            self._refresh_incident(inc, self.clock.now())
            return self.helpdesk.why(public(inc), self._last_risk["risk_index"], self.settings.threshold)

    def why_target(self, target: str) -> dict[str, Any]:
        with self.lock:
            ids = []
            for a in self.actions:
                if a["target"] == target and a["incident"] not in ids:
                    ids.append(a["incident"])
            if not ids:
                return {"target": target, "answer": f"{target} is not in any CactAI containment record."}
            return {"target": target, "incidents": ids, "answer": "\n\n".join(self.why(i) for i in ids)}

    def agents_status(self) -> list[dict[str, Any]]:
        out = []
        for a in self.all_agents():
            st = a.status()
            if isinstance(a, LayerAgent):
                st["analyzed"] = a.analyzed
            out.append(st)
        out.append({"name": "Jev", "role": "TypeSafe System One classifier", "status": self.jev.status,
                    "calls": self.jev.calls, "failures": self.jev.failures, "last_error": self.jev.last_error})
        return out

    # ------------------------------------------------------------------- demo
    def advance(self, demo_hours: float) -> dict[str, Any]:
        with self.lock:
            self.clock.advance_demo_hours(demo_hours)
            self.scribe.record(self.name, "demo_clock_advanced", {"demo_hours": demo_hours})
        self.tick()
        return self.risk(history=0)

    def reset(self) -> dict[str, Any]:
        with self.lock:
            archived = self.audit.archive_and_reset()
            self.rules.reset()
            self.responders.reset()
            self.watchdog.reset()
            self.clock._offset = 0.0
            self._init_state()
            self.scribe.record(self.name, "demo_reset", {"archived_chain": str(archived) if archived else None,
                                                         **self._config_summary()})
            return {"ok": True, "archived_chain": str(archived) if archived else None}
