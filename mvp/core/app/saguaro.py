"""Warden (class Saguaro): lead orchestrator. Owns incidents, the risk index, notifications and the hotpatch workflow.

Incidents, actions (blocks) and notifications are saved to SQLite next to the audit chain after
every change and restored on startup (state.py), so a restart keeps them. reset() clears both.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

import sentrai_paths

from .admins import CATEGORY as ADMIN_CATEGORY, Admins, short_key
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
    next_steps,
)
from . import firewall
from . import anchor, remote_copy, routing
from . import summary as client_summary
from .audit import AuditLog
from .classifier import Classification, default_chain
from .clock import DemoClock, fmt_demo_hours
from .config import Settings, sign
from .extensions import Extension, Host
from .integrity import IntegrityGuard
from .netlogs import enrich
from .responders import Responder, Responders, SimulatedResponder, WebhookResponder
from .risk import SEVERITY, band, band_rank, inaction_penalty, risk_index
from .rules import TRIPWIRE_REASONS, RulesEngine
from .state import StateStore

log = logging.getLogger("sentrai.saguaro")

RISK_STATUSES = ("open", "acknowledged")  # count toward raw score
MERGE_STATUSES = ("open", "acknowledged", "contained")  # new events attach to these
CLOSED_STATUSES = ("resolved", "rejected")
ROLES = ("on_duty", "team_lead", "it_manager", "cxo")  # the four people in the settings (routing.defaults)

TITLES = {
    "brute_force": "Brute force",
    "sql_injection": "SQL injection",
    "xss": "Cross-site scripting",
    "port_scan": "Port or web scan",
    "privilege_escalation": "Shell spawned / privilege escalation",
    "data_exfiltration": "Bulk data export",
    "misconfiguration": "Misconfiguration",
    "log_tampering": "Log tampering",
    "malware": "Malware found",
    "prompt_injection": "Prompt injection",
    "staff_report": "Staff report",
    "unauthorised_admin": "Root access from an unrecognised sign-in",
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
# Root work from a sign-in SentrAI does not recognise: the person says whether it was them. "This was me"
# teaches the sign-in (admins.py) and closes the incident; "Not me" is Approve & Patch (block the address).
BUTTONS_WAS_THIS_YOU = [
    {"label": "This was me", "action": "mine"},
    {"label": "Not me: block it", "action": "approve"},
    {"label": "Acknowledge", "action": "ack"},
]


def _http_probe(url: str, timeout_s: float = 3.0) -> dict[str, Any]:
    """GET the health URL: ok when it answers below 500."""
    import httpx

    started = time.monotonic()
    try:
        status = httpx.get(url, timeout=timeout_s, follow_redirects=True).status_code
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
    return {"ok": status < 500, "status": status, "ms": round((time.monotonic() - started) * 1000)}


def _succeeded(ev: dict[str, Any]) -> bool | None:
    """Did this request or login get through? None when the line does not say."""
    p = ev.get("parsed") or {}
    status = p.get("status")
    if isinstance(status, int):
        return status < 400
    if p.get("ssh_event") == "accepted" or p.get("outcome") == "success":
        return True
    if p.get("outcome") == "failure" or p.get("ssh_event") in ("failed_auth", "invalid_user", "max_auth_exceeded"):
        return False
    return None


def _between(events: Any, start: float, end: float) -> list[dict[str, Any]]:
    return [e for e in events if start < e.get("_rx", 0.0) <= end and e.get("source") != "heartbeat"]


def _matches(a: dict[str, Any], ev: dict[str, Any]) -> bool:
    if a["type"] == "block_ip":
        return str(ev.get("src_ip") or "") == str(a["target"])
    if a["type"] == "lock_user":
        return str(ev.get("user") or "").lower() == str(a["target"]).lower()
    return False


def _did_it_work(a: dict[str, Any], events: Any, start: float, end: float) -> dict[str, Any]:
    """Blocks and locks: after the action, did the target still get anything through?"""
    if a["type"] not in ("block_ip", "lock_user"):
        return {"worked": None, "worked_note": f"SentrAI cannot see a {a['type'].replace('_', ' ')} take effect "
                                               f"itself; check it in the system that carries it out."}
    after = [e for e in _between(events, start, end) if _matches(a, e)]
    got_in = [e for e in after if _succeeded(e)]
    who = "requests from" if a["type"] == "block_ip" else "logins by"
    if got_in:
        return {"worked": False, "seen_after": len(after), "got_through": len(got_in),
                "worked_note": f"{len(got_in)} of {len(after)} {who} {a['target']} still got through after it started."}
    if after:
        return {"worked": True, "seen_after": len(after), "got_through": 0,
                "worked_note": f"{len(after)} later attempt(s) from {a['target']}, none got through."}
    return {"worked": True, "seen_after": 0, "got_through": 0,
            "worked_note": f"Nothing from {a['target']} has reached the logs since it started."}


def _disruption(a: dict[str, Any], events: Any, start: float, end: float, health: dict[str, Any] | None) -> dict[str, Any]:
    """Compare everyone else's traffic in the same length of time before and after the action, and
    probe the health page: fewer successful requests or more server errors may mean collateral damage."""
    span = max(end - start, 1.0)
    others_before = [e for e in _between(events, start - span, start) if not _matches(a, e)]
    others_after = [e for e in _between(events, start, end) if not _matches(a, e)]
    ok_before = sum(1 for e in others_before if _succeeded(e))
    ok_after = sum(1 for e in others_after if _succeeded(e))

    def errors(evs: list[dict[str, Any]]) -> tuple[int, int]:
        statuses = [(e.get("parsed") or {}).get("status") for e in evs]
        statuses = [x for x in statuses if isinstance(x, int)]
        return sum(1 for x in statuses if x >= 500), len(statuses)

    (err_b, web_b), (err_a, web_a) = errors(others_before), errors(others_after)
    problems: list[str] = []
    if ok_before >= 20 and ok_after < ok_before * 0.3:
        problems.append(f"successful requests from everyone else fell from {ok_before} to {ok_after}")
    if web_a >= 5 and err_a / web_a - (err_b / web_b if web_b else 0.0) >= 0.2:
        problems.append(f"server errors rose to {err_a} of {web_a} requests (from {err_b} of {web_b})")
    before = a.get("health_before")
    if health is not None and not health.get("ok"):
        if before is None or before.get("ok"):
            problems.append(f"the health page stopped answering ({health.get('status') or health.get('error')})")
    out: dict[str, Any] = {"others_ok_before": ok_before, "others_ok_after": ok_after,
                           "server_errors_before": err_b, "server_errors_after": err_a}
    if health is not None:
        out["health_after"] = health
    if problems:
        return {**out, "disruption": True, "disruption_note": "Possible disruption: " + "; ".join(problems) + "."}
    if not others_before and not others_after and health is None:
        return {**out, "disruption": None, "disruption_note": "No other traffic to compare and no health page set."}
    note = "Other users' traffic and server errors look the same as before."
    if health is not None:
        note += " Health page " + ("answers." if health.get("ok") else "was already failing before the action.")
    return {**out, "disruption": False, "disruption_note": note}


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


# Agent names used before the SentrAI sentry theme, still found in saved incidents and audit records.
LEGACY_AGENT_NAMES = {"Saguaro": "Warden", "Root": "Gatehouse", "Reservoir": "Vault", "SpineNet": "Watchtower",
                      "AreoleLinux": "Garrison-Linux", "AreoleWin": "Garrison-Win", "Needle": "Countersign"}


AUDIT_RAW_CHARS = 200


def _signal(ev: dict[str, Any], cls: Classification) -> str:
    """One independent piece of evidence: which classifier said so, about which log source."""
    return f"{cls.classified_by or '?'}:{ev.get('source') or ev.get('layer') or '?'}"


def raw_summary(raw: Any) -> dict[str, Any]:
    """What the audit chain keeps of a log line: a short printable excerpt, its length and its SHA-256.
    The chain only needs enough to prove which line it was, and must not keep a permanent copy of the
    passwords, tokens or personal data that people and attackers put in requests."""
    text = "" if raw is None else str(raw)
    excerpt = "".join(ch if ch.isprintable() else " " for ch in text[:AUDIT_RAW_CHARS])
    return {"raw": excerpt + ("..." if len(text) > AUDIT_RAW_CHARS else ""), "raw_len": len(text),
            "raw_sha256": hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()}


def _host(obj: dict[str, Any]) -> str:
    """The machine an event or incident belongs to."""
    return str(obj.get("host") or "unknown")


def service_of(ev: dict[str, Any]) -> str | None:
    """Which service on the machine an event is about (nginx, sshd, ...), for the panel's per-service view."""
    if ev.get("service"):
        return str(ev["service"])
    parsed = ev.get("parsed") if isinstance(ev.get("parsed"), dict) else {}
    fmt, program = str(parsed.get("format") or ""), str(parsed.get("program") or "")
    if fmt.startswith("nginx"):
        return "nginx"
    if program:
        return "sshd" if program.startswith("sshd") else program
    return str(ev.get("source") or "") or None


def _score(raw: float) -> dict[str, Any]:
    raw = round(raw, 1)
    idx = risk_index(raw)
    return {"risk_index": idx, "band": band(idx), "raw_score": raw}


class Saguaro(Agent):
    name = "Warden"
    role = "lead orchestrator: routes events, merges findings, owns the risk index"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = s = settings or Settings()
        # Who owns, hears about and backs up each incident (routing.py). Names in a routing file
        # replace the four role names everywhere an alert goes to a role.
        self.routing_path = routing.path_from_settings(s)
        self.role_names = {role: getattr(s, role) for role in ROLES}  # the settings' own, before the file renames them
        self.router = routing.load(self.routing_path, *self.role_names.values())
        for role in ROLES:
            setattr(s, role, self.router.by_role(role, self.role_names[role]))
        self.clock = DemoClock(s.demo_speed)
        self.audit = AuditLog(s.db_path)
        # The administrators (admins.py): who is signed in on each machine and whether SentrAI knows them.
        self.admins = Admins(sentrai_paths.path("core.admins", Path(s.db_path).parent), s, self.clock)
        self.rules = RulesEngine(s.brute_force_count, s.brute_force_window_s, s.export_rows_threshold,
                                 ssh_count=s.ssh_brute_force_count, ssh_window_s=s.ssh_brute_force_window_s,
                                 scan_4xx_count=s.web_scan_4xx_count, scan_window_s=s.web_scan_window_s,
                                 slow_count=s.slow_brute_force_count, slow_window_s=s.slow_brute_force_window_s,
                                 ssh_slow_count=s.ssh_slow_brute_force_count)
        # The three parts: events arrive from collectors via POST /events, the classifier
        # chain labels them, and the responders carry out approved containment. Extensions
        # (app/extensions.py) add classifier steps and responders to both while the core runs.
        self.classifier = default_chain(self.rules)
        self._own_steps = list(self.classifier.classifiers)  # the rules first, the keyword fallback last
        self.blocklist_responder = firewall.from_settings(s.firewall, s.firewall_enforce, s.protected_ips)
        self._simulated = SimulatedResponder()
        self.webhook_responder: WebhookResponder | None = None
        if s.responder_webhook_url:
            # Always last, so it takes the listed types; the blocklist (and extensions such as Cloudflare)
            # still apply first: rewire() sets what it wraps.
            self.webhook_responder = WebhookResponder(
                s.responder_webhook_url, s.responder_webhook_actions, s.responder_webhook_secret,
                s.responder_webhook_timeout_s)
        self.responders = Responders(self.blocklist_responder, self._simulated)
        self._ext_responders: dict[str, list[Responder]] = {}  # extension name -> the responders it added
        self.extensions = Host(self)  # the installed extensions; the added ones start just before _restore()
        self.root = Root(self.classifier)
        self.reservoir = Reservoir(self.classifier)
        self.spinenet = SpineNet(self.classifier)
        self.areole_linux = AreoleLinux(self.classifier, self.responders)
        self.areole_win = AreoleWin(self.classifier, self.responders)
        self.needle = Needle(s.needle_min_confidence, self.responders.allowlist, s.protected_ips, s.protected_users,
                             s.protected_nets, s.contain_min_severity, s.contain_min_points,
                             auto_actions=s.auto_actions, max_auto_per_hour=s.max_auto_actions_per_hour,
                             admin_address=self.admins.known_address)
        self.watchdog = Watchdog(s.watchdog_silence_s)
        self.scribe = Scribe(self.audit, self.clock)
        self.integrity = IntegrityGuard(self.audit, s.integrity_check_s, s.clock_jump_s)
        self.remote = remote_copy.from_settings(self.audit, s)  # off-box copy; started by the app (main.py)
        self.anchor_key = anchor.load_key(s.db_path)
        self._anchor_next = time.monotonic() + 60.0 * s.anchor_every_min
        self._anchor_seq = 0
        self.helpdesk = HelpDesk()
        self.lock = threading.RLock()
        self._protection_file = s.db_path.parent / "protection.json"
        self._load_protection()
        self._summary_file = s.db_path.parent / "summary.json"
        self.summary_schedule = client_summary.load_schedule(self._summary_file, s, time.time())
        self.store = StateStore(self.audit)
        self._init_state()
        self._configure()
        self.extensions.start()  # their responders must be in place before the saved blocks are put back
        self.scribe.record(self.name, "core_started", self._config_summary())
        self._restore()

    def _configure(self) -> None:
        """Subclass hook, run before saved state is restored (restoring can trigger containment)."""

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
        self._host_risk: dict[str, dict[str, Any]] = {}  # per machine, from _compute
        self._host_seen: dict[str, float] = {}  # machine name -> clock time of its last event or heartbeat
        self._host_history: dict[str, deque[dict[str, Any]]] = {}
        self._host_services: dict[str, dict[str, Any]] = {}  # machine -> {"services": [...], "at": iso} from its agent
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
            "risk_scope": s.risk_scope,
            "sla_hours": s.sla_hours,
            "ttl_hours": s.ttl_hours,
            "limits": self.limits(),
            "on_duty": s.on_duty,
            "extensions": self.extensions.summary(),
            "block_ip_enforcement": self._enforced_by("block_ip").enforcement,
        }

    # ------------------------------------------------------------ extensions
    def _enforced_by(self, action_type: str) -> Responder:
        """The responder that really puts an action type in force: the last one below the webhook."""
        return next((r for r in reversed(self.responders.all) if action_type in r.actions
                     and r is not self.webhook_responder), self.blocklist_responder)

    def rewire(self) -> None:
        """Puts the running extensions' classifier steps and responders in place (called by the Host)."""
        own = [self.blocklist_responder]  # what really enforces, so what the webhook may wrap

        def below(action_type: str) -> Responder | None:
            return next((r for r in reversed(own) if action_type in r.actions), None)

        steps, chain, by_ext = [], [self.blocklist_responder, self._simulated], {}
        for name, ext in self.extensions.exts():
            try:
                added = list(ext.responders(below) or [])
                steps += list(ext.classifiers() or [])
            except Exception:  # a broken extension is left out, never the core
                log.exception("extension %s could not be plugged in", name)
                continue
            by_ext[name] = added
            chain += added
            own += added
        if self.webhook_responder is not None:
            self.webhook_responder.inner = below
            chain.append(self.webhook_responder)
        self.classifier.classifiers = [self._own_steps[0], *steps, *self._own_steps[1:]]
        self.responders.replace(*chain)
        self._ext_responders = by_ext
        self.needle.allowlist = self.responders.allowlist

    def _in_force_for(self, responders: list[Responder]) -> list[tuple[Responder, dict[str, Any]]]:
        return [(r, a) for a in self.actions if a["status"] in ("active", "permanent") and a.get("verified") is not False
                for r in responders if a["type"] in r.actions]

    def plug_in_extension(self, name: str, ext: Extension) -> None:
        """An extension was added while the core runs: plug it in, and give it the actions already in
        force that it handles (Cloudflare blocks the addresses SentrAI is blocking now)."""
        with self.lock:
            self.rewire()
            for r, a in self._in_force_for(self._ext_responders.get(name, [])):
                try:
                    r.adopt(a)
                except Exception:
                    log.exception("extension %s could not take over %s", name, a.get("action_id"))
            self._save()

    def unplug_extension(self, name: str, ext: Extension) -> dict[str, Any]:
        """An extension is being removed: take its part out of every action in force (the local block
        stays), then close it. What did not come out is reported, since nothing will retry it."""
        with self.lock:
            released, failed = 0, []
            for r, a in self._in_force_for(self._ext_responders.get(name, [])):
                try:
                    ok = r.release(a)
                except Exception as exc:
                    ok, a[f"{r.name}_revert"] = False, {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}
                if ok is False:
                    failed.append({"action_id": a["action_id"], "target": a["target"],
                                   "error": (a.get(f"{r.name}_revert") or {}).get("error", "not confirmed")})
                    inc = self.incidents.get(a["incident"])
                    if inc is not None:
                        self._timeline(inc, self.clock.now(), "undo_failed",
                                       f"{name} was removed but could not take {a['type']} {a['target']} out of "
                                       f"its service: {failed[-1]['error']}. Remove it there by hand.")
                else:
                    released += 1
            try:
                note = ext.close() or {}
            except Exception as exc:
                note = {"close_error": f"{type(exc).__name__}: {exc}"[:200]}
            self._save()
            return {"released": released, "left_in_place": failed, **note}

    def note_on_incidents(self, src_ip: str, key: str, value: Any, text: str) -> None:
        """An extension learned something about an address (AbuseIPDB's reputation): note it on every
        open incident from it that has no such note yet. Context for the person deciding, never a score."""
        with self.lock:
            now = self.clock.now()
            for inc in self.incidents.values():
                if inc.get("src_ip") == src_ip and inc["status"] in MERGE_STATUSES and key not in inc:
                    inc[key] = value
                    self._timeline(inc, now, key, text)
            self._save()

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
        name = LEGACY_AGENT_NAMES.get(name, name)  # incidents saved before the sentry names
        for a in self.layer_agents():
            if a.name == name:
                return a
        return self.root

    # --------------------------------------------------------------- ingestion
    def ingest(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        accepted = 0
        tampering: list[dict[str, Any]] = []  # broken line chains and clock jumps, classified after this batch
        # A classifier step with a time budget (TypeSafe's Jev) starts it now; the rest use the fallback.
        self.classifier.begin()
        for raw_ev in events:
            ev = enrich(dict(raw_ev))
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
                if (broken := self.integrity.chained(raw_ev)) is not None:
                    tampering.append(broken)
                if self.remote is not None:
                    self.remote.add_line(raw_ev)  # off the box as it arrives
                self.events[ev["event_id"]] = {**ev, "category": None, "_rx": now}
                self._host_seen[str(ev["host"])] = now
                recovered = self.watchdog.observe(str(ev["host"]), now, heartbeat)
                if recovered:
                    self.scribe.record(self.watchdog.name, "collector_recovered", recovered)
            accepted += 1
            if heartbeat:
                if (jump := self.integrity.heartbeat(str(ev["host"]), ev.get("timestamp"))) is not None:
                    tampering.append(jump)
                with self.lock:
                    self.events[ev["event_id"]].update(category="benign", classified_by="rules", reason="heartbeat")
                continue
            agent = self._route(ev)
            cls = agent.analyze(ev, now)  # may call an outside classifier (Jev): done outside the lock
            with self.lock:
                verdict = self.admins.observe(ev, cls, now)  # who did it, when the line is a person's work on a host
                for fact in self.admins.take_learned():  # a known key from a new address, and the like
                    self.scribe.record(agent.name, "admin_learned", {**fact, "host": ev.get("host"),
                                                                     "event_id": ev["event_id"]})
                self._apply_classification(ev, cls, agent, now, verdict)
        if tampering:
            self.ingest(tampering)
        with self.lock:
            self._trim_events()
            now = self.clock.now()
            self._evaluate(now)
            self._record_history(now)
            return {"accepted": accepted, "risk_index": self._last_risk["risk_index"]}

    def _trim_events(self, limit: int = 20000) -> None:
        while len(self.events) > limit:
            self.events.pop(next(iter(self.events)))

    def _apply_classification(self, ev: dict[str, Any], cls: Classification, agent: LayerAgent, now: float,
                              verdict: Any = None) -> None:
        rec = self.events[ev["event_id"]]
        if verdict is not None:
            rec["actor"] = ev["actor"] = verdict.actor
            if verdict.src_ip and not ev.get("src_ip"):
                # The sign-in's address: the incident names it, and a block has a target.
                rec["src_ip"] = ev["src_ip"] = verdict.src_ip
            if verdict.activity:
                self.scribe.record(agent.name, "admin_action", {
                    "event_id": ev["event_id"], **raw_summary(ev.get("raw")), "host": ev.get("host"),
                    "user": verdict.actor.get("user"), "via": verdict.actor.get("via"),
                    "address": verdict.actor.get("address"), "key": short_key(verdict.actor.get("key")),
                    "session": verdict.actor.get("session"), "trusted_because": verdict.actor.get("why"),
                    "what": verdict.activity, "would_be": cls.category if verdict.suppress else "benign",
                    "rule": cls.reason if verdict.suppress else None, "learned": verdict.learned})
            if verdict.suppress:
                # A known administrator's own command: the rules alone would have raised it. Recorded, not an incident.
                rec.update(category="benign", confidence=cls.confidence, malicious=0.0, classified_by="rules",
                           reason=f"{verdict.reason}; on its own the line reads as {cls.category}: {cls.reason}",
                           analyzed_by=agent.name, incident=None, admin_action=True, flagged_as=cls.category)
                return
            if verdict.escalate:
                # Root from a sign-in SentrAI does not know is the question; a command the rules flag on its own
                # (wiping logs, a shell) makes it a louder one: full points, the plain command three quarters.
                detail = f" The line itself: {cls.reason}." if cls.category != "benign" else ""
                cls = Classification(ADMIN_CATEGORY, 1.0 if cls.category != "benign" else 0.75, 0.5,
                                     f"{verdict.reason}.{detail}",
                                     related_event_ids=list(cls.related_event_ids), classified_by="rules")
        if cls.category == "brute_force" and ev.get("src_ip"):
            self.admins.mark_suspect(str(ev["src_ip"]), "password guessing", now)  # a later sign-in from it is suspect
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
        per_host = self.settings.risk_scope == "host"  # the same attacker on two machines is two incidents
        inc = next(
            (
                i
                for i in self.incidents.values()
                if i["category"] == cls.category
                and i["status"] in MERGE_STATUSES
                and (i.get("src_ip") or i.get("user") or i.get("host")) == key
                and (not per_host or _host(i) == _host(ev))
            ),
            None,
        )
        if inc is None:
            inc = self._open_incident(ev, cls, agent, needs_review, now)
            inc.setdefault("service", service_of(ev))
        else:
            self._attach(inc, ev, cls, needs_review, now)
        self.scribe.record(
            agent.name,
            "event_classified",
            {
                "event_id": ev["event_id"],
                **raw_summary(ev.get("raw")),
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
            "actor": ev.get("actor"),  # the sign-in behind it, when the line was a person's work on a host (admins.py)
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
            # Who handles it (routing.py): set by the first matching rule, changed by assign() and escalation.
            "owner": None,
            "owner_id": None,
            "backup": None,
            "backup_id": None,
            "assigned_by": None,
            "assigned_at": None,
            "route": None,
            "notify": [],
            "escalation_level": 0,
            "escalations": [],
            "resolved_by": None,
            "resolution": None,
            "_opened_ts": now,
            "_last_event_ts": now,
            "_acked_ts": None,
            "_reminders": 0,
            "_sla_flag": False,
            "_notified_open": False,
            "_autonomous_denied": False,
            # Evidence Countersign weighs before acting alone: a deterministic rule or tripwire is strong;
            # an AI or keyword guess is weak and needs a second, independent one (another source or classifier).
            "strong_signal": cls.classified_by == "rules",
            "signals": [_signal(ev, cls)],
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
        self._route_incident(inc, now)
        self.scribe.record(self.name, "incident_opened", {
            "incident": iid, **{k: inc[k] for k in (
                "category", "severity", "base_points", "ai_confidence", "asset_criticality", "points",
                "classified_by", "needs_review", "src_ip", "user", "host", "layer", "actor", "opened_at",
                "recommended_action", "event_ids", "owner", "backup", "route", "notify")},
            "analyst": agent.name,
        })
        self.extensions.each("incident_opened", inc)  # AbuseIPDB looks the address up, in the background
        return inc

    def _proposals(self, inc: dict[str, Any], agent: LayerAgent) -> list[Proposal]:
        """The containment steps for an incident. Cyanide overrides this with its own plan."""
        return agent.propose(inc, self.settings.ttl_hours)

    def _describe(self, inc: dict[str, Any], agent: LayerAgent) -> None:
        proposals = self._proposals(inc, agent)
        inc["recommended_action"] = agent.recommended_text(proposals, self.settings.ttl_hours)
        inc["explanation"] = agent.explain(inc)
        inc["next_steps"] = next_steps(inc)
        if inc["category"] == ADMIN_CATEGORY:
            inc["explanation"] += " SentrAI does nothing on its own here: a person says whether this was them."
        elif inc.get("needs_review"):
            inc["explanation"] += " The classifier is uncertain: needs human review (never auto-contained)."

    def _attach(self, inc: dict[str, Any], ev: dict[str, Any], cls: Classification, needs_review: bool, now: float) -> None:
        inc["_last_event_ts"] = now
        for eid in [*cls.related_event_ids, ev["event_id"]]:
            if eid not in inc["event_ids"]:
                inc["event_ids"].append(eid)
            if eid in self.events:
                self.events[eid]["incident"] = inc["id"]
        changed = False
        sig = _signal(ev, cls)
        if sig not in inc.setdefault("signals", []):
            inc["signals"].append(sig)
            changed = True
        if cls.classified_by == "rules" and not inc.get("strong_signal", True):
            inc["strong_signal"] = True
            changed = True
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
        if cls.reason.startswith(TRIPWIRE_REASONS) and not str(inc.get("classification_reason")).startswith(TRIPWIRE_REASONS):
            inc["classification_reason"] = cls.reason  # a decoy touch is the strongest evidence: lead with it
        if changed:
            inc["points"] = round(inc["base_points"] * inc["ai_confidence"] * inc["asset_criticality"], 1)
            inc["_autonomous_denied"] = False  # stronger evidence: Countersign looks again
        self._describe(inc, self._agent(inc["analyzed_by"]))

    # ------------------------------------------------------------- risk engine
    def _refresh_incident(self, inc: dict[str, Any], now: float) -> None:
        end = inc["_acked_ts"] if inc["_acked_ts"] is not None else (inc.get("_closed_ts") or now)
        hours = self.clock.demo_hours(inc["_opened_ts"], end)
        inc["time_unaddressed_hours"] = round(hours, 2)
        inc["inaction_penalty"] = inaction_penalty(hours, self.settings.penalty_per_hour, self.settings.penalty_cap,
                                                  inc.get("severity", "high"))
        if hours > self.settings.sla_hours:
            inc["sla_breached"] = True
        inc["contribution"] = round(inc["points"] + inc["inaction_penalty"], 1) if inc["status"] in RISK_STATUSES else 0.0

    def _compute(self, now: float) -> dict[str, Any]:
        for inc in self.incidents.values():
            self._refresh_incident(inc, now)
        by_host: dict[str, float] = {}
        for inc in self.incidents.values():
            by_host[_host(inc)] = by_host.get(_host(inc), 0.0) + inc["contribution"]
        self._host_risk = {h: _score(v) for h, v in by_host.items()}
        if self.settings.risk_scope == "host":
            # Each machine on its own: the headline is the worst machine, not the sum of all of them.
            raw = max(by_host.values(), default=0.0)
        else:
            raw = sum(by_host.values())
        self._last_risk = _score(raw)
        return self._last_risk

    def _risk_of(self, inc: dict[str, Any]) -> int:
        """The index containment compares with the threshold: the incident's own machine in host scope."""
        if self.settings.risk_scope == "host":
            return self._host_risk.get(_host(inc), _score(0.0))["risk_index"]
        return self._last_risk["risk_index"]

    def _record_history(self, now: float) -> None:
        r = self._last_risk
        t = self.clock.iso(now)
        self.history.append({"t": t, "risk_index": r["risk_index"], "raw": r["raw_score"], "band": r["band"]})
        for h in {*self._host_risk, *self._host_seen}:
            hr = self._host_risk.get(h) or _score(0.0)
            if h not in self._host_history:
                self._host_history[h] = deque(maxlen=self.settings.history_len)
            self._host_history[h].append({"t": t, "risk_index": hr["risk_index"], "raw": hr["raw_score"], "band": hr["band"]})

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
            self._send_fingerprint(now)
            self._send_summary(now)
            self.admins.flush()
            findings = self.integrity.check()
            if self.remote is not None:
                refused, notes = self.remote.take()
                findings += refused
                for rtype, data in notes:
                    self.scribe.record(self.name, rtype, data)
        if findings:
            self.ingest(findings)  # a broken audit chain, a deleted audit file or a clock jump

    def _send_fingerprint(self, now: float, force: bool = False) -> dict[str, Any] | None:
        """Every ANCHOR_EVERY_MIN real minutes (when new records were written), send the newest
        record's signed fingerprint to the alert channels: a copy the server cannot recall (anchor.py)."""
        every = self.settings.anchor_every_min
        if not force and (every <= 0 or time.monotonic() < self._anchor_next):
            return None
        self._anchor_next = time.monotonic() + 60.0 * max(every, 1.0)
        fp = anchor.fingerprint(self.audit, self.anchor_key)
        if fp.seq == self._anchor_seq and not force:
            return None
        self._anchor_seq = fp.seq
        return self._notify(now, "audit_anchor", None, [self.settings.on_duty], f"Record fingerprint {fp.short()}",
                            f"Fingerprint of audit records 1 to {fp.seq}. Keep this message: if the audit log on "
                            f"the server is ever rebuilt, this line proves it (python -m app.anchor verify).\n"
                            f"{fp.line()}", [])

    # ------------------------------------------------------- client summary
    def _summary_url(self, period: str, until: int, ext: str = "pdf") -> str:
        """Signed like the report links, so the client opens it from Telegram or email without the API token."""
        path = f"/summary/{period}.{ext}"
        return f"{self.settings.public_url}{path}?until={until}&sig={sign(self.settings.api_token, f'{path}?until={until}')}"

    def _send_summary(self, now: float, force: bool = False, operator: str | None = None) -> dict[str, Any] | None:
        """At each due time of the client's schedule, queue the one-page summary for the alert channels."""
        sched = self.summary_schedule
        slot = sched.last_slot(now)
        if not force and (slot is None or (sched.last_sent_ts is not None and slot <= sched.last_sent_ts)):
            return None
        period = sched.every if sched.every in client_summary.PERIODS else "daily"
        until = now if force else slot
        r = client_summary.build_summary(self, period, until)
        sched.last_sent_ts = now if force else slot
        client_summary.save_schedule(self._summary_file, sched)
        num = r["numbers"]
        link = self._summary_url(period, r["until_ts"])
        n = self._notify(now, "summary", None, [sched.to], f"{r['title']}: {r['headline']}",
                         f"{r['period_text']}. Threats found: {num['threats']}, stopped automatically: "
                         f"{num['stopped_automatically']}, handled by staff: {num['handled_by_staff']}, "
                         f"need attention: {num['need_attention']}.", [])
        n["report_url"] = link  # the alert channels show it as a link to the one-page PDF
        self.scribe.record(self.scribe.name, "summary_sent", {
            "summary_id": r["summary_id"], "period": period, "from": r["from"], "until": r["until"],
            "numbers": num, "notification": n["id"], "recipients": [sched.to], "requested_by": operator,
            "chain_head_hash": self.audit.head_hash()})
        self._save()
        return {"summary": r, "notification": public(n), "link": link}

    def send_summary_now(self, operator: str) -> dict[str, Any]:
        with self.lock:
            return self._send_summary(self.clock.now(), force=True, operator=operator)  # type: ignore[return-value]

    def summary_settings(self) -> dict[str, Any]:
        with self.lock:
            return self.summary_schedule.public(self.clock.now())

    def set_summary_settings(self, operator: str, every: str | None = None, at: str | None = None,
                             day: str | None = None, to: str | None = None) -> dict[str, Any]:
        """The client's preference: daily or weekly (or off), what time, which weekday and who it goes to."""
        with self.lock:
            sched = self.summary_schedule
            if every is not None and every.strip().lower() not in client_summary.EVERY:
                raise BadRequestError(f"every must be one of {', '.join(client_summary.EVERY)}")
            if day is not None and day.strip().lower()[:3] not in client_summary.DAYS:
                raise BadRequestError("day must be a weekday such as mon or friday")
            if at is not None and client_summary.clock_time(at) is None:
                raise BadRequestError("at must be a time of day such as 08:00")
            before = {k: getattr(sched, k) for k in ("every", "at", "day", "to")}
            for k, v in (("every", every), ("at", at), ("day", day), ("to", to)):
                if v is not None:
                    setattr(sched, k, v)
            sched.checked()
            now = self.clock.now()
            sched.changed_by, sched.changed_at = operator, self.clock.iso(now)
            # A new schedule starts from now: no catch-up summary for a time that has already passed.
            sched.last_sent_ts = max(sched.last_sent_ts or 0.0, now)
            client_summary.save_schedule(self._summary_file, sched)
            self.scribe.record(self.name, "summary_schedule_changed", {
                "operator": operator, "before": before, "after": {k: getattr(sched, k) for k in ("every", "at", "day", "to")}})
            return sched.public(now)

    def _evaluate(self, now: float) -> None:
        self._expire_actions(now)
        self._check_actions(now)
        self._auto_close_quiet(now)
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
                and self._risk_of(i) >= self.settings.threshold
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
                self._contain(inc, "autonomous", self.needle.name, now, self._risk_of(inc))
            if candidates:
                r = self._compute(now)
                self._band_changes(now, r)
        if r["risk_index"] < self.settings.threshold:
            self._above_threshold = False
        self.admins.flush()
        self._save()

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
            saved = {"changed_by": "SENTRAI_MONITOR_ONLY", "reason": "set in the environment"}
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
                             f"{operator} turned SentrAI protection back on. Incidents over the threshold "
                             f"({len(open_ids)} open) can be contained again.", [])
            else:
                self._notify(now, "protection_off", None, [s.on_duty, s.it_manager, s.cxo],
                             "Protection is off: monitor-only mode",
                             f"{operator} turned SentrAI protection off: {reason}\nSentrAI keeps collecting, classifying "
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
    def _report_url(self, incident_id: str) -> str:
        """Signed, so the link in a Telegram alert opens in a browser without the API token."""
        path = f"/reports/{incident_id}.md"
        return f"{self.settings.public_url}{path}?sig={sign(self.settings.api_token, path)}"

    def _notify(self, now: float, kind: str, incident_id: str | None, recipients: list[str], title: str,
                text: str, buttons: list[dict[str, str]]) -> dict[str, Any]:
        nid = f"ntf-{self._next_notif:04d}"
        self._next_notif += 1
        r = self._last_risk
        # The signed fingerprint of the audit chain right now. Every alert carries it off the box, so
        # each message in Telegram or email is a witness the server cannot recall (anchor.py).
        witness = anchor.fingerprint(self.audit, self.anchor_key).line()
        n = {
            "id": nid,
            "incident": incident_id,
            "kind": kind,
            "title": title,
            "text": text,
            "recipients": recipients,
            # Each recipient's email / Telegram from the routing contacts, so the notifier can reach them.
            "deliver_to": self._addresses(recipients),
            "owner": self.incidents[incident_id].get("owner") if incident_id in self.incidents else None,
            "risk_index": r["risk_index"],
            "band": r["band"],
            "buttons": buttons,
            "report_url": self._report_url(incident_id) if incident_id else None,
            "witness": witness,
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

    @staticmethod
    def _buttons(inc: dict[str, Any]) -> list[dict[str, str]]:
        """The buttons an alert about an open incident carries."""
        return BUTTONS_WAS_THIS_YOU if inc["category"] == ADMIN_CATEGORY else BUTTONS_DECIDE

    def _notify_open_incidents(self, now: float, r: dict[str, Any]) -> None:
        for inc in self.incidents.values():
            if inc["_notified_open"] or inc["status"] != "open":
                continue
            if inc["needs_review"] or band_rank(r["band"]) >= band_rank("amber"):
                inc["_notified_open"] = True
                kind = "needs_review" if inc["needs_review"] else "incident_opened"
                extra = "\nClassifier uncertain: needs review, no automatic action will be taken." if inc["needs_review"] else ""
                if inc["category"] == ADMIN_CATEGORY:
                    kind = "was_this_you"
                    extra = ("\nWas this you? 'This was me' teaches SentrAI this sign-in and closes the alert. "
                             "'Not me' blocks the address." if inc.get("src_ip") else
                             "\nWas this you? 'This was me' teaches SentrAI this sign-in and closes the alert.")
                fp = anchor.fingerprint(self.audit, None).short()
                self._notify(now, kind, inc["id"], self._recipients(inc), self._headline(inc, r),
                             f"{self._headline(inc, r)}\n{inc['explanation']}\nRecommended: {inc['recommended_action']}.{extra}"
                             f"\n{self._owner_line(inc)}\nRecord fingerprint: {fp}",
                             self._buttons(inc))

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
                             f"is engaged for unacknowledged incidents; evidence reports are available.", [])
        self._last_band = new

    def _sla_reminders(self, now: float, r: dict[str, Any]) -> None:
        """Unanswered alerts: remind the owner every demo hour past the SLA, and after
        escalate_after_reminders unanswered reminders hand the incident to the owner's backup.
        Acknowledged but still unresolved incidents get a nudge every resolve_within_hours."""
        s = self.settings
        for inc in self.incidents.values():
            if inc["status"] in CLOSED_STATUSES:
                continue
            if inc["acked"]:
                self._resolve_reminders(inc, now, r)
                continue
            hours = self.clock.demo_hours(inc["_opened_ts"], now)
            if hours < s.sla_hours:
                continue
            if not inc["_sla_flag"]:
                inc["_sla_flag"] = True
                inc["sla_breached"] = True
                self.scribe.record(self.name, "sla_breached", {"incident": inc["id"], "sla_hours": s.sla_hours,
                                                               "responsible": inc.get("owner") or s.on_duty})
                self._timeline(inc, now, "sla_breached", f"SLA of {s.sla_hours:g} h passed without acknowledgement")
            due = min(s.max_reminders, int(math.floor(hours - s.sla_hours)) + 1)
            while inc["_reminders"] < due:
                inc["_reminders"] += 1
                n = inc["_reminders"]
                if self._escalate(inc, now, r, n, hours):
                    continue
                inc["_owner_reminders"] = inc.get("_owner_reminders", 0) + 1
                overdue = fmt_demo_hours(max(0.0, hours - s.sla_hours))
                self._notify(now, "sla_reminder", inc["id"], self._recipients(inc, everyone=False),
                             f"Reminder {n}: {inc['id']} unacknowledged",
                             f"Reminder {n}: {self._headline(inc, r)} is still unacknowledged, "
                             f"overdue by {overdue} (Policy SLA: {s.sla_hours:g} hrs). "
                             f"Inaction penalty so far: +{inc['inaction_penalty']:g}.\nRecommended: {inc['recommended_action']}."
                             f"\n{self._owner_line(inc)}",
                             self._buttons(inc))

    def _resolve_reminders(self, inc: dict[str, Any], now: float, r: dict[str, Any]) -> None:
        every = self.router.follow_up.resolve_within_hours
        if every <= 0 or inc["_acked_ts"] is None:
            return
        hours = self.clock.demo_hours(inc["_acked_ts"], now)
        due = min(3, int(hours // every))
        while inc.get("_resolve_reminders", 0) < due:
            inc["_resolve_reminders"] = inc.get("_resolve_reminders", 0) + 1
            self._notify(now, "resolve_reminder", inc["id"], self._recipients(inc, everyone=False),
                         f"{inc['id']} is still not resolved",
                         f"{self._headline(inc, r)} was acknowledged {fmt_demo_hours(hours)} ago and is still "
                         f"{inc['status']}. Resolve it with a short note, or hand it to someone else.\n"
                         f"{self._owner_line(inc)}", [])

    # ------------------------------------------------------------- ownership
    def _recipients(self, inc: dict[str, Any], everyone: bool = True) -> list[str]:
        """The owner first, then (for the first alert) the people its routing rule names."""
        names = [inc.get("owner") or self.settings.on_duty]
        if everyone:
            names += [n for n in inc.get("notify") or [] if n not in names]
        return names

    def _owner_line(self, inc: dict[str, Any]) -> str:
        backup = f" · backup: {inc['backup']}" if inc.get("backup") else ""
        return f"Owner: {inc.get('owner') or 'nobody yet'}{backup}"

    def _set_owner(self, inc: dict[str, Any], owner: routing.Contact, backup: routing.Contact | None,
                   by: str, now: float) -> None:
        inc.update(owner=owner.name, owner_id=owner.id or None, backup=backup.name if backup else None,
                   backup_id=backup.id if backup else None, assigned_by=by, assigned_at=self.clock.iso(now),
                   _owner_reminders=0)

    def _route_incident(self, inc: dict[str, Any], now: float) -> None:
        route = self.router.route(inc)
        self._set_owner(inc, route.owner, self.router.backup_of(route.owner), f"routing: {route.rule}", now)
        inc["route"] = route.rule
        inc["notify"] = [c.name for c in route.notify]
        cc = f"; also told: {', '.join(inc['notify'])}" if inc["notify"] else ""
        self._timeline(inc, now, "assigned", f"Assigned to {inc['owner']} by rule \"{route.rule}\"{cc}")

    def _escalate(self, inc: dict[str, Any], now: float, r: dict[str, Any], n: int, hours: float) -> bool:
        """Hand an unanswered incident to the owner's backup. False when it is not time yet or nobody is left."""
        fu = self.router.follow_up
        if (fu.escalate_after_reminders <= 0 or inc.get("_owner_reminders", 0) < fu.escalate_after_reminders
                or inc.get("escalation_level", 0) >= fu.max_escalations):
            return False
        new = self.router.contact(inc.get("backup_id"))
        if new is None:
            return False
        old = inc.get("owner") or self.settings.on_duty
        self._set_owner(inc, new, self.router.backup_of(new), "escalation", now)
        inc["escalation_level"] = inc.get("escalation_level", 0) + 1
        why = f"{old} did not answer {fu.escalate_after_reminders} reminder(s)"
        inc.setdefault("escalations", []).append({"from": old, "to": new.name, "at": self.clock.iso(now),
                                                  "level": inc["escalation_level"], "why": why})
        self.scribe.record(self.name, "incident_escalated", {
            "incident": inc["id"], "from": old, "to": new.name, "level": inc["escalation_level"], "why": why,
            "hours_unacknowledged": round(hours, 2)})
        self._timeline(inc, now, "escalated", f"Escalated to backup {new.name}: {why}")
        self._notify(now, "escalated", inc["id"], [new.name, old],
                     f"Escalated to you: {inc['id']} unanswered",
                     f"{self._headline(inc, r)} has had no answer for {fmt_demo_hours(hours)}: {why}. "
                     f"You are the backup contact, so it is yours now.\nRecommended: {inc['recommended_action']}."
                     f"\n{self._owner_line(inc)}", self._buttons(inc))
        return True

    def pending_notifications(self) -> list[dict[str, Any]]:
        with self.lock:
            return public([n for n in self.notifications if not n["delivered"]])

    def mark_delivered(self, nid: str, channel: str, message_id: str | None, to: str | None = None) -> dict[str, Any]:
        with self.lock:
            n = next((x for x in self.notifications if x["id"] == nid), None)
            if n is None:
                raise KeyError(nid)
            now = self.clock.now()
            ts = self.clock.iso(now)
            # `to`: the one person a private message went to (a direct Telegram message); None = the whole channel.
            n["deliveries"].append({"channel": channel, "message_id": message_id, "delivered_at": ts, "to": to})
            if not n["delivered"]:
                n.update(delivered=True, delivered_at=ts, channel=channel, message_id=message_id)
            self.scribe.record(self.scribe.name, "notification_delivered", {
                "notification": nid, "incident": n["incident"], "channel": channel, "message_id": message_id,
                "recipients": [to] if to else n["recipients"], "kind": n["kind"]})
            if n["incident"] in self.incidents:
                self._timeline(self.incidents[n["incident"]], now, "delivered",
                               f"{nid} delivered via {channel}{' to ' + to if to else ''} (message_id {message_id})")
            self._save()
            return public(n)

    # --------------------------------------------------------- hotpatch / TTL
    def _is_active(self, a: dict[str, Any], now: float) -> bool:
        return a["status"] == "permanent" or (a["status"] == "active" and a["_expires_ts"] > now)

    def _active_actions(self, inc: dict[str, Any], now: float) -> list[dict[str, Any]]:
        return [a for a in inc["actions"] if self._is_active(a, now)]

    def blocklist(self, host: str | None = None) -> dict[str, list[str]]:
        """Everything blocked; with a host in host scope, only what that machine's agent must enforce.
        In fleet scope every machine guards against every block, so the host makes no difference."""
        with self.lock:
            if host is None or self.settings.risk_scope != "host":
                return self.blocklist_responder.blocklist()
            now = self.clock.now()
            ips: set[str] = set()
            users: set[str] = set()
            for a in self.actions:
                if not (self._is_active(a, now) and a.get("verified")) or self._action_host(a) != host:
                    continue
                if a["type"] == "block_ip":
                    ips.add(str(a["target"]))
                elif a["type"] == "lock_user":
                    users.add(str(a["target"]))
            return {"ips": sorted(ips), "users": sorted(users)}

    def _action_host(self, a: dict[str, Any]) -> str:
        if a.get("host"):
            return str(a["host"])
        return _host(self.incidents.get(a["incident"]) or {})  # actions saved before they named a host

    def _end_action(self, a: dict[str, Any], status: str) -> None:
        """Every way an action stops (expired, rolled back) goes through here, so the responder undoes it
        and whether the undo worked is recorded (a failed undo is retried by _check_actions)."""
        in_force = a["status"] in ("active", "permanent")
        a["status"] = status
        if in_force:
            a["ended_at"] = self.clock.iso(self.clock.now())
            a["_ended_ts"] = self.clock.now()
            self._undo(a, attempt=1)

    def _undo(self, a: dict[str, Any], attempt: int) -> None:
        try:
            ok = self.responders.revert(a)
            # Each responder notes its own undo under "<name>_revert" (webhook, cloudflare, firewall, ...).
            failed = [v for k, v in a.items() if k.endswith("_revert") and isinstance(v, dict) and v.get("ok") is False]
            error = None if ok is not False else (failed[0] if failed else {}).get(
                "error", "the responder could not confirm the action was removed")
        except Exception as exc:  # a broken responder must not stop the rest of the rollback
            ok, error = False, f"{type(exc).__name__}: {exc}"[:200]
        now = self.clock.now()
        a["undo"] = {"ok": ok, "at": self.clock.iso(now), "attempts": attempt, **({"error": error} if error else {})}
        a["_undo_next"] = time.monotonic() + self.settings.undo_retry_s if ok is False else None
        self.scribe.record(self.name, "action_undone" if ok is not False else "action_undo_failed", {
            "incident": a["incident"], "action_id": a["action_id"], "type": a["type"], "target": a["target"],
            "ended_as": a["status"], "ok": ok, "attempt": attempt, **({"error": error} if error else {})})
        inc = self.incidents.get(a["incident"])
        if inc is None:
            return
        what = f"{a['type']} {a['target']} ({a['action_id']})"
        if ok is False:
            last = attempt > self.settings.undo_retries
            self._timeline(inc, now, "undo_failed", f"Undo of {what} failed (attempt {attempt}): {error}"
                                                    + ("; a person must remove it by hand" if last else "; retrying"))
            if attempt == 1 or last:
                self._notify(now, "undo_failed", inc["id"], [self.settings.on_duty, self.settings.team_lead],
                             f"{inc['id']}: undo of {a['type']} {a['target']} failed",
                             f"SentrAI tried to remove {what} but could not confirm it is gone: {error}.\n"
                             + ("It gave up after several tries. Please remove it by hand and check the target "
                                "can connect again." if last else
                                f"It will retry {self.settings.undo_retries} more time(s). Check the target can connect."),
                             [])
        elif attempt > 1:
            self._timeline(inc, now, "undo_ok", f"Undo of {what} succeeded on attempt {attempt}")

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
            review = self.needle.review(inc, proposals, risk_idx, s.threshold, self._auto_last_hour(now))
            self.scribe.record(self.needle.name, "needle_review", {
                "incident": inc["id"], "approved": review.approved, "reasoning": review.reasoning,
                "proposals": [p.__dict__ for p in proposals], "denied": review.denied})
            if not review.approved:
                inc["_autonomous_denied"] = True
                self._timeline(inc, now, "needle_denied", review.reasoning)
                self._notify(now, "needs_operator", inc["id"], [s.on_duty, s.team_lead],
                             f"{inc['id']}: autonomous action denied by Countersign",
                             f"{self._headline(inc, self._last_risk)}\nCountersign denied autonomous action: {review.reasoning}\n"
                             f"A human must decide. Recommended: {inc['recommended_action']}.", BUTTONS_DECIDE)
                return False
            approved = review.approved_proposals
        else:
            approved, _ = self.needle.screen(proposals)
            self.scribe.record(self.needle.name, "needle_review", {
                "incident": inc["id"], "approved": True, "operator": approver,
                "reasoning": f"Operator {approver} approved; the human decision is the second key. "
                             f"Countersign checked the allowlist only ({len(approved)} action(s)).",
                "justification": justification})
        if not approved:
            self._timeline(inc, now, "no_playbook", "No allowlisted playbook applies")
            return False
        # 3. Apply with TTL
        new_actions = []
        for p in approved:
            aid = f"act-{self._next_action:04d}"
            self._next_action += 1
            a = executor.apply(p, inc["id"], aid, mode, approver, now, self.clock, s.ttl_for(p.type), snap,
                               s.check_after_min / 60.0)
            a["host"] = inc.get("host")  # the machine whose agent puts this block in place
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
        if s.health_url:
            before = self._probe_health()
            for a in new_actions:
                a["health_before"] = before
        inc["status"] = "contained"
        inc["contained_at"] = self.clock.iso(now)
        summary = "; ".join(f"{a['type']} {a['target']}" for a in new_actions)
        ttl = "/".join(f"{t:g}" for t in sorted({a["ttl_hours"] for a in new_actions}))
        self._timeline(inc, now, "action", f"{'Autonomous override' if mode == 'autonomous' else 'Operator-approved hotpatch'}"
                                           f" ({approver}): {summary}; TTL {ttl} h; snapshot {snap[:12]}", -inc["points"])
        # 5. Notify
        if mode == "autonomous":
            self._notify(now, "autonomous_action", inc["id"], [s.on_duty, s.it_manager, s.cxo],
                         f"{inc['id']}: autonomous containment engaged",
                         f"\U0001f335 SentrAI autonomous override on {inc['id']} (risk {risk_idx}/100 >= {s.threshold}, "
                         f"no acknowledgement). Approved by Countersign. Applied for {ttl} h: {summary}.\n"
                         f"Evidence report: {s.public_url}/reports/{inc['id']}.md", BUTTONS_AFTER_ACTION)
        else:
            self._notify(now, "operator_action", inc["id"], [s.on_duty],
                         f"{inc['id']}: hotpatch applied by {approver}",
                         f"{approver} approved the hotpatch for {inc['id']}. Applied for {ttl} h: {summary}.",
                         BUTTONS_AFTER_ACTION)
        return True

    def _expire_actions(self, now: float, while_down: bool = False) -> None:
        for a in self.actions:
            if a["status"] == "active" and a["_expires_ts"] <= now:
                self._end_action(a, "expired")
                data = {"incident": a["incident"], "action_id": a["action_id"], "type": a["type"], "target": a["target"]}
                if while_down:
                    data.update(while_core_down=True, expired_at=a["expires_at"])
                self.scribe.record(a["executed_by"], "action_expired", data)
                inc = self.incidents.get(a["incident"])
                if inc:
                    when = f" at {a['expires_at']} while the core was down; rolled back on restart" if while_down else ""
                    self._timeline(inc, now, "expired", f"TTL expired{when}: {a['type']} {a['target']} ({a['action_id']})")
                    if not any(x["status"] == "active" for x in inc["actions"]):
                        self._notify(now, "action_expired", inc["id"], [self.settings.on_duty],
                                     f"{inc['id']}: temporary hotpatch expired",
                                     f"The temporary hotpatch for {inc['id']} expired after {a['ttl_hours']:g} h. "
                                     f"Make it permanent or leave it expired.", BUTTONS_AFTER_ACTION)

    # ------------------------------------------------- business limits / checks
    def limits(self) -> dict[str, Any]:
        """The business limits on protective actions, as in force now."""
        s = self.settings
        return {
            "auto_actions": sorted(s.auto_actions & self.responders.allowlist),
            "needs_a_person": sorted(self.responders.allowlist - s.auto_actions),
            "ttl_hours": {t: s.ttl_for(t) for t in sorted(self.responders.allowlist)},
            "max_ttl_hours": s.max_ttl_hours,
            "max_auto_actions_per_hour": s.max_auto_actions_per_hour,
            "auto_actions_last_hour": self._auto_last_hour(self.clock.now()),
            "permanent_needs_a_person": True,
            "check_after_min": s.check_after_min,
            "health_url_set": bool(s.health_url),
        }

    def _auto_last_hour(self, now: float) -> int:
        """Automatic actions started in the last timer hour (the MAX_AUTO_ACTIONS_PER_HOUR budget)."""
        since = now - self.clock.real_seconds(1.0)
        return sum(1 for a in self.actions if a["mode"] == "autonomous" and a.get("_applied_ts", 0.0) > since)

    health_probe: Callable[[str], dict[str, Any]] = staticmethod(lambda url: _http_probe(url))

    def _probe_health(self) -> dict[str, Any] | None:
        if not self.settings.health_url:
            return None
        try:
            return self.health_probe(self.settings.health_url)
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:200]}

    def _check_actions(self, now: float) -> None:
        """Retries failed undos, and runs the after-action check on each action once it is due:
        did it work, and did it disrupt anything."""
        for a in self.actions:
            u = a.get("undo")
            if u and u.get("ok") is False and u["attempts"] <= self.settings.undo_retries \
                    and time.monotonic() >= (a.get("_undo_next") or 0.0):
                self._undo(a, u["attempts"] + 1)
            if a.get("check") is not None or a.get("_check_ts") is None:
                continue
            ended = a["status"] not in ("active", "permanent")
            if a["_check_ts"] > now and not ended:
                continue
            self._after_action_check(a, now)

    def _after_action_check(self, a: dict[str, Any], now: float) -> None:
        start = a.get("_applied_ts", a["_check_ts"])
        end = min(now, a.get("_ended_ts", now), max(a["_check_ts"], start))
        if a.get("verified") is False:
            check = {"worked": False, "worked_note": "never went in force: the responder could not verify it, "
                                                     "so it was rolled back at once", "disruption": None}
        else:
            check = {**_did_it_work(a, self.events.values(), start, end),
                     **_disruption(a, self.events.values(), start, end, self._probe_health())}
        check["at"] = self.clock.iso(now)
        check["window_min"] = round(self.clock.demo_hours(start, max(end, start)) * 60, 1)
        if end < a["_check_ts"] and check.get("worked") is True:
            check["worked_note"] += f" (it ended after {check['window_min']:g} min, before the full check window)"
        a["check"] = check
        self.scribe.record(self.name, "action_checked", {"incident": a["incident"], "action_id": a["action_id"],
                                                         "type": a["type"], "target": a["target"], **check})
        inc = self.incidents.get(a["incident"])
        if inc is None:
            return
        verdict = {True: "worked", False: "did NOT work", None: "could not be checked"}[check["worked"]]
        harm = {True: "possible disruption", False: "no disruption seen", None: "disruption not measurable"}[check["disruption"]]
        self._timeline(inc, now, "action_checked", f"After-action check of {a['type']} {a['target']} "
                                                   f"({a['action_id']}): {verdict}; {harm}. {check['worked_note']}"
                                                   + (f" {check['disruption_note']}" if check.get("disruption_note") else ""))
        if check["worked"] is False or check["disruption"] is True:
            buttons = BUTTONS_AFTER_ACTION if a["status"] in ("active", "permanent") else []
            self._notify(now, "action_check", inc["id"], [self.settings.on_duty],
                         f"{inc['id']}: {a['type']} {a['target']} {verdict}" + (", possible disruption"
                                                                                if check["disruption"] else ""),
                         f"After-action check of {a['action_id']} ({a['type']} {a['target']}):\n"
                         f"Did it work? {check['worked_note']}\n"
                         f"Side effects? {check.get('disruption_note') or harm}\n"
                         "Roll it back if it is hurting real users, or check the enforcement path if it did not work.",
                         buttons)

    def _auto_close_quiet(self, now: float) -> None:
        """Resolve scan / brute-force incidents that went quiet, so a public server's background noise
        does not pile up forever. Never touches an incident with containment in force."""
        quiet_s = self.settings.auto_close_quiet_min * 60.0
        if quiet_s <= 0:
            return
        for inc in self.incidents.values():
            if (inc["status"] not in RISK_STATUSES or inc["category"] not in self.settings.auto_close_categories
                    or self._active_actions(inc, now)):
                continue
            last = inc.get("_last_event_ts") or inc["_opened_ts"]
            if now - last < quiet_s:
                continue
            minutes = int((now - last) // 60)
            was_acked = inc["acked"]
            inc["status"] = "resolved"
            inc["resolved_by"] = "auto-close"
            inc["_closed_ts"] = now
            self._refresh_incident(inc, now)
            note = "" if was_acked else " It was never acknowledged; the inaction record stays in the report."
            self._timeline(inc, now, "auto_closed", f"Closed automatically: no new events for {minutes} min.{note}")
            self.scribe.record(self.name, "incident_auto_closed", {
                "incident": inc["id"], "category": inc["category"], "src_ip": inc.get("src_ip"),
                "quiet_minutes": minutes, "acked": was_acked, "sla_breached": inc["sla_breached"],
                "events": len(inc["event_ids"])})
    # ------------------------------------------------------------ persistence
    def _encode_incident(self, inc: dict[str, Any]) -> dict[str, Any]:
        """Incident as saved: actions by id (they are saved in their own table). Cyanide adds its plan."""
        return {**inc, "actions": [a["action_id"] for a in inc["actions"]]}

    def _decode_incident(self, data: dict[str, Any]) -> dict[str, Any]:
        return data

    def _save(self) -> None:
        """Writes whatever changed since the last save. Called at the end of every state change."""
        linked = {eid for inc in self.incidents.values() for eid in inc["event_ids"]}
        self.store.save({
            "incidents": {iid: self._encode_incident(inc) for iid, inc in self.incidents.items()},
            "actions": {a["action_id"]: a for a in self.actions},
            "notifications": {n["id"]: n for n in self.notifications},
            # Only events behind an incident: the chat and Cyanide show them as evidence.
            "events": {eid: self.events[eid] for eid in linked if eid in self.events},
            "meta": {"counters": {
                "next_incident": self._next_incident, "next_action": self._next_action,
                "next_notif": self._next_notif, "last_band": self._last_band,
                "above_threshold": self._above_threshold, "started_ts": self._started_ts,
                "clock_offset": self.clock._offset,
            }},
        })

    def _restore(self) -> None:
        """Loads the saved state (if any), puts blocks still in force back in place, and rolls back
        and audits the ones whose TTL ran out while the core was down."""
        saved = self.store.load()
        if not saved["incidents"] and not saved["actions"]:
            return
        with self.lock:
            c = saved["meta"].get("counters", {})
            self.clock._offset = float(c.get("clock_offset", 0.0))
            self._next_incident = max(self._next_incident, int(c.get("next_incident", 0)))
            self._next_action = int(c.get("next_action", 1))
            self._next_notif = int(c.get("next_notif", 1))
            self._last_band = c.get("last_band", "green")
            self._above_threshold = bool(c.get("above_threshold", False))
            self._started_ts = float(c.get("started_ts", self._started_ts))
            self.events = dict(sorted(saved["events"].items(), key=lambda kv: kv[0]))
            self.actions = sorted(saved["actions"].values(), key=lambda a: a["action_id"])
            by_id = {a["action_id"]: a for a in self.actions}
            self.notifications = sorted(saved["notifications"].values(), key=lambda n: n["id"])
            self.incidents = {}
            for iid in sorted(saved["incidents"], key=lambda x: saved["incidents"][x]["_opened_ts"]):
                inc = self._decode_incident(saved["incidents"][iid])
                inc["actions"] = [by_id[x] for x in inc["actions"] if x in by_id]
                if "owner_id" not in inc:  # saved before incidents had owners
                    for k, v in (("owner", None), ("backup", None), ("backup_id", None), ("assigned_by", None),
                                 ("assigned_at", None), ("route", None), ("notify", []), ("escalation_level", 0),
                                 ("escalations", []), ("resolved_by", inc.get("resolved_by")), ("resolution", None)):
                        inc.setdefault(k, v)
                    inc["owner_id"] = None
                    if inc["status"] not in CLOSED_STATUSES:
                        self._route_incident(inc, self.clock.now())
                self.incidents[iid] = inc
            # The responders start empty: put back everything still in force.
            in_force = [a for a in self.actions if a["status"] in ("active", "permanent")]
            for a in in_force:
                self.responders.apply(a)
            # Undos that had failed: track them again, so the retry in _check_actions can take them out.
            for a in self.actions:
                if (a.get("undo") or {}).get("ok") is False:
                    self.responders.apply(dict(a))
                    a["_undo_next"] = 0.0
            now = self.clock.now()
            expiring = [a["action_id"] for a in in_force if a["status"] == "active" and a["_expires_ts"] <= now]
            self.scribe.record(self.name, "state_restored", {
                "incidents": len(self.incidents),
                "open_incidents": [i["id"] for i in self.incidents.values() if i["status"] in RISK_STATUSES],
                "actions_in_force": [a["action_id"] for a in in_force if a["action_id"] not in expiring],
                "actions_expired_while_down": expiring,
                "pending_notifications": sum(1 for n in self.notifications if not n["delivered"]),
            })
            self._expire_actions(now, while_down=True)
            self._evaluate(now)
            self._record_history(now)

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

    def assign(self, iid: str, assignee: str, operator: str, note: str | None = None) -> dict[str, Any]:
        """Give the incident to someone: a routing contact (id, name, role or Telegram handle) or any name."""
        assignee = (assignee or "").strip()
        if not assignee:
            raise BadRequestError("assignee is required")
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            if inc["status"] in CLOSED_STATUSES:
                raise ConflictError(f"{iid} is already {inc['status']}")
            who = self.router.person(assignee)
            if who.name == inc.get("owner"):
                return self.incident_public(inc)
            old = inc.get("owner")
            # Someone outside the contact book keeps the contact who had it as their backup.
            backup = self.router.backup_of(who) if who.id else (self.router.contact(inc.get("owner_id"))
                                                                 or self.router.contact(inc.get("backup_id")))
            self._set_owner(inc, who, backup, operator, now)
            took = operator.strip().lower().lstrip("@") == who.name.lower().lstrip("@") or \
                (who.telegram and operator.strip().lower().lstrip("@") == who.telegram.lower().lstrip("@"))
            self.scribe.record(self.name, "incident_assigned", {"incident": iid, "from": old, "to": who.name,
                                                                "operator": operator, "note": note})
            self._timeline(inc, now, "assigned", (f"Taken by {who.name}" if took else
                                                  f"Assigned to {who.name} by {operator}") + (f": {note}" if note else ""))
            if not took:
                self._notify(now, "assigned", iid, [who.name], f"{iid} assigned to you",
                             f"{operator} assigned {self._headline(inc, self._last_risk)} to you"
                             + (f": {note}" if note else ".") + f"\nRecommended: {inc['recommended_action']}."
                             f"\n{self._owner_line(inc)}",
                             self._buttons(inc) if inc["status"] != "contained" else BUTTONS_AFTER_ACTION)
            self._save()
            return self.incident_public(inc)

    def resolve(self, iid: str, operator: str, note: str | None) -> dict[str, Any]:
        """Close the incident: the owner (or anyone) says it is dealt with and how. Blocks in force stay
        until they expire or are rolled back."""
        note = (note or "").strip()
        if not note:
            raise BadRequestError("resolving requires a short note on what was done")
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            if inc["status"] in CLOSED_STATUSES:
                raise ConflictError(f"{iid} is already {inc['status']}")
            self._set_acked(inc, operator, "resolve", now)
            inc["status"] = "resolved"
            inc.update(resolved_by=operator, resolution=note, closed_at=self.clock.iso(now), _closed_ts=now)
            inc["decisions"].append({"operator": operator, "decision": "resolve", "justification": note,
                                     "at": inc["closed_at"]})
            still = [a["action_id"] for a in self._active_actions(inc, now)]
            self.scribe.record(self.name, "incident_resolved", {"incident": iid, "operator": operator, "note": note,
                                                                "owner": inc.get("owner"), "actions_in_force": still})
            left = f" {len(still)} block(s) stay until they expire or are rolled back." if still else ""
            self._timeline(inc, now, "resolved", f"Resolved by {operator}: {note}.{left}", -inc["points"])
            self._evaluate(now)
            return self.incident_public(inc)

    # ------------------------------------------------------ the administrators
    def mine(self, iid: str, operator: str, channel: str = "dashboard") -> dict[str, Any]:
        """"This was me": the person says the sign-in behind this incident was their own. SentrAI learns its
        address, key and account, rolls back any block it had put on them, and closes the incident along
        with the same person's other open incidents on that machine."""
        with self.lock:
            inc = self._get(iid)
            now = self.clock.now()
            if inc["status"] in CLOSED_STATUSES:
                raise ConflictError(f"{iid} is already {inc['status']}")
            if not self.admins.on:
                raise BadRequestError("ADMIN_SESSIONS is off: SentrAI is not keeping track of the administrators")
            events = [self.events[e] for e in inc["event_ids"] if e in self.events]
            learned = self.admins.teach(inc, events, operator, now)
            closed: list[str] = []
            for other in list(self.incidents.values()):
                if other is inc or other["status"] in CLOSED_STATUSES:
                    continue
                other_events = [self.events[e] for e in other["event_ids"] if e in self.events]
                if self.admins.same_actor(inc, events, other, other_events):
                    self._close_as_mine(other, operator, now, f"closed with {iid}: {operator} said this was them")
                    closed.append(other["id"])
            what = ", ".join(learned) if learned else "nothing new to learn"
            self._close_as_mine(inc, operator, now, f"This was me ({operator}): {what}")
            self.scribe.record(self.name, "admin_confirmed", {
                "incident": iid, "operator": operator, "channel": channel, "learned": learned,
                "also_closed": closed, "actor": inc.get("actor")})
            self._evaluate(now)
            return {**self.incident_public(inc), "learned": learned, "also_closed": closed}

    def _close_as_mine(self, inc: dict[str, Any], operator: str, now: float, note: str) -> None:
        self._set_acked(inc, operator, "mine", now)
        for a in self._active_actions(inc, now):
            self._end_action(a, "rolled_back")
            self.scribe.record(self.name, "action_rolled_back", {
                "incident": inc["id"], "action_id": a["action_id"], "operator": operator,
                "reason": "the sign-in was the administrator's own"})
        inc["status"] = "resolved"
        inc.update(resolved_by=operator, resolution=note, closed_at=self.clock.iso(now), _closed_ts=now)
        inc["decisions"].append({"operator": operator, "decision": "mine", "justification": note, "at": inc["closed_at"]})
        self._timeline(inc, now, "admin_confirmed", f"{operator} said this was them: {note}", -inc["points"])

    def _not_me(self, inc: dict[str, Any], operator: str, now: float) -> None:
        """"Not me" on a root-access incident: what SentrAI had learned from that sign-in is forgotten, and
        its address is distrusted, before the block goes on."""
        events = [self.events[e] for e in inc["event_ids"] if e in self.events]
        forgotten = self.admins.distrust(inc, events, operator, now)
        self.scribe.record(self.name, "admin_distrusted", {
            "incident": inc["id"], "operator": operator, "address": inc.get("src_ip"), "forgotten": forgotten,
            "actor": inc.get("actor")})
        self._timeline(inc, now, "admin_distrusted", f"{operator} said this was not them"
                       + (f"; forgotten: {', '.join(forgotten)}" if forgotten else ""))

    def admins_public(self, host: str | None = None) -> dict[str, Any]:
        """The known administrators, who is signed in now and their recent work; for one machine with host."""
        with self.lock:
            data = self.admins.public(self.clock.now())
            if host:
                data["sessions"] = [x for x in data["sessions"] if x.get("host") == host]
                data["activity"] = [x for x in data["activity"] if x.get("host") == host]
                data["accounts"] = [x for x in data["accounts"] if x.get("host") in ("*", host)]
            return data

    def admins_change(self, operator: str, action: str, kind: str, value: str, label: str = "",
                      host: str | None = None) -> dict[str, Any]:
        """Add or forget a known address, key fingerprint or account by hand (the Admins tab). ValueError when
        the value is not one."""
        with self.lock:
            now = self.clock.now()
            data = self.admins.change(operator, action, kind, value, label, host, now)
            self.scribe.record(self.name, "admin_changed", {
                "operator": operator, "action": action, "kind": kind,
                "value": short_key(value) if kind == "key" else value, "label": label, "host": host})
            return data

    def admin_signed_in(self, email: str, role: str, address: str | None) -> dict[str, Any]:
        """The dashboard says an Owner or Admin signed in with the authenticator from this address: it is an
        administrator's for ADMIN_SIGNIN_HOURS."""
        with self.lock:
            now = self.clock.now()
            out = self.admins.signed_in(email, role, address, now)
            if out.get("vouched"):
                self.scribe.record(self.name, "admin_signed_in", {
                    "email": email, "role": role, "address": out["address"], "until": out["until"]})
            return out

    def routing_public(self) -> dict[str, Any]:
        with self.lock:
            out = self.router.public()
            self.extensions.each("contacts", out["contacts"])  # Telegram: whether each person linked a chat
            return out

    def routing_update(self, data: dict[str, Any], operator: str, summary: str = "") -> dict[str, Any]:
        """Replace the routing file (people, rules, follow-up, map layout) and use it from the next alert on.
        The audit record says which parts changed and, in the dashboard's words, what."""
        clean = routing.validate(data)  # ValueError: nothing is written
        with self.lock:
            old = self.router.public()
            before = {c.id: c.name for c in self.router.contacts.values()}
            routing.save(self.routing_path, clean)
            self.router = routing.load(self.routing_path, *self.role_names.values())
            for role in ROLES:
                setattr(self.settings, role, self.router.by_role(role, self.role_names[role]))
            after = {c.id: c.name for c in self.router.contacts.values()}
            self.scribe.record(self.name, "routing_changed", {
                "operator": operator, "file": str(self.routing_path),
                "people": len(after), "rules": len(self.router.rules),
                "added": sorted(after[i] for i in after.keys() - before.keys()),
                "removed": sorted(before[i] for i in before.keys() - after.keys()),
                "changed": routing.changed_parts(old, self.router.public()),
                "summary": " ".join(str(summary or "").split())[:300]})
        return self.routing_public()

    # ---------------------------------------------------- who an alert reaches
    def _addresses(self, recipients: list[str]) -> list[dict[str, str]]:
        """Each recipient's email and Telegram, plus what extensions add (the private Telegram chat
        that reaches them, once they linked one)."""
        out = self.router.addresses(recipients)
        self.extensions.each("addresses", out)
        return out

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
                if inc["category"] == ADMIN_CATEGORY:
                    self._not_me(inc, operator, now)
                inc["decisions"].append({"operator": operator, "decision": "approve", "justification": justification,
                                         "at": self.clock.iso(now)})
                self.scribe.record(self.name, "decision", {"incident": iid, "operator": operator, "decision": "approve",
                                                           "justification": justification})
                self._timeline(inc, now, "decision", f"Approve & Patch pressed by {operator}")
                if self._active_actions(inc, now):
                    self._timeline(inc, now, "decision", "Containment already active; operator endorsed it")
                else:
                    self._contain(inc, "operator", operator, now, self._risk_of(inc), justification)
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

    def list_incidents(self, host: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            now = self.clock.now()
            self._compute(now)
            return [public(i) for i in self.incidents.values() if host is None or _host(i) == host]

    def get_incident(self, iid: str) -> dict[str, Any]:
        with self.lock:
            inc = self._get(iid)
            self._refresh_incident(inc, self.clock.now())
            return public(inc)

    def risk(self, history: int = 600, host: str | None = None) -> dict[str, Any]:
        """The risk index. With a host: that one machine's own score, incidents and history."""
        with self.lock:
            now = self.clock.now()
            r = self._compute(now)
            source = self.history
            incs = list(self.incidents.values())
            if host is not None:
                r = self._host_risk.get(host) or _score(0.0)
                source = self._host_history.get(host) or deque()
                incs = [i for i in incs if _host(i) == host]
            hist = list(source)[-history:] if history > 0 else []
            out = {
                "risk_index": r["risk_index"],
                "band": r["band"],
                "raw_score": r["raw_score"],
                "threshold": self.settings.threshold,
                "risk_scope": self.settings.risk_scope,
                "open_incidents": [i["id"] for i in incs if i["status"] in RISK_STATUSES],
                "needs_review": [i["id"] for i in incs if i["needs_review"] and i["status"] in RISK_STATUSES],
                "contained_incidents": [i["id"] for i in incs if i["status"] == "contained"],
                "monitor_only": self.monitor_only,
                "demo_speed": self.settings.demo_speed,
                "demo_hours_elapsed": round(self.clock.demo_hours(self._started_ts, now), 2),
                "timestamp": self.clock.iso(now),
                "history": hist,
            }
            if host is not None:
                out["host"] = host
            return out

    def set_services(self, host: str, services: list[dict[str, Any]]) -> dict[str, Any]:
        """What runs on a machine (its agent reports it every minute): name, port, protocol, process."""
        with self.lock:
            self._host_seen.setdefault(host, self.clock.now())
            self._host_services[host] = {"services": services[:200], "at": self.clock.iso(self.clock.now())}
            return {"ok": True, "services": len(self._host_services[host]["services"])}

    def _services_with_incidents(self, host: str, incs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """The machine's services, each with its open incidents; a service named only by an incident is listed too."""
        out = [dict(x) for x in (self._host_services.get(host) or {}).get("services", [])]
        for svc in out:
            svc["open_incidents"] = 0
        for inc in incs:
            name = inc.get("service")
            if not name or inc["status"] not in RISK_STATUSES:
                continue
            svc = next((x for x in out if x.get("name") == name), None)
            if svc is None:
                svc = {"name": name, "port": None, "proto": None, "process": None, "open_incidents": 0}
                out.append(svc)
            svc["open_incidents"] += 1
        return out

    def machines(self) -> list[dict[str, Any]]:
        """Every machine SentrAI has heard from or opened an incident for, worst first."""
        with self.lock:
            now = self.clock.now()
            self._compute(now)
            silent = {c["collector"] for c in self.watchdog.collectors.values() if c["silent"]}
            names = {*self._host_seen, *(_host(i) for i in self.incidents.values())}
            out = []
            for h in names:
                r = self._host_risk.get(h) or _score(0.0)
                incs = [i for i in self.incidents.values() if _host(i) == h]
                seen = self._host_seen.get(h)
                out.append({
                    "host": h,
                    "risk_index": r["risk_index"],
                    "band": r["band"],
                    "raw_score": r["raw_score"],
                    "open_incidents": sum(1 for i in incs if i["status"] in RISK_STATUSES),
                    "contained_incidents": sum(1 for i in incs if i["status"] == "contained"),
                    "blocked": len(self.blocklist(h)["ips"]),
                    "last_seen": self.clock.iso(seen) if seen is not None else None,
                    "silent": h in silent,
                    "services": self._services_with_incidents(h, incs),
                    "services_at": (self._host_services.get(h) or {}).get("at"),
                    "sessions": self.admins.live_count(h, now),  # people signed in right now (admins.py)
                })
            out.sort(key=lambda m: (-m["risk_index"], m["host"]))
            return out

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
                return {"target": target, "answer": f"{target} is not in any SentrAI containment record."}
            return {"target": target, "incidents": ids, "answer": "\n\n".join(self.why(i) for i in ids)}

    def agents_status(self) -> list[dict[str, Any]]:
        out = []
        for a in self.all_agents():
            st = a.status()
            if isinstance(a, LayerAgent):
                st["analyzed"] = a.analyzed
            out.append(st)
        out += self.extensions.agents()  # TypeSafe's Jev, when it is added
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
            self.classifier.reset()
            self.responders.reset()
            self.watchdog.reset()
            self.admins.forget_sessions()
            self.clock._offset = 0.0
            self.store.forget()
            self._init_state()
            self.scribe.record(self.name, "demo_reset", {"archived_chain": str(archived) if archived else None,
                                                         **self._config_summary()})
            return {"ok": True, "archived_chain": str(archived) if archived else None}
