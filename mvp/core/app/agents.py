"""Specialist agents (design doc section 12). Deterministic Python classes; no LLM calls.

Saguaro (orchestrator) lives in saguaro.py and calls these in turn:
  Root / Reservoir / AreoleLinux / AreoleWin / SpineNet  -> analyze events, propose playbooks
  Needle   -> two-key reviewer for every autonomous action
  Areole*  -> the only agents that execute, through the responders in responders.py
  Watchdog -> collector heartbeats
  Scribe   -> hash-chained audit + negligence reports
  HelpDesk -> answers "why" questions from incident data
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .audit import AuditLog, canonical
from .classifier import Classification, ClassifierChain
from .clock import DemoClock
from .responders import Responders

if TYPE_CHECKING:
    from .config import Settings

# category -> ordered playbook steps: (action type, incident field or literal target)
PLAYBOOKS: dict[str, list[tuple[str, str]]] = {
    "brute_force": [("block_ip", "@src_ip"), ("lock_user", "@user"), ("rate_limit", "/login")],
    "sql_injection": [("waf_rule", "sqli-signature"), ("block_ip", "@src_ip")],
    "xss": [("waf_rule", "xss-signature"), ("block_ip", "@src_ip")],
    "port_scan": [("block_ip", "@src_ip")],
    "privilege_escalation": [("kill_process", "@host"), ("block_ip", "@src_ip"), ("lock_user", "@user")],
    "data_exfiltration": [("block_ip", "@src_ip"), ("lock_user", "@user")],
    "misconfiguration": [("revoke_public_acl", "@host")],
}

ACTION_TEXT = {
    "block_ip": "block {t}",
    "lock_user": "lock account '{t}'",
    "rate_limit": "rate-limit {t}",
    "waf_rule": "add WAF rule ({t})",
    "kill_process": "kill the spawned shell on {t}",
    "revoke_public_acl": "revoke public ACL on {t}",
}

EXPLAIN = {
    "brute_force": "{n} failed logins from {src} against account '{user}' on {host}: a password-guessing (brute force) pattern.",
    "sql_injection": "A request from {src} to {host} carried SQL injection syntax (e.g. ' OR 1=1 / UNION SELECT), an attempt to read or alter the database.",
    "xss": "A request from {src} to {host} carried script markup (cross-site scripting), an attempt to run code in other users' browsers.",
    "port_scan": "{src} probed many ports on {host} (port scan), usually reconnaissance before an attack.",
    "privilege_escalation": "The application on {host} reported a shell being spawned (request from {src}). The endpoint is simulated and executed nothing, but in production this means remote code execution.",
    "data_exfiltration": "A bulk export of member data was requested from {host} by {src} (user '{user}'), possible data theft of PII.",
    "misconfiguration": "An insecure configuration was found on {host} (public access / open admin port / default password).",
}


@dataclass
class Proposal:
    type: str
    target: str
    proposed_by: str

    def describe(self) -> str:
        return ACTION_TEXT.get(self.type, self.type + " {t}").format(t=self.target)


@dataclass
class Review:
    approved: bool
    reasoning: str
    approved_proposals: list[Proposal] = field(default_factory=list)
    denied: list[dict[str, str]] = field(default_factory=list)


class Agent:
    name = "Agent"
    role = ""
    can_execute = False

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "role": self.role, "can_execute": self.can_execute}


class LayerAgent(Agent):
    layers: tuple[str, ...] = ()
    role = "layer analyst (propose only)"

    def __init__(self, classifier: ClassifierChain) -> None:
        self.classifier = classifier
        self.analyzed = 0

    def analyze(self, event: dict[str, Any], now: float) -> Classification:
        self.analyzed += 1
        return self.classifier.classify(event, now)

    def propose(self, incident: dict[str, Any], ttl_hours: float) -> list[Proposal]:
        out: list[Proposal] = []
        for atype, spec in PLAYBOOKS.get(incident["category"], []):
            target = incident.get(spec[1:]) if spec.startswith("@") else spec
            if target:
                out.append(Proposal(atype, str(target), self.name))
        return out

    @staticmethod
    def recommended_text(proposals: list[Proposal], ttl_hours: float) -> str:
        if not proposals:
            return "Investigate manually; no allowlisted playbook applies."
        parts = [p.describe() for p in proposals]
        text = ", ".join(parts[:-1]) + (" and " if len(parts) > 1 else "") + parts[-1]
        return f"{text[0].upper()}{text[1:]} for {ttl_hours:g} h"

    @staticmethod
    def explain(incident: dict[str, Any]) -> str:
        tmpl = EXPLAIN.get(incident["category"], "Suspicious activity on {host}.")
        return tmpl.format(
            n=len(incident.get("event_ids", [])),
            src=incident.get("src_ip") or "an unknown source",
            user=incident.get("user") or "n/a",
            host=incident.get("host") or "an unknown host",
        )


class Root(LayerAgent):
    name = "Root"
    layers = ("web",)
    role = "web layer: web/WAF logs, proposes WAF rules"


class Reservoir(LayerAgent):
    name = "Reservoir"
    layers = ("db",)
    role = "database/storage layer: DB audit, bulk exports"


class SpineNet(LayerAgent):
    name = "SpineNet"
    layers = ("network", "cloud")
    role = "network/scanner layer (stub: signature rules only)"


class Areole(LayerAgent):
    """OS agents. The only executors: they build the action record and hand it to the
    responder for its type (responders.py). No firewall, shell or OS changes are made unless
    the operator opts in to real firewall blocking (firewall.py, dry run by default)."""

    layers = ("os",)
    can_execute = True
    role = "OS layer; runs allowlisted playbooks (app-level blocklist only)"

    def __init__(self, classifier: ClassifierChain, responders: Responders) -> None:
        super().__init__(classifier)
        self.responders = responders
        self.executed = 0

    def apply(self, proposal: Proposal, incident_id: str, action_id: str, mode: str, approved_by: str,
              now: float, clock: DemoClock, ttl_hours: float, snapshot_hash: str) -> dict[str, Any]:
        responder = self.responders.for_type(proposal.type)  # raises if nothing handles it
        self.executed += 1
        expires_ts = now + clock.real_seconds(ttl_hours)
        action = {
            "action_id": action_id,
            "incident": incident_id,
            "type": proposal.type,
            "target": proposal.target,
            "ttl_hours": ttl_hours,
            "expires_at": clock.iso(expires_ts),
            "mode": mode,
            "approved_by": approved_by,
            "status": "active",
            "snapshot_hash": snapshot_hash,
            "applied_at": clock.iso(now),
            "executed_by": self.name,
            "proposed_by": proposal.proposed_by,
            "enforcement": responder.enforcement,
            "verified": None,
            "_expires_ts": expires_ts,
        }
        action["verified"] = responder.apply(action)
        return action


class AreoleLinux(Areole):
    name = "AreoleLinux"


class AreoleWin(Areole):
    name = "AreoleWin"


class Needle(Agent):
    name = "Needle"
    role = "reviewer: two-key approval for every autonomous action"

    def __init__(self, min_confidence: float, allowlist: set[str], protected_ips: set[str],
                 protected_users: set[str] | None = None) -> None:
        self.min_confidence = min_confidence
        self.allowlist = allowlist
        self.protected_ips = protected_ips
        self.protected_users = protected_users or set()

    def screen(self, proposals: list[Proposal]) -> tuple[list[Proposal], list[dict[str, str]]]:
        """Splits proposals into (allowed, denied): allowlisted type and not a protected target."""
        ok: list[Proposal] = []
        denied: list[dict[str, str]] = []
        for p in proposals:
            why = ("not in allowlist" if p.type not in self.allowlist
                   else "protected asset" if p.type == "block_ip" and p.target in self.protected_ips
                   else "protected account" if p.type == "lock_user" and p.target in self.protected_users
                   else None)
            if why:
                denied.append({"type": p.type, "target": p.target, "why": why})
            else:
                ok.append(p)
        return ok, denied

    def review(self, incident: dict[str, Any], proposals: list[Proposal], risk_index: int, threshold: int) -> Review:
        conf = incident["ai_confidence"]
        if incident.get("needs_review"):
            return Review(False, f"DENY: {incident['id']} is flagged 'needs review' (uncertain classification, "
                                 f"malicious p={incident.get('malicious_probability')}); a human must decide.")
        if conf < self.min_confidence:
            return Review(False, f"DENY: AI confidence {conf} < {self.min_confidence}; autonomous action not justified.")
        if risk_index < threshold:
            return Review(False, f"DENY: risk index {risk_index} is below threshold {threshold}.")
        ok, denied = self.screen(proposals)
        if not ok:
            return Review(False, "DENY: no allowlisted action remains after review.", [], denied)
        reasoning = (
            f"APPROVE: risk {risk_index} >= threshold {threshold}; confidence {conf} >= {self.min_confidence}; "
            f"classified by {incident['classified_by']}; operator has not acknowledged; "
            f"{len(ok)} allowlisted action(s) with TTL: " + "; ".join(p.describe() for p in ok) + "."
        )
        return Review(True, reasoning, ok, denied)


class Watchdog(Agent):
    name = "Watchdog"
    role = "collector heartbeats; flags silent collectors"

    def __init__(self, silence_s: float) -> None:
        self.silence_s = silence_s
        self.collectors: dict[str, dict[str, Any]] = {}

    def reset(self) -> None:
        self.collectors.clear()

    def observe(self, collector: str, now: float, heartbeat: bool) -> dict[str, Any] | None:
        """Returns a 'recovered' record if a flagged collector came back."""
        c = self.collectors.get(collector)
        if c is None:
            if not heartbeat:
                return None  # only collectors that registered via heartbeat are watched
            c = self.collectors[collector] = {"collector": collector, "last_seen": now, "silent": False}
        c["last_seen"] = now
        if c["silent"]:
            c["silent"] = False
            return {"collector": collector, "status": "recovered"}
        return None

    def check(self, now: float) -> list[dict[str, Any]]:
        flagged = []
        for c in self.collectors.values():
            silent_for = now - c["last_seen"]
            if not c["silent"] and silent_for > self.silence_s:
                c["silent"] = True
                flagged.append({"collector": c["collector"], "silent_for_s": round(silent_for, 1)})
        return flagged

    def status(self) -> dict[str, Any]:
        s = super().status()
        s["collectors"] = [
            {"collector": c["collector"], "silent": c["silent"], "last_seen_ts": c["last_seen"]}
            for c in self.collectors.values()
        ]
        return s


class Scribe(Agent):
    name = "Scribe"
    role = "auditor: hash-chained log and negligence reports (write-only log)"

    def __init__(self, audit: AuditLog, clock: DemoClock) -> None:
        self.audit = audit
        self.clock = clock

    def record(self, agent: str, rtype: str, data: dict[str, Any]) -> dict[str, Any]:
        payload = {"agent": agent, **{k: v for k, v in data.items() if not k.startswith("_")}}
        return self.audit.append(rtype, payload, self.clock.now_iso())

    @staticmethod
    def snapshot_hash(state: dict[str, Any]) -> str:
        return hashlib.sha256(canonical(state).encode("utf-8")).hexdigest()


class HelpDesk(Agent):
    name = "HelpDesk"
    role = "answers operator questions ('why was this blocked?') from incident data"

    def why(self, incident: dict[str, Any], risk_now: int, threshold: int) -> str:
        lines = [
            f"{incident['id']} ({incident['category']}, {incident['severity']}) was opened at {incident['opened_at']}.",
            f"Why: {incident['explanation']}",
            f"Classified by {incident['classified_by']} with AI confidence {incident['ai_confidence']} "
            f"-> {incident['points']} points (base {incident['base_points']} x confidence x asset criticality "
            f"{incident.get('asset_criticality', 1.0)}), plus inaction penalty {incident['inaction_penalty']}.",
        ]
        if incident.get("needs_review"):
            lines.append("The classifier was uncertain, so it is marked 'needs review' and will never be auto-contained.")
        if incident["acked"]:
            lines.append(f"Acknowledged by {incident['acked_by']} at {incident['acked_at']}.")
        else:
            lines.append("Nobody has acknowledged it yet.")
        for a in incident["actions"]:
            who = "Needle (autonomous, two-key approval)" if a["mode"] == "autonomous" else a["approved_by"]
            lines.append(
                f"Action {a['action_id']}: {a['type']} {a['target']} approved by {who}, status {a['status']}, "
                f"expires {a['expires_at'] or 'never (made permanent)'}."
            )
        if any(a["mode"] == "autonomous" for a in incident["actions"]):
            lines.append(
                f"Autonomous containment happens only when the organization's risk index reaches the threshold "
                f"({threshold}) and the incident is unacknowledged. Current risk index: {risk_now}."
            )
        lines.append(f"Recommended: {incident['recommended_action']}.")
        lines.append(f"To undo: POST /incidents/{incident['id']}/rollback with a justification.")
        return "\n".join(lines)
