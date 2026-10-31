"""Fake SentrAI core for UI development (implements the endpoints in mvp/CONTRACT.md).

NOT the real core. In-memory, single process, plays a scripted demo scenario:
  t≈4 s   brute_force incident opens (risk ≈ 40, amber) + notification
  t≈12 s  root work on web-01 from a sign-in SentrAI does not know ("was this you?": This was me / Not me)
  ...     nobody acks -> inaction penalty climbs (fast demo clock)
  t≈40 s  sql_injection incident opens -> risk crosses 80 -> Countersign approves
          autonomous containment (block IP, lock user) + evidence report
Run:  .venv\\Scripts\\python dev\\fake_core.py   (serves http://127.0.0.1:8900)
Env:  FAKE_CORE_PORT (8900, so it never collides with the real core on 8000), FAKE_DEMO_SPEED (120 = 30 real s per demo hour),
      FAKE_TTL_SECONDS (300 real s before containment expires),
      FAKE_AUTOPLAY (1), FAKE_THRESHOLD (80), FAKE_RISK_SCOPE (host: a central panel with two joined machines; fleet)
Extra dev-only endpoints: POST /dev/trigger/{category}?src_ip=..&user=.., POST /dev/reset,
      POST /dev/extensions/managed?on=1 (act as if the server's SENTRAI_EXTENSIONS decides),
      GET /dev/admin-sign-ins (every dashboard sign-in reported to POST /admins/sign-in)
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import threading
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import uvicorn
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

sys.path.append(str(Path(__file__).resolve().parents[2]))
import sentrai_extensions as se  # noqa: E402  the real manifests, so the Extensions page shows what ships

SGT = timezone(timedelta(hours=8))
DEMO_SPEED = float(os.environ.get("FAKE_DEMO_SPEED", "120"))
THRESHOLD = int(os.environ.get("FAKE_THRESHOLD", "80"))
AUTOPLAY = os.environ.get("FAKE_AUTOPLAY", "1") != "0"
SLA_HOURS = 2.0
TTL_SECONDS = float(os.environ.get("FAKE_TTL_SECONDS", "300"))
BASELINE_RAW = 5.0
RISK_SCOPE = "fleet" if os.environ.get("FAKE_RISK_SCOPE", "host") == "fleet" else "host"

SEVERITY = {
    "brute_force": ("high", 30), "sql_injection": ("high", 40), "xss": ("medium", 20),
    "port_scan": ("medium", 15), "privilege_escalation": ("critical", 60),
    "data_exfiltration": ("critical", 70), "misconfiguration": ("medium", 20), "log_tampering": ("critical", 55),
    "malware": ("critical", 65), "prompt_injection": ("critical", 60), "staff_report": ("medium", 20),
    "unauthorised_admin": ("critical", 60), "benign": ("low", 0),
}
ADMIN = "unauthorised_admin"  # root work from a sign-in SentrAI does not know: the person says This was me or Not me
WAS_THIS_YOU_BUTTONS = [{"label": "This was me", "action": "mine"}, {"label": "Not me: block it", "action": "approve"},
                        {"label": "Acknowledge", "action": "ack"}]
PLAYBOOK = {
    "brute_force": [("block_ip", "src_ip"), ("lock_user", "user"), ("rate_limit", "/login")],
    "sql_injection": [("waf_rule", "/search UNION/OR 1=1"), ("block_ip", "src_ip")],
    "xss": [("waf_rule", "script-tag filter")],
    "port_scan": [("block_ip", "src_ip")],
    "privilege_escalation": [("kill_process", "sh (pid 4242)"), ("block_ip", "src_ip")],
    "data_exfiltration": [("block_ip", "src_ip"), ("lock_user", "user")],
    "misconfiguration": [("revoke_public_acl", "s3://demo-bucket")],
    "log_tampering": [("block_ip", "src_ip")],
    "malware": [],
    "staff_report": [],
    "prompt_injection": [("waf_rule", "prompt-injection filter"), ("block_ip", "src_ip")],
    "unauthorised_admin": [("block_ip", "src_ip"), ("lock_user", "user")],
}
RECOMMEND = {
    "brute_force": "Block {src_ip} for 2 h, lock account '{user}' and rate-limit /login",
    "sql_injection": "Add WAF rule for UNION/OR-1=1 payloads on /search and block {src_ip} for 2 h",
    "xss": "Add WAF rule stripping <script> payloads on /search",
    "port_scan": "Block {src_ip} for 2 h",
    "privilege_escalation": "Kill the spawned shell and block {src_ip}",
    "data_exfiltration": "Revoke session of '{user}', block {src_ip}",
    "misconfiguration": "Remove the public ACL and enable default encryption",
    "log_tampering": "Block {src_ip} for 2 h and check the host for compromise",
    "malware": "Check the file or program and quarantine it from the threat scan",
    "staff_report": "Read the report under Staff reports and close it with a note",
    "prompt_injection": "Add a WAF rule for prompt-injection text and block {src_ip} for 2 h",
    "unauthorised_admin": "Not me: block {src_ip} for 2 h and lock account '{user}'. This was me: SentrAI learns the "
                          "sign-in and stops asking",
}

app = FastAPI(title="SentrAI FAKE core (dev only)")
lock = threading.RLock()


def now() -> datetime:
    return datetime.now(SGT)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


class State:
    def __init__(self) -> None:
        self.started = time.monotonic()
        self.incidents: dict[str, dict] = {}
        self.audit: list[dict] = []
        self.notifications: list[dict] = []
        self.history: list[dict] = []
        self.reports: dict[str, dict] = {}
        self.seq_inc = 80
        self.seq_act = 0
        self.seq_ntf = 0
        self.script_done: set[str] = set()
        self.chat: list[dict] = []
        self.protection: dict = {"monitor_only": False, "changed_at": None, "changed_by": None, "reason": None}
        self.scan: dict | None = None
        self.log_sources: list[dict] = []
        self.threats: dict | None = None
        self.deps: dict | None = None  # the panel's own package check
        self.quarantine: list[dict] = []
        self.backups: list[dict] = []
        self.jobs: list[dict] = []  # scans/backups asked of a machine; "done" a few seconds later
        self.pending: list[dict] = []  # Scout proposals; seed one with POST /_fake/scout-proposal
        # Machines joined to this (pretend) central panel: web-01 has the scripted incidents, office-pc is quiet.
        self.agents: dict[str, dict] = {
            "a1b2c3": {"agent_id": "a1b2c3", "host": "web-01", "joined_at": iso(now()), "invited_by": "erick",
                       "last_seen": iso(now()), "revoked_at": None, "revoked_by": None},
            "d4e5f6": {"agent_id": "d4e5f6", "host": "office-pc", "joined_at": iso(now()), "invited_by": "erick",
                       "last_seen": iso(now()), "revoked_at": None, "revoked_by": None, "offline_total": 1,
                       "offline": {"from": iso(now() - timedelta(minutes=50)), "to": iso(now() - timedelta(minutes=20)),
                                   "scored": 42, "local_blocks": 1, "reported_at": iso(now() - timedelta(minutes=20))}},
        }
        self.staff_reports: list[dict] = []
        self.admins: dict = fake_admins()  # the administrators (core admins.py): known ones, sign-ins, root work
        self.sign_in_reports: list[dict] = []  # every POST /admins/sign-in, vouched or not (GET /dev/admin-sign-ins)


# ---- the administrators (core admins.py): who is signed in, who is known, "This was me" ----
ADMIN_KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"  # an example fingerprint, not anyone's key
KEY_RX = re.compile(r"^(SHA256|MD5):[A-Za-z0-9+/=:]{8,}$")


def short_key(fp: str | None) -> str:
    return fp if not fp or len(fp) <= 20 else fp[:19] + "…"


def fake_admins() -> dict:
    """What the real core keeps in people/admins.json: a known administrator at work on web-01 (taught key and
    address, a learned account), a setting from ADMIN_IPS / ADMIN_ACCOUNTS, and one dashboard sign-in vouching."""
    t = now()
    return {
        "on": True, "next": 1,
        "accounts": [{"account": "erick", "host": "web-01", "how": "learned", "by": "a trusted sign-in",
                      "at": iso(t - timedelta(hours=3)), "last_seen": iso(t - timedelta(minutes=12))},
                     {"account": "deploy", "host": "*", "how": "setting", "by": "ADMIN_ACCOUNTS", "at": None}],
        "addresses": [{"address": "203.0.113.5", "how": "taught", "by": "erick", "at": iso(t - timedelta(days=2)),
                       "label": "Erick's home", "last_seen": iso(t - timedelta(minutes=12))},
                      {"address": "198.51.100.20", "how": "learned", "by": f"key {short_key(ADMIN_KEY)}",
                       "at": iso(t - timedelta(days=1)), "label": "", "last_seen": iso(t - timedelta(hours=20))},
                      {"address": "192.0.2.0/24", "how": "setting", "by": "ADMIN_IPS", "at": None, "label": "",
                       "last_seen": None}],
        "keys": [{"fingerprint": ADMIN_KEY, "type": "ED25519", "users": ["erick"], "how": "taught", "by": "erick",
                  "at": iso(t - timedelta(days=2)), "last_seen": iso(t - timedelta(minutes=12))}],
        "sign_ins": [{"address": "203.0.113.8", "email": "erick@example.com", "role": "Owner",
                      "at": iso(t - timedelta(hours=1)), "until": iso(t + timedelta(hours=11))}],
        "sessions": [{"session": "s1", "host": "web-01", "user": "erick", "via": "ssh", "address": "203.0.113.5",
                      "tty": "pts/0", "key": ADMIN_KEY, "key_type": "ED25519", "method": "publickey", "trust": "trusted",
                      "why": f"known SSH key {short_key(ADMIN_KEY)} (taught by erick)", "since": iso(t - timedelta(minutes=40)),
                      "last_seen": iso(t - timedelta(minutes=12)), "ended": None, "preexisting": False, "actions": 2,
                      "incident": None}],
        "activity": [{"at": iso(t - timedelta(minutes=12)), "host": "web-01", "user": "erick", "via": "ssh",
                      "address": "203.0.113.5", "session": "s1", "what": "sudo: /usr/bin/systemctl stop sentrai-core",
                      "flagged_as": "log_tampering",
                      "reason": "Log tampering: stopping the SentrAI core silences the record"},
                     {"at": iso(t - timedelta(minutes=35)), "host": "web-01", "user": "erick", "via": "ssh",
                      "address": "203.0.113.5", "session": "s1", "what": "sudo: /usr/bin/apt update",
                      "flagged_as": None, "reason": None}],
        "suspect": [],
        "settings": {"session_hours": 12.0, "signin_hours": 12.0, "learn": True},
    }


def admin_session(host: str, user: str, ip: str | None, trust: str, why: str) -> dict:
    """A sign-in seen on a machine, as the core's Session.public()."""
    A = S.admins
    A["next"] += 1
    s = {"session": f"s{A['next']}", "host": host, "user": user, "via": "ssh", "address": ip, "tty": f"pts/{A['next']}",
         "key": None, "key_type": None, "method": "password", "trust": trust, "why": why, "since": iso(now()),
         "last_seen": iso(now()), "ended": None, "preexisting": False, "actions": 0, "incident": None}
    A["sessions"].append(s)
    return s


def admins_view(host: str | None = None) -> dict:
    """GET /admins: with host, that machine's sessions, root work and accounts (addresses and keys are for all)."""
    A, t = S.admins, now()
    out = {k: v for k, v in A.items() if k != "next"}
    out["sessions"] = [s for s in A["sessions"] if not s["ended"] and host in (None, s["host"])]
    out["activity"] = [a for a in A["activity"] if host in (None, a["host"])]
    out["accounts"] = [a for a in A["accounts"] if host is None or a["host"] in ("*", host)]
    out["sign_ins"] = [s for s in A["sign_ins"] if datetime.fromisoformat(s["until"]) > t]
    out["suspect"] = [s for s in A["suspect"] if datetime.fromisoformat(s["until"]) > t]
    return out


def teach(inc: dict, op: str) -> list[str]:
    """"This was me": the incident's sign-in facts become known administrator facts, in words."""
    A, actor, learned, t = S.admins, inc.get("actor") or {}, [], iso(now())
    ip, key, user, host = actor.get("address") or inc.get("src_ip"), actor.get("key"), actor.get("user"), inc["host"]
    if ip and not any(x["address"] == ip and x["how"] in ("setting", "taught") for x in A["addresses"]):
        A["addresses"] = [x for x in A["addresses"] if x["address"] != ip]
        A["addresses"].append({"address": ip, "how": "taught", "by": op, "at": t, "label": "", "last_seen": t})
    if ip:
        learned.append(f"address {ip}")
        A["suspect"] = [s for s in A["suspect"] if s["address"] != ip]
    if key:
        if not any(k["fingerprint"] == key and k["how"] in ("setting", "taught") for k in A["keys"]):
            A["keys"] = [k for k in A["keys"] if k["fingerprint"] != key]
            A["keys"].append({"fingerprint": key, "type": actor.get("key_type"), "users": [user] if user else [],
                              "how": "taught", "by": op, "at": t, "last_seen": t})
        learned.append(f"SSH key {short_key(key)}")
    if user:
        if not any(a["account"] == user and a["host"] in ("*", host) and a["how"] in ("setting", "taught") for a in A["accounts"]):
            A["accounts"] = [a for a in A["accounts"] if not (a["account"] == user and a["host"] == host)]
            A["accounts"].append({"account": user, "host": host, "how": "taught", "by": op, "at": t, "last_seen": t})
        learned.append(f"account {user} on {host}")
    for s in A["sessions"]:
        if s["session"] == actor.get("session"):
            s.update(trust="trusted", why=f"{op} said this was them")
    return learned


def distrust(inc: dict, op: str) -> None:
    """"Not me": the sign-in is an intruder's, and its address is suspect for a while."""
    A, actor = S.admins, inc.get("actor") or {}
    ip = actor.get("address") or inc.get("src_ip")
    for s in A["sessions"]:
        if s["session"] == actor.get("session"):
            s.update(trust="suspect", why=f"{op} said this was not them")
    if ip:
        A["suspect"] = [s for s in A["suspect"] if s["address"] != ip]
        A["suspect"].append({"address": ip, "why": f"{op} said a sign-in from it was not them",
                             "until": iso(now() + timedelta(hours=12))})
        A["sign_ins"] = [s for s in A["sign_ins"] if s["address"] != ip]
    audit("admin_distrusted", "Warden", incident=inc["id"], operator=op, address=ip, forgotten=[], actor=actor)


def close_as_mine(inc: dict, op: str, note: str) -> None:
    for act in inc["actions"]:
        if act["status"] == "active":
            act["status"] = "rolled_back"
            audit("action_rolled_back", "Garrison-Linux", incident=inc["id"], action_id=act["action_id"], operator=op,
                  reason="the sign-in was the administrator's own")
    inc.update(status="resolved", resolved_by=op, resolution=note, acked=True, acked_by=inc.get("acked_by") or op,
               closed_at=iso(now()))
    inc.setdefault("decisions", []).append({"operator": op, "decision": "mine", "justification": note, "at": iso(now())})
    inc.setdefault("timeline", []).append({"ts": iso(now()), "kind": "admin_confirmed",
                                           "text": f"{op} said this was them: {note}"})


S = State()


def demo_hours(since: datetime) -> float:
    return (now() - since).total_seconds() * DEMO_SPEED / 3600.0


def audit(rtype: str, agent: str, **data) -> None:
    prev = S.audit[-1]["hash"] if S.audit else "0" * 64
    rec = {"seq": len(S.audit) + 1, "ts": iso(now()), "type": rtype, "data": {"agent": agent, **data},
           "prev_hash": prev}
    rec["hash"] = hashlib.sha256((prev + json.dumps(rec["data"], sort_keys=True) + rec["ts"]).encode()).hexdigest()
    S.audit.append(rec)


def notify(inc: dict, kind: str, text: str) -> None:
    S.seq_ntf += 1
    S.notifications.append({
        "id": f"ntf-{S.seq_ntf:04d}", "incident_id": inc["id"], "kind": kind, "severity": inc["severity"],
        "risk_index": risk_index(), "text": text, "recommended_action": inc["recommended_action"],
        "created_at": iso(now()), "delivered": False, "channel": None, "message_id": None,
        **({"buttons": list(WAS_THIS_YOU_BUTTONS)} if inc["category"] == ADMIN else {}),
    })
    audit("notification_queued", "Scribe", incident=inc["id"], kind=kind)


def raw_score() -> float:
    raw = BASELINE_RAW
    for inc in S.incidents.values():
        if inc["status"] in ("open", "acknowledged"):
            raw += inc["points"] + inc["inaction_penalty"]
        elif inc["status"] == "contained":
            raw += 0.2 * inc["points"]
    return raw


def risk_index() -> int:
    return round(100 * (1 - math.exp(-max(0.0, raw_score()) / 60)))


def band(idx: int) -> str:
    return "green" if idx < 30 else "amber" if idx < 60 else "red" if idx < 80 else "critical"


def open_incident(category: str, src_ip: str, user: str, conf: float, crit: float, by: str) -> dict:
    sev, base = SEVERITY[category]
    S.seq_inc += 1
    iid = f"RSK-2026-{S.seq_inc:03d}"
    inc = {
        "id": iid, "category": category, "severity": sev, "base_points": base, "ai_confidence": conf,
        "points": round(base * conf * crit, 1), "classified_by": by, "src_ip": src_ip, "user": user,
        "host": "web-01", "layer": "web", "opened_at": iso(now()), "status": "open", "acked": False,
        "acked_by": None, "acked_at": None, "inaction_penalty": 0, "sla_breached": False,
        "recommended_action": RECOMMEND[category].format(src_ip=src_ip, user=user),
        "explanation": f"{category.replace('_', ' ').capitalize()} activity from {src_ip} against '{user}' on web-01.",
        "actions": [], "event_ids": [f"evt-{int(time.time())}-{i:03d}" for i in range(3)],
        "owner": ROUTING["contacts"][0]["name"], "owner_id": "on_duty", "backup": ROUTING["contacts"][1]["name"],
        "backup_id": "team_lead", "assigned_by": "routing: High", "route": "High", "notify": [],
        "escalation_level": 0, "escalations": [], "resolved_by": None, "resolution": None, "timeline": [],
    }
    S.incidents[iid] = inc
    if category == ADMIN:  # root work from a sign-in SentrAI does not know: who did it, and why it did not know them
        why = (f"sign-in with password from {src_ip} (no key SentrAI knows): neither the address nor the key is known "
               "as an administrator's")
        s = admin_session("web-01", user, src_ip, "unknown", why)
        s.update(actions=1, incident=iid)
        inc.update(layer="os", needs_review=True, title="Root access from an unrecognised sign-in",
                   actor={"host": "web-01", "user": user, "via": "ssh", "address": src_ip, "key": None,
                          "session": s["session"], "trust": "unknown", "why": why, "since": s["since"]},
                   explanation=(f"Administrator (root) work on web-01 by '{user}' from a sign-in SentrAI does not know as "
                                "an administrator's. If this was you or a colleague, press This was me and SentrAI will know this sign-in from "
                                "now on. If nobody you know was signed in, press Not me: the address is blocked and the "
                                "machine should be treated as possibly taken over."),
                   next_steps=["If this was you or a colleague, press This was me: SentrAI learns the sign-in and stops asking.",
                               "If nobody you know was signed in, press Not me: the address is blocked. Treat the machine "
                               "as possibly taken over and call your technical staff.",
                               "Do not switch the machine off; it keeps the evidence."])
    audit("classification", "Jev" if by == "jev" else "Warden", incident=iid, category=category, confidence=conf)
    audit("incident_opened", "Warden", incident=iid, category=category, risk_index=risk_index(), actor=inc.get("actor"))
    if category == ADMIN:
        notify(inc, "was_this_you", f"Root access on web-01 by {user} from {src_ip}, a sign-in SentrAI does not know. "
                                    "Was this you?")
    else:
        notify(inc, "incident_opened", f"{category.replace('_', ' ').capitalize()} on web-01 from {src_ip}")
    return inc


def apply_containment(inc: dict, mode: str, approver: str) -> None:
    snap = hashlib.sha256(f"snapshot-{inc['id']}-{time.time()}".encode()).hexdigest()
    audit("snapshot", "Garrison-Linux", incident=inc["id"], snapshot_hash=snap[:16])
    if mode == "autonomous":
        audit("action_approved", "Countersign", incident=inc["id"], summary=f"Two-key review passed for {inc['id']}")
    for atype, tgt in PLAYBOOK.get(inc["category"], []):
        S.seq_act += 1
        target = inc.get(tgt, tgt) if tgt in ("src_ip", "user") else tgt
        act = {"action_id": f"act-{S.seq_act:04d}", "incident": inc["id"], "type": atype, "target": target,
               "ttl_hours": 2, "mode": mode, "approved_by": approver, "status": "active", "snapshot_hash": snap}
        # expires_at in wall-clock: 2 demo hours
        act["expires_at"] = iso(now() + timedelta(seconds=TTL_SECONDS))
        inc["actions"].append(act)
        audit("action_applied", "Garrison-Linux", incident=inc["id"], target=target, summary=f"{atype} {target} (TTL 2 h)")
    inc["status"] = "contained"


def make_report(inc: dict) -> None:
    delivered = [n for n in S.notifications if n["incident_id"] == inc["id"] and n["delivered"]]
    first = delivered[0] if delivered else None
    rep = {
        "incident_id": inc["id"], "generated_at": iso(now()), "responsible": "Operator on duty (Shift Bravo)",
        "sla_hours": SLA_HOURS, "overdue_hours": round(max(0.0, demo_hours(datetime.fromisoformat(inc["opened_at"])) - SLA_HOURS), 1),
        "ack": inc["acked_by"] or "none",
        "delivered": f"{first['channel']} @ {first.get('delivered_at', '-')}" if first else "not delivered",
        "actions": inc["actions"], "chain_head": S.audit[-1]["hash"] if S.audit else None,
    }
    S.reports[inc["id"]] = rep
    audit("report_generated", "Scribe", incident=inc["id"], summary=f"Evidence report for {inc['id']}")


def report_md(rep: dict) -> str:
    inc = S.incidents[rep["incident_id"]]
    lines = [
        f"# Security Evidence Report · {inc['id']}",
        "",
        "> FAKE CORE output for UI development. Not evidence.",
        "",
        "| Field | Value |", "| --- | --- |",
        f"| Responsible entity | {rep['responsible']} |",
        f"| Category | {inc['category']} ({inc['severity']}) |",
        f"| SLA | {rep['sla_hours']} h, overdue by {rep['overdue_hours']} h |",
        f"| Proof of delivery | {rep['delivered']} (Ack: {rep['ack']}) |",
        f"| Forced action | {', '.join(a['type'] + ' ' + str(a['target']) for a in inc['actions']) or 'none'} |",
        f"| Hash-chain head | `{(rep['chain_head'] or '')[:24]}…` |",
        "", "## Timeline of inaction", "",
    ]
    for rec in S.audit:
        if rec["data"].get("incident") == inc["id"]:
            lines.append(f"- `{rec['ts'][11:19]}` **{rec['data'].get('agent')}** · {rec['type']}")
    lines += ["", "## Recommended action", "", inc["recommended_action"]]
    return "\n".join(lines) + "\n"


def tick() -> None:
    while True:
        with lock:
            elapsed = time.monotonic() - S.started
            if AUTOPLAY and elapsed > 4 and "bf" not in S.script_done:
                S.script_done.add("bf")
                open_incident("brute_force", "203.0.113.45", "admin", 0.94, 1.0, "jev")
            if AUTOPLAY and elapsed > 12 and "adm" not in S.script_done:
                S.script_done.add("adm")
                open_incident(ADMIN, "203.0.113.9", "erick", 1.0, 1.0, "rules")
            if AUTOPLAY and elapsed > 40 and "sqli" not in S.script_done:
                S.script_done.add("sqli")
                open_incident("sql_injection", "203.0.113.45", "admin", 1.0, 1.5, "rules")
            for inc in S.incidents.values():
                if inc["status"] == "open" and not inc["acked"]:
                    hrs = demo_hours(datetime.fromisoformat(inc["opened_at"]))
                    pen = min(30, 5 * int(hrs))
                    if pen != inc["inaction_penalty"]:
                        inc["inaction_penalty"] = pen
                        audit("risk_update", "Warden", incident=inc["id"], summary=f"Inaction penalty +{pen}")
                    if hrs > SLA_HOURS and not inc["sla_breached"]:
                        inc["sla_breached"] = True
                        audit("sla_breach", "Watchdog", incident=inc["id"], summary="SLA 2 h breached, no ack")
                        notify(inc, "reminder", f"REMINDER: {inc['id']} unacknowledged past SLA")
                for act in inc["actions"]:
                    if act["status"] == "active" and datetime.fromisoformat(act["expires_at"]) < now():
                        act["status"] = "expired"
                        audit("action_expired", "Watchdog", incident=inc["id"], target=act["target"])
            # "Was this you?" and other alerts a person must judge are never contained on their own.
            active = [i for i in S.incidents.values() if i["status"] in ("open", "acknowledged") and not i.get("needs_review")]
            if risk_index() >= THRESHOLD and active and not S.protection["monitor_only"]:
                S.history.append({"t": iso(now()), "risk_index": risk_index()})  # show the peak
                audit("threshold_crossed", "Warden", risk_index=risk_index(), summary=f"Risk {risk_index()} ≥ {THRESHOLD}")
                for inc in active:
                    apply_containment(inc, "autonomous", "Countersign")
                    make_report(inc)
                    notify(inc, "autonomous_action", f"Autonomous containment applied for {inc['id']}")
            if not S.history or (now() - datetime.fromisoformat(S.history[-1]["t"])).total_seconds() >= 1:
                S.history.append({"t": iso(now()), "risk_index": risk_index()})
                S.history = S.history[-600:]
        time.sleep(0.5)


def get_inc(iid: str) -> dict:
    inc = S.incidents.get(iid)
    if not inc:
        raise HTTPException(404, f"incident {iid} not found")
    return inc


@app.get("/health")
def health():
    return {"ok": True, "fake": True}


@app.post("/events")
def events(body=Body(...)):
    n = len(body) if isinstance(body, list) else 1
    return {"accepted": n, "risk_index": risk_index()}


@app.get("/risk")
def risk(host: str | None = None):
    """With ?host=, one machine's own score: the scripted incidents are all on web-01, the others stay at 0."""
    with lock:
        idx = risk_index() if host in (None, "web-01") else 0
        hist = S.history if host in (None, "web-01") else [{"t": p["t"], "risk_index": 0} for p in S.history]
        return {"risk_index": idx, "band": band(idx), "raw_score": round(raw_score(), 1), "threshold": THRESHOLD,
                "open_incidents": [i for i, v in S.incidents.items() if v["status"] in ("open", "acknowledged")
                                   and host in (None, v["host"])],
                "monitor_only": S.protection["monitor_only"], "history": hist, "risk_scope": RISK_SCOPE,
                **({"host": host} if host else {})}


@app.get("/incidents")
def incidents(host: str | None = None):
    with lock:
        return [i for i in S.incidents.values() if host is None or i["host"] == host]


@app.get("/machines")
def machines():
    with lock:
        idx = risk_index()
        for a in S.agents.values():
            if not a["revoked_at"]:
                a["last_seen"] = iso(now())
        out = []
        for h in sorted({"web-01", *(a["host"] for a in S.agents.values() if not a["revoked_at"])}):
            incs = [i for i in S.incidents.values() if i["host"] == h]
            hi = idx if h == "web-01" else 0
            out.append({"host": h, "risk_index": hi, "band": band(hi), "raw_score": 0.0,
                        "open_incidents": sum(i["status"] in ("open", "acknowledged") for i in incs),
                        "contained_incidents": sum(i["status"] == "contained" for i in incs),
                        "blocked": len(blocklist()["ips"]) if h == "web-01" else 0,
                        "sessions": sum(1 for s in S.admins["sessions"] if s["host"] == h and not s["ended"]),
                        "last_seen": iso(now()), "silent": False, "services_at": iso(now()),
                        "services": FAKE_SERVICES.get(h, []) if h != "web-01" else [
                            {**x, "open_incidents": sum(1 for i in incs if i["status"] in ("open", "acknowledged"))
                             if x["name"] == "web" else 0} for x in FAKE_SERVICES["web-01"]],
                        "hardware": fake_hardware(h)})
        return sorted(out, key=lambda m: -m["risk_index"])


def fake_hardware(host: str, t: float | None = None) -> dict:
    """A made-up hardware reading that moves a little each call (core hardware.py, GET /fleet/hardware)."""
    t = time.time() if t is None else t
    busy = host == "web-01"
    cpu = round(max(1.0, min(99.0, (38 if busy else 9) + 14 * math.sin(t / 97) + 6 * math.sin(t / 13))), 1)
    gib = 2 ** 30
    disk = 93.0 if busy else 61.0
    out = {"cpu": {"percent": cpu, "cores": 4 if busy else 8, "load": [round(cpu / 25, 2), 1.1, 0.9]},
           "memory": {"total": 8 * gib, "used": int(8 * gib * 0.62), "percent": 62.0},
           "swap": {"total": 2 * gib, "used": 0, "percent": 0.0},
           "disks": [{"mount": "/" if busy else "C:\\", "total": 80 * gib, "used": int(80 * gib * disk / 100), "percent": disk}]
           + ([{"mount": "/data", "total": 500 * gib, "used": 120 * gib, "percent": 24.0}] if busy else []),
           "net": {"sent": 81234567, "recv": 912345678, "sent_rate": round(2000 + 1500 * math.sin(t / 31), 1),
                   "recv_rate": round(15000 + 9000 * math.sin(t / 23), 1)},
           "temps": [{"label": "coretemp Package id 0", "current": 58.0, "high": 100.0},
                     {"label": "nvme Composite", "current": 41.0, "high": 84.8}] if busy else [],
           "uptime_s": 3 * 86400 + 4 * 3600 if busy else 26 * 3600, "os": "Linux 6.8.0" if busy else "Windows 11",
           "at": iso(datetime.fromtimestamp(t, timezone.utc)),
           "warnings": ["disk / is 93% full (limit 90%)"] if busy else []}
    return out


@app.get("/fleet/hardware")
def fleet_hardware(host: str):
    t = time.time()
    hist = []
    for k in range(119, -1, -1):
        r = fake_hardware(host, t - 30 * k)
        hist.append({"t": r["at"], "cpu": r["cpu"]["percent"], "memory": r["memory"]["percent"],
                     "disk": r["disks"][0]["percent"], "temp": (r["temps"] or [{}])[0].get("current"),
                     "net_in": r["net"]["recv_rate"], "net_out": r["net"]["sent_rate"]})
    return {"host": host, "latest": fake_hardware(host, t), "history": hist,
            "limits": {"alerts": True, "cpu": 90.0, "memory": 90.0, "disk": 90.0, "temp": 85.0, "for_min": 5.0}}


FAKE_SERVICES = {
    "web-01": [{"name": "sshd", "port": 22, "proto": "tcp", "process": "sshd"},
               {"name": "web", "port": 443, "proto": "tcp", "process": "nginx"},
               {"name": "mysql", "port": 3306, "proto": "tcp", "process": "mysqld"}],
    "office-pc": [{"name": "rdp", "port": 3389, "proto": "tcp", "process": "svchost.exe"}],
}


@app.get("/fleet/agents")
def fleet_agents():
    with lock:
        return list(S.agents.values())


@app.get("/fleet/panel")
def fleet_panel():
    return {"panel_url": os.environ.get("SENTRAI_PANEL_URL", "").rstrip("/"), "pin": ""}


@app.post("/fleet/join-codes")
def fleet_join_code(body: dict = Body(...)):
    with lock:
        audit("join_code_created", "Warden", operator=body.get("operator"), name=body.get("name"))
    return {"code": "K7QM-2XPA-9RTD", "expires_at": iso(now() + timedelta(hours=24)), "name": body.get("name") or None}


FAKE_JOB_SCAN = {"files_checked": 214, "counts": {"critical": 1, "high": 0, "medium": 1}, "findings": [
    {"path": "/var/www/html/uploads/img.php", "line": 1, "kind": "web_shell", "severity": "critical",
     "label": "PHP web shell (eval of request data)"},
    {"path": "/var/www/html/js/stats.js", "line": 40, "kind": "miner", "severity": "medium",
     "label": "Browser crypto-miner pool address"}]}


FAKE_DEPS = {"packages_checked": 312, "counts": {"critical": 0, "high": 1, "medium": 1, "low": 0, "no_fix_os": 4},
             "sources": [{"kind": "python", "ecosystem": "PyPI", "path": "/srv/app/.venv", "packages": 41},
                         {"kind": "os", "ecosystem": "Ubuntu:24.04:LTS", "path": "dpkg", "packages": 271}],
             "findings": [
                 {"id": "3f1c9a0b7d2e4f61", "kind": "python", "ecosystem": "PyPI", "name": "requests",
                  "version": "2.32.3", "fixed": "2.33.0", "severity": "high", "vuln_count": 1, "update": "safe",
                  "how": "Update requests 2.32.3 → 2.33.0 (SentrAI can undo it).", "path": "/srv/app/.venv",
                  "vulns": [{"id": "GHSA-9hjg-9r4m-mvj7", "aliases": ["CVE-2024-47081"], "summary": "netrc leak"}]},
                 {"id": "8a2d77c0e1f3b954", "kind": "os", "ecosystem": "Ubuntu:24.04:LTS", "name": "openssl",
                  "version": "3.0.13-0ubuntu3.4", "fixed": "3.0.13-0ubuntu3.5", "severity": "medium", "vuln_count": 2,
                  "update": "manual", "path": "dpkg",
                  "how": "Run: sudo apt-get update && sudo apt-get install --only-upgrade libssl3t64 openssl",
                  "vulns": [{"id": "USN-7264-1", "aliases": ["CVE-2024-12797"], "summary": "openssl flaws"}]}],
             "took_s": 3.2, "note": None}


def _job_summary(j: dict) -> str:
    if j["status"] != "done":
        return "waiting for the machine to pick it up"
    r = j["result"]
    if j["kind"] == "dep_scan":
        return f"{r['packages_checked']} packages checked, {len(r['findings'])} vulnerable (1 critical or high)"
    if j["kind"] in ("dep_update", "dep_rollback"):
        return f"{r['name']} {r['from']} → {r['to']} in {r['path']} (update {r['id']})"
    if j["kind"] == "threat_scan":
        return f"{r['files_checked']} files checked, {len(r['findings'])} findings" + (
            " (1 critical or high)" if r["findings"] else "")
    return f"{r['id']}: {r['files']} files, {r['bytes'] / 1048576:.1f} MB"


@app.get("/fleet/jobs")
def fleet_jobs(host: str | None = None):
    with lock:
        for j in S.jobs:
            if j["status"] == "queued" and (now() - datetime.fromisoformat(j["created_at"])).total_seconds() > 3:
                clean = j["host"] != "web-01"
                change = {"id": "u-1a2b3c4d", "finding": "3f1c9a0b7d2e4f61", "kind": "python", "name": "requests",
                          "from": "2.32.3", "to": "2.33.0", "path": "/srv/app/.venv", "status": "applied"}
                j.update(status="done", finished_at=iso(now()), result=(
                    {"files_checked": 96, "counts": {}, "findings": []} if clean else FAKE_JOB_SCAN)
                    if j["kind"] == "threat_scan" else {**FAKE_DEPS, "scanned_at": iso(now())} if j["kind"] == "dep_scan"
                    else change if j["kind"] == "dep_update" else {**change, "status": "rolled_back"}
                    if j["kind"] == "dep_rollback" else
                    {"id": f"b-{now():%Y%m%d-%H%M%S}", "files": 1342, "bytes": 48 * 1048576})
        return [{**j, "summary": _job_summary(j)} for j in reversed(S.jobs) if host in (None, j["host"])]


@app.post("/fleet/jobs")
def fleet_queue_job(body: dict = Body(...)):
    with lock:
        if body.get("kind") not in ("threat_scan", "backup", "dep_scan", "dep_update", "dep_rollback"):
            raise HTTPException(400, "unknown job")
        if any(j["host"] == body.get("host") and j["kind"] == body["kind"] and j.get("params") == body.get("params")
               and j["status"] == "queued" for j in S.jobs):
            raise HTTPException(409, f"a {body['kind'].replace('_', ' ')} is already queued on {body.get('host')}")
        j = {"id": f"j-{len(S.jobs) + 1:04x}", "host": body.get("host"), "kind": body["kind"], "status": "queued",
             **({"params": body["params"]} if body.get("params") else {}),
             "requested_by": body.get("operator"), "created_at": iso(now()), "finished_at": None, "result": None}
        S.jobs.append(j)
        audit("machine_job_queued", "Warden", host=j["host"], kind=j["kind"], operator=j["requested_by"])
        return {**j, "summary": _job_summary(j)}


@app.post("/fleet/agents/{agent_id}/revoke")
def fleet_revoke(agent_id: str, body: dict = Body(...)):
    with lock:
        a = S.agents.get(agent_id)
        if a is None:
            raise HTTPException(404, f"no machine with id {agent_id}")
        a.update(revoked_at=iso(now()), revoked_by=body.get("operator"))
        audit("machine_revoked", "Warden", agent_id=agent_id, host=a["host"])
        return a


@app.get("/incidents/{iid}")
def incident(iid: str):
    with lock:
        return get_inc(iid)


@app.post("/incidents/{iid}/decision")
def decision(iid: str, body: dict = Body(...)):
    with lock:
        inc = get_inc(iid)
        if inc["status"] not in ("open", "acknowledged"):
            raise HTTPException(409, f"incident is {inc['status']}")
        op, dec, just = body.get("operator", "?"), body.get("decision"), body.get("justification", "")
        if dec == "reject" and not just.strip():
            raise HTTPException(422, "justification required for reject")
        if dec == "approve" and S.protection["monitor_only"]:
            raise HTTPException(409, "Protection is off (monitor-only mode), so an approved hotpatch is not applied.")
        audit("decision", "Operator", operator=op, incident=iid, decision=dec, justification=just)
        if dec == "approve":
            if inc["category"] == ADMIN:  # "Not me: block it"
                distrust(inc, op)
            apply_containment(inc, "operator", op)
        elif dec == "reject":
            inc["status"] = "rejected"
        else:
            raise HTTPException(422, "decision must be approve|reject")
        return inc


def _close_actions(iid: str, body: dict, new_status: str, rtype: str):
    with lock:
        inc = get_inc(iid)
        for act in inc["actions"]:
            if act["status"] == "active":
                act["status"] = new_status
        inc["status"] = "resolved"
        audit(rtype, "Operator", operator=body.get("operator"), incident=iid, justification=body.get("justification"))
        return inc


@app.post("/incidents/{iid}/mine")
def mine(iid: str, body: dict = Body(...)):
    """"This was me": the sign-in behind the incident was the administrator's own. Its address, key and account
    become known, any block on it is undone, and the same person's other open incidents on the machine close too."""
    with lock:
        inc = get_inc(iid)
        if inc["status"] in ("resolved", "rejected"):
            raise HTTPException(409, f"{iid} is already {inc['status']}")
        if not S.admins["on"]:
            raise HTTPException(400, "ADMIN_SESSIONS is off: SentrAI is not keeping track of the administrators")
        op = body.get("operator") or "operator"
        learned = teach(inc, op)
        closed = []
        for other in S.incidents.values():
            same = other["host"] == inc["host"] and (other.get("src_ip") == inc.get("src_ip") or other.get("user") == inc.get("user"))
            if other is not inc and other["status"] not in ("resolved", "rejected") and same \
                    and other["category"] in (ADMIN, "log_tampering", "privilege_escalation"):
                close_as_mine(other, op, f"closed with {iid}: {op} said this was them")
                closed.append(other["id"])
        close_as_mine(inc, op, f"This was me ({op}): {', '.join(learned) or 'nothing new to learn'}")
        audit("admin_confirmed", "Warden", incident=iid, operator=op, channel=body.get("channel") or "dashboard",
              learned=learned, also_closed=closed, actor=inc.get("actor"))
        return {**inc, "learned": learned, "also_closed": closed}


@app.get("/admins")
def get_admins(host: str | None = None):
    with lock:
        return admins_view(host)


@app.post("/admins")
def post_admins(body: dict = Body(...)):
    """Add or forget a known administrator address, key fingerprint or account; 400 with plain words for a bad value."""
    with lock:
        action = str(body.get("action") or "").strip().lower()
        kind, value = str(body.get("kind") or "").strip().lower(), str(body.get("value") or "").strip()
        op, label, host = body.get("operator") or "operator", str(body.get("label") or ""), body.get("host")
        A, t = S.admins, iso(now())
        if action not in ("add", "forget"):
            raise HTTPException(400, "action must be add or forget")
        if kind == "address":
            try:
                ipaddress.ip_network(value.strip("[]"), strict=False)
            except ValueError:
                raise HTTPException(400, f"{value!r} is not an address or a network")
            A["addresses"] = [x for x in A["addresses"] if x["address"] != value or x["how"] == "setting"]
            A["sign_ins"] = [x for x in A["sign_ins"] if x["address"] != value]
            if action == "add":
                A["addresses"].append({"address": value, "how": "taught", "by": op, "at": t, "label": label, "last_seen": None})
        elif kind == "key":
            if not KEY_RX.match(value):
                raise HTTPException(400, "a key fingerprint looks like SHA256:... (ssh-keygen -lf id_ed25519.pub shows it)")
            A["keys"] = [k for k in A["keys"] if k["fingerprint"] != value or k["how"] == "setting"]
            if action == "add":
                A["keys"].append({"fingerprint": value, "type": None, "users": [], "how": "taught", "by": op, "at": t,
                                  "label": label, "last_seen": None})
        elif kind == "account":
            user, _, at_host = value.partition("@")
            at_host = (host or at_host or "*").strip().lower()
            if not user or re.search(r"\s", user):
                raise HTTPException(400, "an account is a user name, or user@machine")
            A["accounts"] = [a for a in A["accounts"] if (a["account"], a["host"]) != (user.lower(), at_host) or a["how"] == "setting"]
            if action == "add":
                A["accounts"].append({"account": user.lower(), "host": at_host, "how": "taught", "by": op, "at": t, "label": label})
        else:
            raise HTTPException(400, "kind must be address, key or account")
        audit("admin_changed", "Warden", operator=op, action=action, kind=kind,
              value=short_key(value) if kind == "key" else value, label=label, host=host)
        return admins_view()


@app.post("/admins/sign-in")
def post_admin_sign_in(body: dict = Body(...)):
    """A dashboard sign-in (password and authenticator): an Owner's or Admin's address counts as an administrator's."""
    with lock:
        email, role, address = str(body.get("email") or ""), str(body.get("role") or ""), body.get("address")
        try:
            ip = str(ipaddress.ip_address(str(address or "").strip()))
        except ValueError:
            ip = None
        vouched = bool(ip) and role.strip().lower() in ("owner", "admin") and S.admins["on"]
        S.sign_in_reports.append({"email": email, "role": role, "address": address, "vouched": vouched, "at": iso(now())})
        if not vouched:
            return {"ok": True, "vouched": False, "address": ip, "until": None}
        until = iso(now() + timedelta(hours=12))
        S.admins["sign_ins"] = [s for s in S.admins["sign_ins"] if s["address"] != ip]
        S.admins["sign_ins"].append({"address": ip, "email": email, "role": role, "at": iso(now()), "until": until})
        audit("admin_signed_in", "Warden", email=email, role=role, address=ip, until=until)
        return {"ok": True, "vouched": True, "address": ip, "until": until}


@app.get("/dev/admin-sign-ins")
def dev_admin_sign_ins():
    """Test helper: every sign-in the dashboard reported, vouched for or not."""
    with lock:
        return list(S.sign_in_reports)


@app.post("/incidents/{iid}/rollback")
def rollback(iid: str, body: dict = Body(...)):
    return _close_actions(iid, body, "rolled_back", "rollback")


@app.post("/incidents/{iid}/permanent")
def permanent(iid: str, body: dict = Body(...)):
    return _close_actions(iid, body, "permanent", "permanent")


ROUTING = {"source": "defaults", "contacts": [
    {"id": "on_duty", "name": "John Doe (SEC-409) / Shift Bravo", "role": "on_duty", "email": "", "telegram": "", "backup": "team_lead"},
    {"id": "team_lead", "name": "Team lead", "role": "team_lead", "email": "", "telegram": "", "backup": "it_manager"},
    {"id": "it_manager", "name": "IT manager", "role": "it_manager", "email": "", "telegram": "", "backup": "cxo"},
    {"id": "cxo", "name": "CXO", "role": "cxo", "email": "", "telegram": "", "backup": ""}],
    "rules": [{"name": "Critical", "match": {"severity": ["critical"]}, "owner": "on_duty",
               "notify": ["team_lead", "it_manager", "cxo"]},
              {"name": "Attacker inside", "match": {"category": ["malware", "data_exfiltration", "log_tampering",
                                                                 "privilege_escalation"]},
               "owner": "on_duty", "notify": ["team_lead", "it_manager"]},
              {"name": "High", "match": {"severity": ["high"]}, "owner": "on_duty", "notify": ["team_lead"]},
              {"name": "Everything else", "match": {}, "owner": "on_duty", "notify": []}],
    "follow_up": {"escalate_after_reminders": 2, "max_escalations": 3, "resolve_within_hours": 24},
    "layout": {}}  # where the dashboard's map draws each box; empty: it lays them out itself


@app.get("/routing")
def routing():
    if not EXT["telegram"]["added"]:  # like the real core: no Telegram, no telegram_linked
        return {**ROUTING, "contacts": [dict(c) for c in ROUTING["contacts"]]}
    return {**ROUTING, "contacts": [{**c, "telegram_linked": c["id"] in TG_LINKS} for c in ROUTING["contacts"]]}


@app.post("/routing")
def save_routing(body: dict = Body(...)):
    new = body.get("routing") or {}
    contacts = new.get("contacts") or {}
    if not contacts:
        raise HTTPException(400, "keep at least one person in the routing")
    for r in new.get("rules") or []:
        if r.get("owner") not in contacts:
            raise HTTPException(400, f"rule {r.get('name')!r} needs an owner who is one of the people")
    ROUTING.update(source="routing.json (fake core)", follow_up=new.get("follow_up") or ROUTING["follow_up"],
                   contacts=[{"id": k, **{f: str(v.get(f) or "") for f in ("name", "role", "email", "telegram", "backup")}}
                             for k, v in contacts.items()],
                   rules=[{"name": r.get("name"), "match": r.get("match") or {}, "owner": r.get("owner"),
                           "notify": [x for x in r.get("notify") or [] if x != r.get("owner")]}
                          for r in new.get("rules") or []],
                   layout=new.get("layout") if isinstance(new.get("layout"), dict) else {})
    if not ROUTING["rules"] or ROUTING["rules"][-1]["match"]:
        ROUTING["rules"].append({"name": "Everything else", "match": {}, "owner": ROUTING["contacts"][0]["id"],
                                 "notify": []})
    with lock:
        audit("routing_changed", "Operator", operator=body.get("operator"), summary=body.get("summary") or "Routing saved")
    return routing()


TG_LINKS: dict = {}  # contact id -> chat id


def _telegram_added() -> None:
    if not EXT["telegram"]["added"]:
        raise HTTPException(404, "The Telegram extension is not added. Add it on the Extensions page.")


@app.post("/telegram/link-codes")
def telegram_link_code(body: dict = Body(...)):
    _telegram_added()
    contact = next((c for c in ROUTING["contacts"] if body.get("contact") in (c["id"], c["name"])), None)
    if contact is None:
        raise HTTPException(404, "no such contact")
    code = "".join(secrets.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(8))
    return {"contact": contact["id"], "name": contact["name"], "code": code, "expires_at": iso(now() + timedelta(minutes=30)),
            "valid_minutes": 30, "send": f"/link {code}"}


@app.post("/telegram/unlink")
def telegram_unlink(body: dict = Body(...)):
    _telegram_added()
    if TG_LINKS.pop(str(body.get("contact")), None) is None:
        raise HTTPException(404, "not linked")
    return {"contact": body.get("contact"), "unlinked": True}


@app.get("/telegram/links")
def telegram_links():
    _telegram_added()
    return [{"contact_id": k, "chat_id": v} for k, v in TG_LINKS.items()]


@app.post("/incidents/{iid}/assign")
def assign(iid: str, body: dict = Body(...)):
    with lock:
        inc = get_inc(iid)
        if inc["status"] in ("resolved", "rejected"):
            raise HTTPException(409, f"incident is {inc['status']}")
        who = str(body.get("assignee") or "").strip()
        if not who:
            raise HTTPException(400, "assignee is required")
        inc.update(owner=who, assigned_by=body.get("operator"), assigned_at=iso(now()))
        inc.setdefault("timeline", []).append({"ts": iso(now()), "kind": "assigned",
                                               "text": f"Assigned to {who} by {body.get('operator')}"})
        audit("incident_assigned", "Warden", incident=iid, to=who, operator=body.get("operator"))
        return inc


@app.post("/incidents/{iid}/resolve")
def resolve(iid: str, body: dict = Body(...)):
    with lock:
        inc = get_inc(iid)
        if inc["status"] in ("resolved", "rejected"):
            raise HTTPException(409, f"incident is {inc['status']}")
        if not str(body.get("note") or "").strip():
            raise HTTPException(400, "resolving requires a short note on what was done")
        inc.update(status="resolved", resolved_by=body.get("operator"), resolution=body.get("note"),
                   acked=True, acked_by=inc.get("acked_by") or body.get("operator"))
        audit("incident_resolved", "Warden", incident=iid, operator=body.get("operator"), note=body.get("note"))
        return inc


@app.post("/incidents/{iid}/ack")
def ack(iid: str, body: dict = Body(...)):
    with lock:
        inc = get_inc(iid)
        if not inc["acked"]:
            inc.update(acked=True, acked_by=body.get("operator"), acked_at=iso(now()))
            if inc["status"] == "open":
                inc["status"] = "acknowledged"
        audit("ack", "Operator", operator=body.get("operator"), incident=iid, channel=body.get("channel"))
        return inc


@app.get("/audit")
def get_audit():
    with lock:
        valid = all(b["prev_hash"] == a["hash"] for a, b in zip(S.audit, S.audit[1:]))
        return {"records": S.audit, "chain_valid": valid}


@app.get("/reports/{name}")
def report(name: str):
    with lock:
        iid = name[:-3] if name.endswith(".md") else name
        rep = S.reports.get(iid)
        if not rep:
            raise HTTPException(404, f"no report for {iid}")
        return PlainTextResponse(report_md(rep), media_type="text/markdown") if name.endswith(".md") else rep


def protection_view() -> dict:
    return {"protection": "off" if S.protection["monitor_only"] else "on", **S.protection, "active_actions": []}


@app.get("/protection")
def get_protection():
    with lock:
        return protection_view()


@app.post("/protection")
def post_protection(body: dict = Body(...)):
    with lock:
        on, reason = bool(body.get("on")), str(body.get("reason") or "").strip()
        if not on and not reason:
            raise HTTPException(400, "turning protection off requires a reason")
        S.protection = {"monitor_only": not on, "changed_at": iso(now()), "changed_by": body.get("operator", "?"),
                        "reason": reason or None}
        audit("protection_changed", "Warden", protection="on" if on else "off", operator=body.get("operator"),
              reason=reason or None)
        return protection_view()


@app.get("/blocklist")
def blocklist(host: str | None = None):
    with lock:
        ips, users = set(), set()
        for inc in S.incidents.values():
            if host is not None and inc["host"] != host:
                continue
            for a in inc["actions"]:
                if a["status"] in ("active", "permanent"):
                    if a["type"] == "block_ip":
                        ips.add(a["target"])
                    elif a["type"] == "lock_user":
                        users.add(a["target"])
        return {"ips": sorted(ips), "users": sorted(users)}


@app.get("/notifications/pending")
def pending():
    with lock:
        return [n for n in S.notifications if not n["delivered"]]


@app.post("/notifications/{nid}/delivered")
def delivered(nid: str, body: dict = Body(...)):
    with lock:
        for n in S.notifications:
            if n["id"] == nid:
                n.update(delivered=True, channel=body.get("channel"), message_id=body.get("message_id"),
                         delivered_at=iso(now()))
                audit("notification_delivered", "Scribe", incident=n["incident_id"], channel=n["channel"],
                      message_id=n["message_id"])
                return n
        raise HTTPException(404, f"notification {nid} not found")


FAKE_AI = {"engine": "Cyanide", "planner": "off (fake core)", "chat": "offline (fake core)", "online": False,
           "provider": None, "model": None, "key_source": None, "off_reason": "the fake core has no AI model"}


@app.get("/ai")
def ai_status():
    return FAKE_AI


@app.post("/ai/reload")
def ai_reload():
    return FAKE_AI


# What each installed extension is doing in this pretend core: the rest of each row comes from its manifest.
EXT_LIVE = {
    "cloudflare": {"added": True, "configured": True, "testable": True, "last_ok": "2026-10-26 10:02:11",
                   "detail": "IP Access rules, block on zone 0123abcd · 2 addresses blocked now"},
    "abuseipdb": {"added": True, "configured": True, "testable": True, "detail": "14 lookups since start, answers kept 24 h"},
    "typesafe": {"added": False, "configured": False, "testable": True,
                 "detail": "Paste a TypeSafe API key on the Configuration page to turn it on."},
    "telegram": {"added": True, "configured": True, "detail": "The notifier runs the bot · 1 personal chat linked"},
    "slack": {"added": False, "configured": False, "testable": True,
              "detail": "Create an incoming webhook in Slack and paste its URL."},
}
NOT_ADDED = "Not added. Add it to use it; its settings are kept either way."
BUILT_IN = [
    {"name": "webhook", "title": "Any other system (webhook)", "kind": "Blocking", "built_in": True, "added": True,
     "added_by": "built_in", "running": True, "configured": False, "testable": False,
     "what": "Sends each block and its removal to a URL you choose: n8n, Zapier, a router, a SOAR.",
     "detail": "Set a URL to hand blocks to another system.", "settings": ["SENTRAI_RESPONDER_WEBHOOK_URL"],
     "docs": "", "last_error": None},
    {"name": "email", "title": "Email", "kind": "Alerts", "built_in": True, "added": True, "added_by": "built_in",
     "running": True, "configured": False, "testable": False,
     "what": "Emails alerts, as a backup to Telegram or with every alert.", "detail": "Handled by the notifier.",
     "settings": ["SMTP_HOST", "ALERT_EMAIL_TO"], "docs": "", "last_error": None},
]


def _ext_state() -> dict[str, dict]:
    return {name: {"added": EXT_LIVE.get(name, {}).get("added", False), "by": "settings", "at": None}
            for name in se.installed()}


EXT = _ext_state()
EXT_MANAGED = {"on": False}


def ext_row(name: str) -> dict:
    m, live, state = se.installed()[name], EXT_LIVE.get(name, {}), EXT[name]
    row = {**m.public(), "built_in": False, "added": state["added"],
           "added_by": se.CHOICE_ENV if EXT_MANAGED["on"] else state["by"], "running": state["added"],
           "configured": False, "detail": "", "last_ok": None, "last_error": None, "testable": False, "error": None,
           "changed_by": state.get("operator"), "changed_at": state["at"]}
    if state["added"]:
        row.update({k: v for k, v in live.items() if k != "added"})
    else:
        row["detail"] = NOT_ADDED
    return row


def ext_rows() -> list[dict]:
    return [ext_row(n) for n in se.installed()] + [dict(r) for r in BUILT_IN]


def _ext(name: str) -> dict:
    if name not in EXT:
        raise HTTPException(404, f"no extension called {name} is installed")
    return EXT[name]


def _changeable() -> None:
    if EXT_MANAGED["on"]:
        raise HTTPException(409, "SENTRAI_EXTENSIONS is set on the server, so the extensions it lists are the "
                                 "ones on. Change it there.")


@app.get("/extensions")
def extensions():
    return ext_rows()


@app.get("/integrations")
def integrations():
    return ext_rows()


@app.post("/extensions/{name}/add")
def add_extension(name: str, body: dict = Body(None)):
    state = _ext(name)
    _changeable()
    operator = (body or {}).get("operator") or "operator"
    with lock:
        state.update(added=True, by="dashboard", operator=operator, at=iso(now()))
        audit("extension_added", "Warden", extension=name, operator=operator)
    return ext_row(name)


@app.post("/extensions/{name}/remove")
def remove_extension(name: str, body: dict = Body(None)):
    state = _ext(name)
    _changeable()
    operator = (body or {}).get("operator") or "operator"
    with lock:
        was = state["added"]
        state.update(added=False, by="dashboard", operator=operator, at=iso(now()))
        cleanup = {"released": 0, "left_in_place": []} if was else {}
        if was and name == "cloudflare":
            cleanup = {"released": 2, "left_in_place": [], "cloudflare_removed": 2}
        audit("extension_removed", "Warden", extension=name, operator=operator, **cleanup)
    return {**ext_row(name), "cleanup": cleanup}


@app.post("/extensions/{name}/test")
def test_extension(name: str):
    state = _ext(name)
    if not state["added"]:
        return {"ok": False, "error": f"{se.installed()[name].title} is not added."}
    return {"ok": False, "error": "the fake core does not call outside services; start the real core to test"}


@app.post("/integrations/{name}/test")
def test_integration(name: str):
    if name in {r["name"] for r in BUILT_IN}:
        return {"ok": False, "error": "This built-in service has no test here yet."}
    return test_extension(name)


@app.post("/extensions/reload")
def reload_extensions():
    return ext_rows()


@app.post("/dev/extensions/managed")
def dev_extensions_managed(on: int = 1):
    """Test helper: act as if the server's SENTRAI_EXTENSIONS decides which extensions are on."""
    EXT_MANAGED["on"] = bool(on)
    return {"managed": EXT_MANAGED["on"]}


@app.post("/ai/test")
def ai_test(body: dict = Body(None)):
    return {"ok": False, "provider": (body or {}).get("provider"), "model": None, "ms": 0, "hint": None,
            "error": "the fake core does not call AI providers; start the real core to test"}


@app.post("/chat/setup/interpret")
def setup_interpret(body: dict = Body(...)):
    return {"ai": False, "choice": "", "reply": ""}  # like a core without an AI key: the setup stays scripted


@app.get("/chat")
def get_chat():
    with lock:
        return {"assistant": "Cyanide", "model": "fake core (canned answers)", "messages": S.chat}


@app.post("/chat")
def post_chat(body: dict = Body(...)):
    """Canned orchestrator: explains the named (or first open) incident and suggests approving it."""
    with lock:
        text, iid = str(body.get("message") or "").strip(), body.get("incident")
        if not text:
            raise HTTPException(400, "empty message")
        S.chat.append({"id": len(S.chat) + 1, "role": "operator", "operator": body.get("operator"), "text": text,
                       "ts": iso(now()), "incident": iid})
        inc = S.incidents.get(iid) or next((i for i in S.incidents.values() if i["status"] in ("open", "acknowledged")), None)
        if inc:
            answer = (f"{inc['id']} is {inc['category'].replace('_', ' ')} from {inc.get('src_ip')}, status {inc['status']}. "
                      f"Recommended: {inc.get('recommended_action')}.")
            sugg = [{"incident": inc["id"], "decision": "approve", "label": f"Approve & patch {inc['id']}",
                     "reason": "Suggested by the fake core", "status": inc["status"]}] if inc["status"] in ("open", "acknowledged") else []
        else:
            answer, sugg = "No active incidents. Risk is quiet.", []
        reply = {"id": len(S.chat) + 1, "role": "assistant", "text": answer, "ts": iso(now()), "incident": iid,
                 "source": "fallback", "looked_at": ["risk overview"], "suggestions": sugg}
        S.chat.append(reply)
        audit("operator_chat", "Cyanide", operator=body.get("operator"), incident=iid, question=text,
              summary=f"{body.get('operator')} asked: {text[:80]}")
        return reply


FAKE_SCAN = {
    "platform": "Windows", "enabled": True, "scanned": 142, "skipped_protected": 3, "recognised": 3, "error": None,
    "notes": ["MySQL / MariaDB database: The error log shows failed logins only when log_error_verbosity is 3."],
    "processes": [{"pid": 1200, "name": "python.exe", "program": "SentrAI lab: fake student portal", "layer": "web",
                   "path": "~\\sentrai\\mvp\\lab\\.venv\\Scripts\\python.exe", "account": "(user)", "service": "",
                   "log_options": []},
                  {"pid": 1300, "name": "nginx.exe", "program": "nginx web server", "layer": "web",
                   "path": "C:\\nginx-1.27\\nginx.exe", "account": "(user)", "service": "", "log_options": []}],
    "suggestions": [
        {"id": "s1", "path": "C:\\nginx-1.27\\logs", "kind": "folder", "program": "nginx web server", "layer": "web",
         "format": "text", "reasons": ["next to the program"], "files_found": 2, "already_watched": False,
         "files": [{"id": "s1f1", "name": "access.log", "size": 20480, "modified": "2026-09-28T20:01:00", "watched": False},
                   {"id": "s1f2", "name": "error.log", "size": 512, "modified": "2026-09-28T19:00:00", "watched": False}]},
        {"id": "s2", "path": "~\\sentrai\\mvp\\lab\\logs", "kind": "folder", "program": "SentrAI lab: fake student portal",
         "layer": "web", "format": "jsonl", "reasons": ["logs folder of the app"], "files_found": 1, "already_watched": True,
         "files": [{"id": "s2f1", "name": "access.jsonl", "size": 4096, "modified": "2026-09-28T20:02:00", "watched": True}]},
    ],
}


@app.post("/system/scan")
def post_scan(body: dict = Body(None)):
    import copy
    with lock:
        S.scan = {**copy.deepcopy(FAKE_SCAN), "scanned_at": iso(now())}
        for s in S.scan["suggestions"]:
            for f in s["files"]:
                f["watched"] = f["watched"] or any(x["file_id"] == f["id"] for x in S.log_sources)
        audit("system_scan", "Cyanide", by=(body or {}).get("operator"), summary="Scanned 142 processes")
        return S.scan


@app.get("/system/scan")
def get_scan():
    return S.scan or {"suggestions": [], "processes": [], "scanned_at": None}


FAKE_THREATS = {
    "roots": ["/var/lib/pterodactyl/volumes"], "missing": [], "files_checked": 1834, "files_not_checked": 0,
    "counts": {"critical": 2, "high": 1, "medium": 0}, "new_alerts": 0,
    "findings": [
        {"id": "t1", "path": "/var/lib/pterodactyl/volumes/a1b2/plugins/web/upload/img.php", "key": "php-eval-request",
         "kind": "webshell", "severity": "critical", "label": "runs code sent in a web request", "line": 3,
         "snippet": "<?php @ev" + "al($_POST['x']); ?>",  # split so antivirus does not flag this file
         "sha256": "0" * 64, "size": 31},
        {"id": "t2", "path": "/var/lib/pterodactyl/volumes/c3d4/start.sh", "key": "miner-pool", "kind": "miner",
         "severity": "critical", "label": "crypto-mining pool address", "line": 4,
         "snippet": "./.cache/sys -o stratum+tcp://pool.example:3333 -u …", "sha256": "1" * 64, "size": 210},
        {"id": "t3", "path": "/var/lib/pterodactyl/volumes/e5f6/harbor.sh", "key": "minirootfs",
         "kind": "container_escape", "severity": "high", "label": "downloads a mini Linux system to run inside the server",
         "line": 12, "snippet": "curl -LO https://dl-cdn.alpinelinux.org/…/alpine-minirootfs-3.20.0-x86_64.tar.gz",
         "sha256": "2" * 64, "size": 4096},
    ],
}


@app.post("/threats/scan")
def post_threats(body: dict = Body(None)):
    import copy
    with lock:
        held = {q["finding_id"] for q in S.quarantine}
        S.threats = {**copy.deepcopy(FAKE_THREATS), "scanned_at": iso(now())}
        S.threats["findings"] = [f for f in S.threats["findings"] if f["id"] not in held]
        audit("threat_scan", "Cyanide", by=(body or {}).get("operator"), summary="Checked 1834 files for threats")
        return S.threats


@app.post("/deps/scan")
def post_deps(body: dict = Body(None)):
    with lock:
        S.deps = {**copy.deepcopy(FAKE_DEPS), "scanned_at": iso(now())}
        audit("dep_scan", "Cyanide", by=(body or {}).get("operator"), summary="Checked 312 packages")
        return S.deps


@app.get("/deps")
def get_deps():
    return S.deps or {"findings": [], "scanned_at": None}


@app.get("/threats")
def get_threats():
    return S.threats or {"findings": [], "scanned_at": None}


@app.post("/threats/{fid}/quarantine")
def post_quarantine(fid: str, body: dict = Body(...)):
    with lock:
        f = next((f for f in (S.threats or {}).get("findings", []) if f["id"] == fid), None)
        if f is None:
            raise HTTPException(404, f"{fid} is not in the latest threat scan; scan again")
        qid = f"q-{fid}"
        S.quarantine.append({"id": qid, "finding_id": fid, "name": f["path"].rsplit("/", 1)[-1], "original": f["path"],
                             "finding": {"label": f["label"]}, "operator": body.get("operator"), "at": iso(now())})
        S.threats["findings"] = [x for x in S.threats["findings"] if x["id"] != fid]
        audit("file_quarantined", "Cyanide", operator=body.get("operator"), summary=f"Quarantined {f['path']}")
        return {"ok": True, "quarantine_id": qid, "file": f["path"]}


@app.get("/quarantine")
def get_quarantine():
    return S.quarantine


@app.post("/quarantine/{qid}/restore")
def post_restore(qid: str, body: dict = Body(...)):
    with lock:
        q = next((q for q in S.quarantine if q["id"] == qid), None)
        if q is None:
            raise HTTPException(404, f"{qid} is not in quarantine")
        S.quarantine.remove(q)
        return {"ok": True, "file": q["original"]}


FAKE_ADVICE = ["Do not click any link or open any attachment in it.",
               "Leave the message where it is so it can be checked.",
               "If you typed a password after clicking, change it now and tell technical staff."]


@app.post("/staff-reports")
def post_staff_report(body: dict = Body(...)):
    text = str(body.get("text") or "").strip()
    if len(text) < 10:
        raise HTTPException(400, "Please describe what you saw in a sentence or two.")
    with lock:
        rid = f"SR-2026-{len(S.staff_reports) + 1:03d}"
        high = any(w in text.lower() for w in ("clicked", "typed my password", "paid", "locked"))
        inc = open_incident("staff_report", None, body.get("reporter") or "anonymous", 1.0, 1.5 if high else 1.0, "rules")
        inc["needs_review"] = True
        inc["host"] = body.get("host") or inc["host"]
        r = {"id": rid, "received_at": iso(now()), "channel": body.get("channel") or "api",
             "reporter": body.get("reporter") or "anonymous", "contact": body.get("contact") or None,
             "where": body.get("where") or None, "host": body.get("host") or None, "text": text, "status": "new", "assignee": None,
             "incident": inc["id"], "notes": [], "kind_label": "Suspicious email, message or link",
             "triage": {"kind": "phishing", "urgency": "high" if high else "medium",
                        "summary": text.split(".")[0][:160], "advice": FAKE_ADVICE, "by": "keywords",
                        "for_tech": "Find the message, check who else got it, block the sender and reset passwords."},
             "history": [{"at": iso(now()), "by": body.get("reporter") or "anonymous", "what": "reported"}]}
        S.staff_reports.append(r)
        audit("staff_report_received", "Warden", report=rid, summary=f"Staff report {rid}: {r['triage']['summary']}")
        return {"id": rid, "status": "new", "kind": "phishing", "kind_label": r["kind_label"],
                "urgency": r["triage"]["urgency"], "advice": FAKE_ADVICE}


@app.get("/staff-reports")
def get_staff_reports(status: str | None = None):
    rows = [r for r in S.staff_reports if not status or r["status"] == status
            or (status == "open" and r["status"] in ("new", "reviewing"))]
    counts = {s: sum(1 for r in S.staff_reports if r["status"] == s)
              for s in ("new", "reviewing", "resolved", "not_a_threat")}
    return {"reports": list(reversed(rows)), "counts": counts}


@app.post("/staff-reports/{rid}")
def update_staff_report(rid: str, body: dict = Body(...)):
    with lock:
        r = next((r for r in S.staff_reports if r["id"] == rid), None)
        if r is None:
            raise HTTPException(404, f"staff report {rid} not found")
        status, note = body.get("status"), (body.get("note") or "").strip()
        if status in ("resolved", "not_a_threat") and not note:
            raise HTTPException(400, "Add a short note saying what was found before closing a report.")
        if body.get("assignee") is not None:
            r["assignee"] = body["assignee"] or None
        if status:
            r["status"] = status
        elif r["status"] == "new":
            r["status"] = "reviewing"
        if note:
            r["notes"].append({"at": iso(now()), "by": body.get("operator"), "text": note})
        r["history"].append({"at": iso(now()), "by": body.get("operator"), "what": f"status {r['status']}"})
        return r


def _fake_backup(by: str, reason: str) -> dict:
    stamp = now()
    b = {"id": f"b-{stamp.strftime('%Y%m%d-%H%M%S')}-{len(S.backups) + 1}", "created": iso(stamp),
         "created_ts": stamp.timestamp(), "by": by, "reason": reason, "folders": ["/var/www/portal"],
         "missing": [], "sentrai": True, "files": 1834, "bytes": 48_234_112, "archive_bytes": 21_004_800,
         "sha256": "3" * 64, "manifest_sha256": "4" * 64, "skipped": [], "copy": None, "verified": None}
    S.backups.insert(0, b)
    del S.backups[7:]
    return b


@app.get("/backups")
def get_backups():
    return {"enabled": True, "every_hours": 24, "keep": 7, "folders": ["/var/www/portal"], "include_sentrai": True,
            "copy_to": None, "stored_in": "/opt/sentrai/mvp/core/data/backups",
            "next_due": iso(now() + timedelta(hours=24)) if S.backups else "now", "overdue": False,
            "last_error": None, "backups": S.backups}


@app.post("/backups")
def post_backup(body: dict = Body(None)):
    with lock:
        b = _fake_backup((body or {}).get("operator") or "operator", "manual")
        audit("backup_made", "Warden", backup=b["id"], summary=f"Backed up {b['files']} files as {b['id']}")
        return {"ok": True, **b, "pruned": []}


@app.post("/backups/{bid}/verify")
def post_verify_backup(bid: str, body: dict = Body(None)):
    with lock:
        b = next((b for b in S.backups if b["id"] == bid), None)
        if b is None:
            raise HTTPException(404, f"{bid} is not a backup")
        b["verified"] = {"ok": True, "at": iso(now()), "problems": []}
        return {"ok": True, "backup": bid, "files_checked": b["files"], "problems": []}


@app.post("/backups/{bid}/restore")
def post_restore_backup(bid: str, body: dict = Body(...)):
    with lock:
        if not any(b["id"] == bid for b in S.backups):
            raise HTTPException(404, f"{bid} is not a backup")
        in_place = bool(body.get("in_place"))
        if in_place and body.get("confirm") != bid:
            raise HTTPException(409, f"type the backup id ({bid}) as confirmation")
        safety = _fake_backup(body.get("operator") or "operator", "before_restore")["id"] if in_place else None
        return {"ok": True, "backup": bid, "in_place": in_place, "files_restored": 1834, "failed": [],
                "restored_to": "in place" if in_place else f"/opt/sentrai/mvp/core/data/restores/{bid}",
                "safety_backup": safety, "note": ""}


@app.get("/log-sources")
def get_log_sources():
    return S.log_sources


@app.post("/log-sources")
def post_log_source(body: dict = Body(...)):
    with lock:
        f = next((f for s in (S.scan or {}).get("suggestions", []) for f in s["files"] if f["id"] == body.get("file_id")), None)
        if f is None:
            raise HTTPException(404, f"{body.get('file_id')} is not in the latest scan; scan again")
        f["watched"] = True
        S.log_sources.append({"file_id": f["id"], "path": f["name"], "layer": "web", "format": "text",
                              "found_by": "process scan", "confirmed_by": body.get("operator")})
        audit("log_source_added", "Cyanide", operator=body.get("operator"), file=f["name"],
              summary=f"{body.get('operator')} added {f['name']} to the collector")
        return {"ok": True, "file": f["name"], "layer": "web", "watching": len(S.log_sources)}


@app.get("/log-sources/pending")
def get_pending_sources():
    return S.pending


@app.post("/_fake/scout-proposal")
def fake_scout_proposal(body: dict = Body(None)):
    """Dev/test only: pretend `python -m scout find` proposed a file."""
    with lock:
        n = len(S.pending) + 1
        p = {"id": f"p{n:010d}", "name": "auth.log", "path": "/var/log/auth.log", "layer": "os", "format": "text",
             "why": "SSH logins with the source address, so password guessing shows up.",
             "goal": "where are the login logs?", "proposed_at": iso(now()), **(body or {})}
        S.pending.append(p)
        return p


@app.post("/log-sources/pending/{pid}")
def decide_pending_source(pid: str, body: dict = Body(...)):
    with lock:
        p = next((x for x in S.pending if x["id"] == pid), None)
        if p is None:
            raise HTTPException(404, f"{pid} is not a pending Scout proposal")
        S.pending.remove(p)
        if body.get("approve"):
            S.log_sources.append({"path": p["path"], "layer": p["layer"], "format": p["format"],
                                  "found_by": "Scout", "confirmed_by": body.get("operator")})
        audit("log_source_added" if body.get("approve") else "log_source_rejected", "Cyanide",
              operator=body.get("operator"), file=p["name"],
              summary=f"{body.get('operator')} {'added' if body.get('approve') else 'rejected'} {p['name']} "
                      f"(proposed by Scout)")
        return {"ok": True, "file": p["name"], "layer": p["layer"], "approved": bool(body.get("approve"))}


@app.post("/chat/clear")
def clear_chat():
    with lock:
        S.chat = []
    return {"ok": True}


@app.post("/dev/reset")
def reset():
    """Test helper: start the fake scenario again from an empty state."""
    global S
    with lock:
        S = State()
        EXT.clear()
        EXT.update(_ext_state())
        EXT_MANAGED["on"] = False
        TG_LINKS.clear()
        audit("dev_reset", "Warden", summary="Fake core state cleared")
    return {"ok": True}


@app.post("/dev/trigger/{category}")
def trigger(category: str, src_ip: str = "198.51.100.7", user: str = "admin"):
    if category not in SEVERITY:
        raise HTTPException(422, "unknown category")
    with lock:
        return open_incident(category, src_ip, user, 0.9, 1.0, "jev")


if __name__ == "__main__":
    threading.Thread(target=tick, daemon=True).start()
    with lock:
        audit("startup", "Warden", summary="FAKE core online")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("FAKE_CORE_PORT", "8900")), log_level="warning")
