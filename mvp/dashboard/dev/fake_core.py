"""Fake CactAI core for UI development (implements the endpoints in mvp/CONTRACT.md).

NOT the real core. In-memory, single process, plays a scripted demo scenario:
  t≈4 s   brute_force incident opens (risk ≈ 40, amber) + notification
  ...     nobody acks -> inaction penalty climbs (fast demo clock)
  t≈40 s  sql_injection incident opens -> risk crosses 80 -> Needle approves
          autonomous containment (block IP, lock user) + negligence report
Run:  .venv\\Scripts\\python dev\\fake_core.py   (serves http://127.0.0.1:8900)
Env:  FAKE_CORE_PORT (8900, so it never collides with the real core on 8000), FAKE_DEMO_SPEED (120 = 30 real s per demo hour),
      FAKE_TTL_SECONDS (300 real s before containment expires),
      FAKE_AUTOPLAY (1), FAKE_THRESHOLD (80)
Extra dev-only endpoint: POST /dev/trigger/{category}?src_ip=..&user=..
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from datetime import datetime, timedelta, timezone

import uvicorn
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse

SGT = timezone(timedelta(hours=8))
DEMO_SPEED = float(os.environ.get("FAKE_DEMO_SPEED", "120"))
THRESHOLD = int(os.environ.get("FAKE_THRESHOLD", "80"))
AUTOPLAY = os.environ.get("FAKE_AUTOPLAY", "1") != "0"
SLA_HOURS = 2.0
TTL_SECONDS = float(os.environ.get("FAKE_TTL_SECONDS", "300"))
BASELINE_RAW = 5.0

SEVERITY = {
    "brute_force": ("high", 30), "sql_injection": ("high", 40), "xss": ("medium", 20),
    "port_scan": ("medium", 15), "privilege_escalation": ("critical", 60),
    "data_exfiltration": ("critical", 70), "misconfiguration": ("medium", 20), "benign": ("low", 0),
}
PLAYBOOK = {
    "brute_force": [("block_ip", "src_ip"), ("lock_user", "user"), ("rate_limit", "/login")],
    "sql_injection": [("waf_rule", "/search UNION/OR 1=1"), ("block_ip", "src_ip")],
    "xss": [("waf_rule", "script-tag filter")],
    "port_scan": [("block_ip", "src_ip")],
    "privilege_escalation": [("kill_process", "sh (pid 4242)"), ("block_ip", "src_ip")],
    "data_exfiltration": [("block_ip", "src_ip"), ("lock_user", "user")],
    "misconfiguration": [("revoke_public_acl", "s3://demo-bucket")],
}
RECOMMEND = {
    "brute_force": "Block {src_ip} for 2 h, lock account '{user}' and rate-limit /login",
    "sql_injection": "Add WAF rule for UNION/OR-1=1 payloads on /search and block {src_ip} for 2 h",
    "xss": "Add WAF rule stripping <script> payloads on /search",
    "port_scan": "Block {src_ip} for 2 h",
    "privilege_escalation": "Kill the spawned shell and block {src_ip}",
    "data_exfiltration": "Revoke session of '{user}', block {src_ip}",
    "misconfiguration": "Remove the public ACL and enable default encryption",
}

app = FastAPI(title="CactAI FAKE core (dev only)")
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
    }
    S.incidents[iid] = inc
    audit("classification", "Jev" if by == "jev" else "Saguaro", incident=iid, category=category, confidence=conf)
    audit("incident_opened", "Saguaro", incident=iid, category=category, risk_index=risk_index())
    notify(inc, "incident_opened", f"{category.replace('_', ' ').capitalize()} on web-01 from {src_ip}")
    return inc


def apply_containment(inc: dict, mode: str, approver: str) -> None:
    snap = hashlib.sha256(f"snapshot-{inc['id']}-{time.time()}".encode()).hexdigest()
    audit("snapshot", "Areole-Linux", incident=inc["id"], snapshot_hash=snap[:16])
    if mode == "autonomous":
        audit("action_approved", "Needle", incident=inc["id"], summary=f"Two-key review passed for {inc['id']}")
    for atype, tgt in PLAYBOOK.get(inc["category"], []):
        S.seq_act += 1
        target = inc.get(tgt, tgt) if tgt in ("src_ip", "user") else tgt
        act = {"action_id": f"act-{S.seq_act:04d}", "incident": inc["id"], "type": atype, "target": target,
               "ttl_hours": 2, "mode": mode, "approved_by": approver, "status": "active", "snapshot_hash": snap}
        # expires_at in wall-clock: 2 demo hours
        act["expires_at"] = iso(now() + timedelta(seconds=TTL_SECONDS))
        inc["actions"].append(act)
        audit("action_applied", "Areole-Linux", incident=inc["id"], target=target, summary=f"{atype} {target} (TTL 2 h)")
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
    audit("report_generated", "Scribe", incident=inc["id"], summary=f"Negligence report for {inc['id']}")


def report_md(rep: dict) -> str:
    inc = S.incidents[rep["incident_id"]]
    lines = [
        f"# Negligence Report · {inc['id']}",
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
            if AUTOPLAY and elapsed > 40 and "sqli" not in S.script_done:
                S.script_done.add("sqli")
                open_incident("sql_injection", "203.0.113.45", "admin", 1.0, 1.5, "rules")
            for inc in S.incidents.values():
                if inc["status"] == "open" and not inc["acked"]:
                    hrs = demo_hours(datetime.fromisoformat(inc["opened_at"]))
                    pen = min(30, 5 * int(hrs))
                    if pen != inc["inaction_penalty"]:
                        inc["inaction_penalty"] = pen
                        audit("risk_update", "Saguaro", incident=inc["id"], summary=f"Inaction penalty +{pen}")
                    if hrs > SLA_HOURS and not inc["sla_breached"]:
                        inc["sla_breached"] = True
                        audit("sla_breach", "Watchdog", incident=inc["id"], summary="SLA 2 h breached, no ack")
                        notify(inc, "reminder", f"REMINDER: {inc['id']} unacknowledged past SLA")
                for act in inc["actions"]:
                    if act["status"] == "active" and datetime.fromisoformat(act["expires_at"]) < now():
                        act["status"] = "expired"
                        audit("action_expired", "Watchdog", incident=inc["id"], target=act["target"])
            active = [i for i in S.incidents.values() if i["status"] in ("open", "acknowledged")]
            if risk_index() >= THRESHOLD and active:
                S.history.append({"t": iso(now()), "risk_index": risk_index()})  # show the peak
                audit("threshold_crossed", "Saguaro", risk_index=risk_index(), summary=f"Risk {risk_index()} ≥ {THRESHOLD}")
                for inc in active:
                    apply_containment(inc, "autonomous", "Needle")
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
def risk():
    with lock:
        idx = risk_index()
        return {"risk_index": idx, "band": band(idx), "raw_score": round(raw_score(), 1), "threshold": THRESHOLD,
                "open_incidents": [i for i, v in S.incidents.items() if v["status"] in ("open", "acknowledged")],
                "history": S.history}


@app.get("/incidents")
def incidents():
    with lock:
        return list(S.incidents.values())


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
        audit("decision", "Operator", operator=op, incident=iid, decision=dec, justification=just)
        if dec == "approve":
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


@app.post("/incidents/{iid}/rollback")
def rollback(iid: str, body: dict = Body(...)):
    return _close_actions(iid, body, "rolled_back", "rollback")


@app.post("/incidents/{iid}/permanent")
def permanent(iid: str, body: dict = Body(...)):
    return _close_actions(iid, body, "permanent", "permanent")


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


@app.get("/blocklist")
def blocklist():
    with lock:
        ips, users = set(), set()
        for inc in S.incidents.values():
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


@app.post("/chat/clear")
def clear_chat():
    with lock:
        S.chat = []
    return {"ok": True}


@app.post("/demo/reset")
def reset():
    global S
    with lock:
        S = State()
        audit("demo_reset", "Saguaro", summary="Demo state cleared")
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
        audit("startup", "Saguaro", summary="FAKE core online")
    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("FAKE_CORE_PORT", "8900")), log_level="warning")
