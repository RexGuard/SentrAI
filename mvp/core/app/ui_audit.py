"""What the web dashboard's Audit trail page needs: the newest records in words, the chain check and who did what.

Same wording rules as the Streamlit console (sentrai_ui/shaping.py: agent_for, summarize_record,
admin_record_summary, build_activity_feed, agent_table), in plain Python.
"""
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Query

from .ui_approvals import category_label, parse_ts

LEGACY_AGENTS = {
    "Saguaro": "Warden", "Needle": "Countersign", "Root": "Gatehouse", "Reservoir": "Vault",
    "SpineNet": "Watchtower", "Spine-Net": "Watchtower", "AreoleLinux": "Garrison-Linux",
    "Areole-Linux": "Garrison-Linux", "AreoleWin": "Garrison-Win", "Areole-Win": "Garrison-Win",
}
TYPE_TO_AGENT = {
    "event": "Warden", "incident_opened": "Warden", "incident_updated": "Warden", "classification": "Jev",
    "risk_update": "Warden", "threshold_crossed": "Warden", "snapshot": "Garrison-Linux",
    "action_proposed": "Gatehouse", "action_approved": "Countersign", "review": "Countersign",
    "action_applied": "Garrison-Linux", "containment": "Garrison-Linux", "action_expired": "Watchdog",
    "notification_queued": "Scribe", "notification_delivered": "Scribe", "report_generated": "Scribe",
    "reminder": "Watchdog", "sla_breach": "Watchdog",
}
OPERATOR_TYPES = ("ack", "decision", "rollback", "permanent", "operator")
TYPE_LABELS = {"needle_review": "countersign review", "admin_action": "admin work", "admin_confirmed": "this was me",
               "admin_distrusted": "not me", "admin_changed": "administrators changed",
               "admin_signed_in": "dashboard sign-in"}


def agent_label(name: Any) -> Any:
    return LEGACY_AGENTS.get(name, name) if isinstance(name, str) else name


def short_time(value: Any) -> str:
    ts = parse_ts(value)
    return ts.strftime("%H:%M:%S") if ts else (str(value) if value else "-")


def day_time(value: Any) -> str:
    ts = parse_ts(value)
    return f"{ts.day} {ts.strftime('%b %H:%M')}" if ts else (str(value) if value else "-")


def short_hash(value: Any, n: int = 8) -> str:
    if not value:
        return "-"
    return str(value)[:n] + "…" if len(str(value)) > n else str(value)


def agent_for(record: dict) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    for key in ("agent", "actor", "by"):
        name = data.get(key) or record.get(key)
        if name:
            if str(name).lower() == "operator" and data.get("operator"):
                return f"Operator:{data['operator']}"
            return str(agent_label(str(name)))
    rtype = str(record.get("type") or "")
    if any(rtype.startswith(t) for t in OPERATOR_TYPES):
        op = data.get("operator") or data.get("acked_by")
        return f"Operator:{op}" if op else "Operator"
    return TYPE_TO_AGENT.get(rtype, "Scribe")


def admin_summary(rtype: str, data: dict) -> str:
    who, host = data.get("user") or "?", data.get("host") or "?"
    if rtype == "admin_action":
        text = f"{who} on {host}: {data.get('what') or data.get('raw') or 'root work'}"
        would = data.get("would_be")
        return text + (f" (would have been: {category_label(would)})" if would and would != "benign" else "")
    op = data.get("operator") or "someone"
    if rtype == "admin_confirmed":
        learned = [str(x) for x in data.get("learned") or []]
        return f"{op} said this was them" + (f"; now known: {', '.join(learned)}" if learned else "")
    if rtype == "admin_distrusted":
        gone = [str(x) for x in data.get("forgotten") or []]
        return f"{op} said this was not them" + (f"; forgotten: {', '.join(gone)}" if gone else "")
    if rtype == "admin_changed":
        verb = "forgot" if data.get("action") == "forget" else "added"
        label = f" ({data['label']})" if data.get("label") else ""
        where = f" on {data['host']}" if data.get("host") else ""
        return f"{op} {verb} {data.get('kind') or 'an entry'} {data.get('value') or ''}{label}{where}".rstrip()
    if rtype == "admin_signed_in":
        return (f"{data.get('email') or 'someone'} signed in as {data.get('role') or '?'} from "
                f"{data.get('address') or '?'}: an administrator's address until {day_time(data.get('until'))}")
    return ""


def summarize(record: dict) -> str:
    data = record.get("data") if isinstance(record.get("data"), dict) else {}
    rtype = str(record.get("type") or "")
    if rtype.startswith("admin_") and (text := admin_summary(rtype, data)):
        return text
    for key in ("summary", "message", "text", "detail", "explanation"):
        if data.get(key):
            return str(data[key])
    parts = [f"{k}={data[k]}" for k in ("incident", "incident_id", "id", "category", "decision", "target",
                                        "risk_index", "channel", "status") if k in data and data[k] not in (None, "")]
    return ", ".join(parts[:5]) or str(record.get("type") or "record")


def feed(records: list[dict], limit: int) -> list[dict]:
    ordered = sorted(records, key=lambda r: (r.get("seq") is None, r.get("seq") or 0))
    out = []
    for rec in reversed(ordered[-limit:]):
        out.append({"seq": rec.get("seq"), "time": short_time(rec.get("ts")),
                    "agent": agent_for(rec).replace("Operator:", "Operator · "),
                    "type": TYPE_LABELS.get(str(rec.get("type")), str(rec.get("type") or "-").replace("_", " ")),
                    "summary": summarize(rec), "hash": short_hash(rec.get("hash")), "ts": str(rec.get("ts") or "")})
    return out


def agent_table(agents: list[dict], records: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for rec in records:
        name = agent_for(rec).split(":", 1)[0]
        row = seen.setdefault(name, {"n": 0, "ts": None})
        row["n"] += 1
        ts = parse_ts(rec.get("ts"))
        if ts and (row["ts"] is None or ts > row["ts"]):
            row["ts"] = ts
    rows = [{"agent": agent_label(a.get("name")), "role": a.get("role") or "-",
             "can_act": "Yes" if a.get("can_execute") else "No"} for a in agents if isinstance(a, dict)]
    if not rows:
        rows = [{"agent": n, "role": "-", "can_act": "-"} for n in seen]
    for r in rows:
        hit = seen.get(r["agent"], {})
        r["records"] = hit.get("n", 0)
        r["last"] = hit["ts"].strftime("%H:%M:%S") if hit.get("ts") else "-"
    rows.sort(key=lambda r: -r["records"])
    return rows


def install(app: FastAPI, core: Any) -> None:
    @app.get("/ui/audit")
    def get_audit_page(limit: int = Query(60, ge=1, le=500)) -> dict[str, Any]:
        valid, bad = core.audit.verify_recent(wait=False)
        records = core.audit.snapshot()
        latest = sorted(records, key=lambda r: r.get("seq") or 0)[-max(limit, 200):]
        return {"chain_valid": valid, "first_invalid_seq": bad, "count": len(records),
                "head_hash": core.audit.head_hash(), "feed": feed(records, limit),
                "agents": agent_table(core.agents_status(), latest)}
