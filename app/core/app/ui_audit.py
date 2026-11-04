"""What the web dashboard's Audit trail page needs: the newest records in words, the chain check and who did what.

Same wording rules as the Streamlit console (sentrai_ui/shaping.py: agent_for, summarize_record,
admin_record_summary, build_activity_feed, agent_table), in plain Python.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Body, FastAPI, HTTPException, Query, Response

from .pdfdoc import Column, PdfDoc
from .ui_approvals import category_label, parse_ts

PDF_MAX = 5000  # records in one PDF export

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


def date_line(value: Any) -> str:
    ts = parse_ts(value)
    return f"{ts.day} {ts.strftime('%b %Y')}" if ts else "-"


def entry(rec: dict) -> dict:
    """One record in words. `person` is the account or operator when a person did it, otherwise blank (an agent)."""
    who = agent_for(rec)
    person = who.split(":", 1)[1] if who.startswith("Operator:") else ("operator" if who == "Operator" else "")
    return {"seq": rec.get("seq"), "date": date_line(rec.get("ts")), "time": short_time(rec.get("ts")),
            "agent": who.replace("Operator:", "Operator · "), "person": person,
            "type": TYPE_LABELS.get(str(rec.get("type")), str(rec.get("type") or "-").replace("_", " ")),
            "summary": summarize(rec), "hash": short_hash(rec.get("hash")), "ts": str(rec.get("ts") or "")}


def in_order(records: list[dict]) -> list[dict]:
    """Oldest first, by sequence number: the order the actions were taken in."""
    return sorted(records, key=lambda r: (r.get("seq") is None, r.get("seq") or 0))


def feed(records: list[dict], limit: int, before: int | None = None) -> list[dict]:
    """The newest `limit` records (older than `before` when given), newest first."""
    ordered = in_order(records)
    if before is not None:
        ordered = [r for r in ordered if (r.get("seq") or 0) < before]
    return [entry(rec) for rec in reversed(ordered[-limit:])]


def render_pdf(rows: list[dict], chain_valid: bool | None, total: int) -> bytes:
    now = datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    doc = PdfDoc(title="SentrAI Activity Log", footer=f"SentrAI  |  Activity Log  |  exported {now}")
    doc.heading("Activity Log", 16)
    chain = "intact" if chain_valid else "broken" if chain_valid is False else "not checked yet"
    doc.paragraph(f"{len(rows)} of {total} records, in the order they happened. Hash chain {chain}.")
    doc.table([Column("When", 1.2), Column("#", 0.6), Column("Who", 1.3), Column("What was done", 4.0)],
              [[f"{r['date']} {r['time']}", r["seq"] if r["seq"] is not None else "-", r["agent"],
                f"{r['type']}: {r['summary']}"] for r in rows])
    return doc.to_bytes()


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
    def get_audit_page(limit: int = Query(60, ge=1, le=500), before: int | None = Query(None, ge=1)) -> dict[str, Any]:
        """The newest records, newest first; `before` (a #) pages back to older ones."""
        valid, bad = core.audit.verify_recent(wait=False)
        records = core.audit.snapshot()
        latest = sorted(records, key=lambda r: r.get("seq") or 0)[-max(limit, 200):]
        return {"chain_valid": valid, "first_invalid_seq": bad, "count": len(records),
                "head_hash": core.audit.head_hash(), "feed": feed(records, limit, before),
                "agents": agent_table(core.agents_status(), latest)}

    @app.post("/ui/audit/pdf")
    def post_audit_pdf(body: dict = Body(...)) -> Response:
        """Export to PDF: {"seqs": [#, ...]} for the chosen records, or {"all": true} for every record.
        Always oldest first, the order the actions were taken in."""
        records = in_order(core.audit.snapshot())
        if body.get("all") is True:
            chosen = records
        else:
            seqs = body.get("seqs")
            if not isinstance(seqs, list) or not seqs or not all(isinstance(x, int) for x in seqs):
                raise HTTPException(400, 'send {"seqs": [numbers]} or {"all": true}')
            want = set(seqs)
            chosen = [r for r in records if r.get("seq") in want]
        if len(chosen) > PDF_MAX:
            raise HTTPException(400, f"At most {PDF_MAX} records fit in one PDF. Pick fewer.")
        valid, _ = core.audit.verify_recent(wait=False)
        pdf = render_pdf([entry(r) for r in chosen], valid, len(records))
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": 'attachment; filename="sentrai-activity-log.pdf"'})
