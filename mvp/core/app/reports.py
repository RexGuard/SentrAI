"""Scribe's Security Evidence Report (JSON, Markdown and PDF)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .clock import fmt_demo_hours, fmt_offset
from .pdfdoc import BOLD, MONO, Column, PdfDoc
from .saguaro import public

if TYPE_CHECKING:
    from .saguaro import Saguaro


def build_report(core: "Saguaro", iid: str) -> dict[str, Any]:
    with core.lock:
        inc = core._get(iid)
        now = core.clock.now()
        core._refresh_incident(inc, now)
        s = core.settings
        clock = core.clock
        opened = inc["_opened_ts"]

        unacked_end = inc["_acked_ts"] if inc["_acked_ts"] is not None else now
        unaddressed = clock.demo_hours(opened, unacked_end)
        overdue = max(0.0, unaddressed - s.sla_hours)
        breached = inc["sla_breached"]
        if breached:
            sla_summary = f"Overdue by {fmt_demo_hours(overdue)} (Policy SLA: {s.sla_hours:g} hrs)"
        else:
            sla_summary = f"Within SLA: {fmt_demo_hours(unaddressed)} of {s.sla_hours:g} hrs used"
        if inc["acked"]:
            sla_summary += f"; acknowledged by {inc['acked_by']} at {inc['acked_at']}"
        else:
            sla_summary += "; not acknowledged"

        # Timeline: recorded entries + derived hourly inaction penalties.
        entries: list[dict[str, Any]] = []
        for t in inc["timeline"]:
            entries.append({"_ts": t["_ts"], "ts": t["ts"], "kind": t["kind"], "event": t["text"], "points": t["points"]})
        hours_full = int(unaddressed)
        total = 0.0
        for h in range(1, hours_full + 1):
            if total >= s.penalty_cap:
                break
            total = min(s.penalty_cap, total + s.penalty_per_hour)
            ts = opened + clock.real_seconds(h)
            entries.append({"_ts": ts, "ts": clock.iso(ts), "kind": "inaction_penalty",
                            "event": f"{h} h unacknowledged: inaction penalty +{s.penalty_per_hour:g} (total +{total:g})",
                            "points": s.penalty_per_hour})
        entries.sort(key=lambda e: e["_ts"])
        timeline = []
        for e in entries:
            timeline.append({"ts": e["ts"], "demo_time": fmt_offset(clock.demo_hours(opened, e["_ts"])),
                             "kind": e["kind"], "event": e["event"], "points": e["points"]})

        auto = [a for a in inc["actions"] if a["mode"] == "autonomous"]
        op = [a for a in inc["actions"] if a["mode"] == "operator"]
        if auto:
            forced = {
                "taken": True,
                "summary": "Autonomous override engaged (approved by Needle): "
                           + "; ".join(f"{a['type']} {a['target']} ({a['status']})" for a in auto)
                           + f". Temporary, TTL {s.ttl_hours:g} h, reversible via rollback.",
            }
        elif op:
            forced = {"taken": False, "summary": "No forced action: operator-approved hotpatch: "
                      + "; ".join(f"{a['type']} {a['target']} ({a['status']})" for a in op)}
        else:
            forced = {"taken": False, "summary": "No containment action has been taken."}
        forced["actions"] = public(inc["actions"])

        ack_text = f"Ack: {inc['acked_by']} at {inc['acked_at']} via {inc['ack_channel']}" if inc["acked"] else "Ack: none"
        deliveries = []
        for n in core.notifications:
            if n["incident"] != iid:
                continue
            if n["delivered"]:
                line = f"Delivered {n['delivered_at']} via {n['channel']} (message_id {n['message_id']}) to {', '.join(n['recipients'])}, {ack_text}"
            else:
                line = f"Queued {n['created_at']} for {', '.join(n['recipients'])}; not delivered yet, no proof of delivery"
            deliveries.append({"notification": n["id"], "kind": n["kind"], "recipients": n["recipients"],
                               "created_at": n["created_at"], "delivered": n["delivered"],
                               "delivered_at": n["delivered_at"], "channel": n["channel"],
                               "message_id": n["message_id"], "line": line})

        chain_valid, bad_seq = core.audit.verify()
        records = [r for r in core.audit.records() if r["data"].get("incident") == iid]
        # Approvals: Needle's review of each containment (two-key rule) and every operator decision.
        approvals = []
        for r in records:
            if r["type"] == "needle_review":
                d = r["data"]
                approvals.append({"ts": r["ts"], "by": d.get("operator") or "Needle",
                                  "decision": "approved" if d.get("approved") else "denied",
                                  "note": d.get("reasoning") or ""})
        for d in inc.get("decisions", []):
            approvals.append({"ts": d.get("at"), "by": d.get("operator"), "decision": d.get("decision"),
                              "note": d.get("justification") or ""})
        approvals.sort(key=lambda a: a["ts"] or "")
        report = {
            "report_id": f"ER-{iid}",
            "title": "Security Evidence Report",
            "generated_at": clock.iso(now),
            "incident_id": iid,
            "incident": {k: inc[k] for k in (
                "category", "severity", "status", "host", "layer", "src_ip", "user", "opened_at", "classified_by",
                "ai_confidence", "base_points", "points", "inaction_penalty", "recommended_action", "explanation")},
            "responsible_entity": s.on_duty,
            "sla": {
                "policy_hours": s.sla_hours,
                "time_unaddressed_demo_hours": round(unaddressed, 2),
                "overdue_demo_hours": round(overdue, 2),
                "breached": breached,
                "summary": sla_summary,
            },
            "timeline_of_inaction": timeline,
            "forced_action": forced,
            "approvals": approvals,
            "non_repudiation": {
                "acknowledged": inc["acked"],
                "ack": ack_text,
                "deliveries": deliveries,
                "statement": "Delivery receipts prove an alert reached the channel (message id + timestamp) and an "
                             "acknowledgement proves the operator responded. Without an acknowledgement SentrAI cannot "
                             "prove the alert was read, so it reports 'Delivered <ts>, Ack: none'.",
            },
            "audit_proof": {
                "chain_valid": chain_valid,
                "first_invalid_seq": bad_seq,
                "chain_head_hash": core.audit.head_hash(),
                "records": [{"seq": r["seq"], "ts": r["ts"], "type": r["type"], "agent": r["data"].get("agent"),
                             "prev_hash": r["prev_hash"], "hash": r["hash"]} for r in records],
            },
            "demo_clock": {
                "demo_speed": s.demo_speed,
                "note": f"Durations are in demo hours (DEMO_SPEED={s.demo_speed:g}: 1 real minute = {s.demo_speed / 60:g} demo hour(s)).",
            },
        }
        reported: set[str] = core.__dict__.setdefault("_reported", set())
        if iid not in reported:  # log first generation only, so polling does not flood the chain
            reported.add(iid)
            core.scribe.record(core.scribe.name, "report_generated", {
                "incident": iid, "report_id": report["report_id"],
                "chain_head_hash": report["audit_proof"]["chain_head_hash"]})
        return report


def render_markdown(r: dict[str, Any]) -> str:
    inc = r["incident"]
    lines = [
        f"# {r['title']}",
        "",
        f"**Report:** {r['report_id']}  ",
        f"**Incident:** {r['incident_id']} ({inc['category']}, {inc['severity']}, status {inc['status']})  ",
        f"**Generated:** {r['generated_at']}",
        "",
        "| Report Field | Value |",
        "| --- | --- |",
        f"| Responsible Entity | {r['responsible_entity']} |",
        f"| SLA Violation | {r['sla']['summary']} |",
        f"| Forced Action Taken | {r['forced_action']['summary']} |",
        f"| Proof of Non-Repudiation | {r['non_repudiation']['ack']}; {sum(d['delivered'] for d in r['non_repudiation']['deliveries'])} alert(s) delivered |",
        f"| Audit chain | {'VALID' if r['audit_proof']['chain_valid'] else 'BROKEN at seq ' + str(r['audit_proof']['first_invalid_seq'])}, head `{r['audit_proof']['chain_head_hash'][:16]}...` |",
        "",
        "## What happened",
        "",
        f"{inc['explanation']}",
        "",
        f"- Host: {inc['host']} ({inc['layer']}), source IP: {inc['src_ip'] or 'n/a'}, user: {inc['user'] or 'n/a'}",
        f"- Classified by: {inc['classified_by']}, AI confidence {inc['ai_confidence']}, "
        f"points {inc['points']} (base {inc['base_points']}), inaction penalty +{inc['inaction_penalty']:g}",
        f"- Recommended action: {inc['recommended_action']}",
        "",
        "## Incident timeline",
        "",
        "| Time | Demo time | Event | Points |",
        "| --- | --- | --- | --- |",
    ]
    for t in r["timeline_of_inaction"]:
        pts = "" if t["points"] is None else (f"+{t['points']:g}" if t["points"] >= 0 else f"{t['points']:g}")
        lines.append(f"| {t['ts']} | {t['demo_time']} | {t['event'].replace('|', '/')} | {pts} |")
    lines += ["", "## Alerts and acknowledgement (non-repudiation)", ""]
    if r["non_repudiation"]["deliveries"]:
        for d in r["non_repudiation"]["deliveries"]:
            lines.append(f"- `{d['notification']}` ({d['kind']}): {d['line']}")
    else:
        lines.append("- No alerts were queued for this incident.")
    lines += ["", f"> {r['non_repudiation']['statement']}", "", "## Approvals", ""]
    if r["approvals"]:
        lines += ["| Time | By | Decision | Note |", "| --- | --- | --- | --- |"]
        for a in r["approvals"]:
            lines.append(f"| {a['ts']} | {a['by']} | {a['decision']} | {str(a['note']).replace('|', '/')} |")
    else:
        lines.append("None recorded.")
    lines += ["", "## Containment actions", ""]
    if r["forced_action"]["actions"]:
        lines += ["| Action | Type | Target | Mode | Approved by | Status | Expires | Snapshot |", "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for a in r["forced_action"]["actions"]:
            lines.append(f"| {a['action_id']} | {a['type']} | {a['target']} | {a['mode']} | {a['approved_by']} | "
                         f"{a['status']} | {a['expires_at'] or 'never'} | `{a['snapshot_hash'][:12]}` |")
    else:
        lines.append("None.")
    lines += ["", "## Hash-chain proof", "", "| Seq | Time | Type | Agent | Hash |", "| --- | --- | --- | --- | --- |"]
    for rec in r["audit_proof"]["records"]:
        lines.append(f"| {rec['seq']} | {rec['ts']} | {rec['type']} | {rec['agent']} | `{rec['hash'][:16]}...` |")
    lines += ["", f"Chain valid: **{r['audit_proof']['chain_valid']}**. Head hash: `{r['audit_proof']['chain_head_hash']}`",
              "", f"_{r['demo_clock']['note']}_", ""]
    return "\n".join(lines)


GREEN, RED = (0.12, 0.45, 0.25), (0.72, 0.13, 0.13)


def _ts(ts: Any) -> str:
    """'2026-09-28T13:54:04+00:00' -> '2026-09-28 13:54:04' so table columns stay narrow."""
    return str(ts or "-").replace("T", " ")[:19]


def render_pdf(r: dict[str, Any]) -> bytes:
    """The same content as the Markdown report, laid out for printing and sharing."""
    inc = r["incident"]
    proof = r["audit_proof"]
    doc = PdfDoc(title=f"{r['title']} {r['report_id']}",
                 footer=f"SentrAI  |  {r['report_id']}  |  generated {r['generated_at']}  |  chain head {proof['chain_head_hash'][:16]}...")

    # Title band across the top of page 1
    top = doc.y + 42
    doc.rect(0, top - 88, 595.28, 88, (0.09, 0.27, 0.17))
    doc.text(42, top - 46, r["title"], BOLD, 21, (1, 1, 1))
    doc.text(42, top - 66, f"{r['report_id']}  |  incident {r['incident_id']} ({inc['category']}, {inc['severity']}, "
                           f"status {inc['status']})  |  generated {r['generated_at']}", size=8.5, color=(0.85, 0.93, 0.87))
    doc.y = top - 88 - 18

    chain_ok = proof["chain_valid"]
    chain_text = "VALID" if chain_ok else f"BROKEN at seq {proof['first_invalid_seq']}"
    delivered = sum(d["delivered"] for d in r["non_repudiation"]["deliveries"])
    doc.table([Column("Field", 1.1, BOLD), Column("Record", 3.4)], [
        ["Responsible entity", r["responsible_entity"]],
        ["SLA", r["sla"]["summary"]],
        ["Containment", r["forced_action"]["summary"]],
        ["Proof of delivery", f"{r['non_repudiation']['ack']}; {delivered} alert(s) delivered"],
        ["Audit chain", f"{chain_text}, head {proof['chain_head_hash']}"],
    ], size=9, colors=[None, RED if r["sla"]["breached"] else None, None,
                       RED if not r["non_repudiation"]["acknowledged"] else None, GREEN if chain_ok else RED])

    doc.heading("What happened")
    doc.paragraph(inc["explanation"])
    doc.bullet(f"Host: {inc['host']} ({inc['layer']}), source IP: {inc['src_ip'] or 'n/a'}, user: {inc['user'] or 'n/a'}")
    doc.bullet(f"Classified by: {inc['classified_by']}, AI confidence {inc['ai_confidence']}, points {inc['points']} "
               f"(base {inc['base_points']}), inaction penalty +{inc['inaction_penalty']:g}")
    doc.bullet(f"Recommended action: {inc['recommended_action']}")

    doc.heading("Incident timeline")
    rows = []
    for t in r["timeline_of_inaction"]:
        pts = "" if t["points"] is None else (f"+{t['points']:g}" if t["points"] >= 0 else f"{t['points']:g}")
        rows.append([_ts(t["ts"]), t["demo_time"], t["event"], pts])
    doc.table([Column("Time", 1.2), Column("Demo time", 0.7), Column("Event", 3.75), Column("Points", 0.5)], rows)

    doc.heading("Alerts and acknowledgement")
    if r["non_repudiation"]["deliveries"]:
        for d in r["non_repudiation"]["deliveries"]:
            doc.bullet(f"{d['notification']} ({d['kind']}): {d['line']}")
    else:
        doc.bullet("No alerts were queued for this incident.")
    doc.paragraph(r["non_repudiation"]["statement"], size=8.5, color=(0.4, 0.42, 0.4))

    doc.heading("Approvals")
    if r["approvals"]:
        doc.table([Column("Time", 1.2), Column("By", 0.8), Column("Decision", 0.7), Column("Note", 3.3)],
                  [[_ts(a["ts"]), a["by"], a["decision"], a["note"]] for a in r["approvals"]],
                  colors=[RED if a["decision"] in ("denied", "reject") else None for a in r["approvals"]])
    else:
        doc.paragraph("None recorded.")

    doc.heading("Containment actions")
    acts = r["forced_action"]["actions"]
    if acts:
        doc.table([Column("Action", 0.9), Column("Type", 0.8), Column("Target", 1.0), Column("Mode", 0.8),
                   Column("Approved by", 0.8), Column("Status", 0.65), Column("Expires", 1.25), Column("Snapshot", 0.85, MONO)],
                  [[a["action_id"], a["type"], a["target"], a["mode"], a["approved_by"], a["status"],
                    _ts(a["expires_at"]) if a["expires_at"] else "never", a["snapshot_hash"][:10]] for a in acts], size=8)
    else:
        doc.paragraph("None.")

    doc.heading("Hash-chain proof")
    doc.paragraph("Each audit record stores the hash of the one before it, so changing or deleting any record breaks "
                  "every hash after it. Re-check at any time with GET /audit.", size=8.5, color=(0.4, 0.42, 0.4))
    doc.table([Column("Seq", 0.4), Column("Time", 1.3), Column("Type", 1.1), Column("Agent", 0.75),
               Column("Previous hash", 1.2, MONO), Column("Hash", 1.2, MONO)],
              [[rec["seq"], _ts(rec["ts"]), rec["type"], rec["agent"], rec["prev_hash"][:16], rec["hash"][:16]]
               for rec in proof["records"]], size=7.5)
    doc.paragraph(f"Chain valid: {proof['chain_valid']}. Head hash: {proof['chain_head_hash']}", BOLD, 9,
                  GREEN if chain_ok else RED)
    doc.paragraph(r["demo_clock"]["note"], size=8, color=(0.4, 0.42, 0.4))
    return doc.to_bytes()
