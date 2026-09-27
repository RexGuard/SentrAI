"""Scribe's Executive Negligence / Non-repudiation report (JSON + Markdown)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .clock import fmt_demo_hours, fmt_offset
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
        report = {
            "report_id": f"NR-{iid}",
            "title": "Executive Negligence & Non-Repudiation Report",
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
            "non_repudiation": {
                "acknowledged": inc["acked"],
                "ack": ack_text,
                "deliveries": deliveries,
                "statement": "Delivery receipts prove an alert reached the channel (message id + timestamp) and an "
                             "acknowledgement proves the operator responded. Without an acknowledgement CactAI cannot "
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
        "## Timeline of inaction",
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
    lines += ["", f"> {r['non_repudiation']['statement']}", "", "## Containment actions", ""]
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
