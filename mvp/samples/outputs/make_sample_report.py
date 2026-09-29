"""Writes a sample Security Evidence Report (PDF + Markdown) from made-up data. Run from mvp/core."""
import sys; sys.path.insert(0, ".")
from app.reports import render_pdf, render_markdown
h = lambda i: f"{i:02x}" * 32
r = {"report_id": "ER-RSK-2026-081", "title": "Security Evidence Report", "generated_at": "2026-09-29T14:05:00+08:00",
 "incident_id": "RSK-2026-081",
 "incident": {"category": "brute_force", "severity": "high", "status": "contained", "host": "portal", "layer": "web",
   "src_ip": "203.0.113.45", "user": "admin", "opened_at": "2026-09-29T13:54:04+08:00", "classified_by": "rules",
   "ai_confidence": 0.94, "base_points": 25, "points": 23.5, "inaction_penalty": 30,
   "recommended_action": "Block 203.0.113.45 for 2 h and rate-limit /login",
   "explanation": "40 failed logins for 'admin' from 203.0.113.45 in 3 minutes, then an SQL injection attempt on /search."},
 "responsible_entity": "Admin: John Doe (Sample) - ID SEC-409 - Shift Bravo",
 "sla": {"breached": True, "summary": "Overdue by 4 h 30 min (Policy SLA: 2 hrs); not acknowledged"},
 "timeline_of_inaction": [
   {"ts": "2026-09-29T13:54:04+08:00", "demo_time": "+0:00", "kind": "opened", "event": "Brute force detected on /login (+25)", "points": 25},
   {"ts": "2026-09-29T13:55:04+08:00", "demo_time": "+1:00", "kind": "inaction_penalty", "event": "1 h unacknowledged: inaction penalty +5 (total +5)", "points": 5},
   {"ts": "2026-09-29T13:56:04+08:00", "demo_time": "+2:00", "kind": "sla_breach", "event": "SLA breached, team lead copied", "points": None},
   {"ts": "2026-09-29T14:00:34+08:00", "demo_time": "+6:30", "kind": "event", "event": "SQL injection on /search (+54)", "points": 54},
   {"ts": "2026-09-29T14:00:40+08:00", "demo_time": "+6:36", "kind": "containment", "event": "Autonomous containment: block_ip 203.0.113.45 (TTL 2 h)", "points": None}],
 "forced_action": {"taken": True, "summary": "Autonomous override engaged (approved by Needle): block_ip 203.0.113.45 (active). Temporary, TTL 2 h, reversible via rollback.",
   "actions": [{"action_id": "ACT-0007", "type": "block_ip", "target": "203.0.113.45", "mode": "autonomous", "approved_by": "Needle", "status": "active", "expires_at": "2026-09-29T14:02:40+08:00", "snapshot_hash": h(7)}]},
 "approvals": [{"ts": "2026-09-29T14:00:39+08:00", "by": "Needle", "decision": "approved", "note": "Risk 88 is over the tolerance of 80; block is temporary and reversible."}],
 "non_repudiation": {"acknowledged": False, "ack": "Ack: none", "deliveries": [
   {"notification": "ntf-0001", "kind": "incident_opened", "delivered": True, "line": "Delivered 2026-09-29T13:54:06+08:00 via telegram (message_id 4242) to operator, Ack: none"},
   {"notification": "ntf-0002", "kind": "sla_breach", "delivered": True, "line": "Delivered 2026-09-29T13:56:05+08:00 via telegram+email (message_id 4250) to operator, lead, Ack: none"}],
   "statement": "Delivery receipts prove an alert reached the channel (message id + timestamp) and an acknowledgement proves the operator responded. Without an acknowledgement SentrAI cannot prove the alert was read, so it reports 'Delivered <ts>, Ack: none'."},
 "audit_proof": {"chain_valid": True, "first_invalid_seq": None, "chain_head_hash": h(0xb6),
   "records": [{"seq": 1040 + i, "ts": "2026-09-29T13:54:0%d+08:00" % i, "type": t, "agent": a, "prev_hash": h(i), "hash": h(i + 1)}
               for i, (t, a) in enumerate([("event", "Collector"), ("incident_opened", "Saguaro"), ("notification_delivered", "Herald"), ("needle_review", "Needle"), ("action_applied", "Saguaro")])]},
 "demo_clock": {"demo_speed": 3600, "note": "Durations are in demo hours (DEMO_SPEED=3600: 1 real minute = 60 demo hour(s))."}}
out = sys.argv[1] if len(sys.argv) > 1 else "."
open(out + "/sample-evidence-report.pdf", "wb").write(render_pdf(r))
open(out + "/sample-evidence-report.md", "w").write(render_markdown(r))
