# 🛡️ Security Evidence Report

_Issued by **SentrAI**. A sentry doesn't chase you. It just guards the gate._

> 🔴 SLA breached · 🔴 No acknowledgement · 🔵 Autonomous containment · 🟢 Audit chain valid

**Report:** ER-RSK-2026-081  
**Incident:** RSK-2026-081 (brute_force, high, status contained)  
**Generated:** 2026-09-29T14:05:00+08:00

| Report Field | Value |
| --- | --- |
| Responsible Entity | Admin: John Doe (Sample) - ID SEC-409 - Shift Bravo |
| SLA Violation | Overdue by 4 h 30 min (Policy SLA: 2 hrs); not acknowledged |
| Forced Action Taken | Autonomous override engaged (approved by Needle): block_ip 203.0.113.45 (active). Temporary, TTL 2 h, reversible via rollback. |
| Proof of Non-Repudiation | Ack: none; 2 alert(s) delivered |
| Audit chain | VALID, head `b6b6b6b6b6b6b6b6...` |

## What happened

40 failed logins for 'admin' from 203.0.113.45 in 3 minutes, then an SQL injection attempt on /search.

- Host: portal (web), source IP: 203.0.113.45, user: admin
- Classified by: rules, AI confidence 0.94, points 23.5 (base 25), inaction penalty +30
- Recommended action: Block 203.0.113.45 for 2 h and rate-limit /login

## Incident timeline

| Time | Demo time | Event | Points |
| --- | --- | --- | --- |
| 2026-09-29T13:54:04+08:00 | +0:00 | Brute force detected on /login (+25) | +25 |
| 2026-09-29T13:55:04+08:00 | +1:00 | 1 h unacknowledged: inaction penalty +5 (total +5) | +5 |
| 2026-09-29T13:56:04+08:00 | +2:00 | SLA breached, team lead copied |  |
| 2026-09-29T14:00:34+08:00 | +6:30 | SQL injection on /search (+54) | +54 |
| 2026-09-29T14:00:40+08:00 | +6:36 | Autonomous containment: block_ip 203.0.113.45 (TTL 2 h) |  |

## Alerts and acknowledgement (non-repudiation)

- `ntf-0001` (incident_opened): Delivered 2026-09-29T13:54:06+08:00 via telegram (message_id 4242) to operator, Ack: none
- `ntf-0002` (sla_breach): Delivered 2026-09-29T13:56:05+08:00 via telegram+email (message_id 4250) to operator, lead, Ack: none

> Delivery receipts prove an alert reached the channel (message id + timestamp) and an acknowledgement proves the operator responded. Without an acknowledgement SentrAI cannot prove the alert was read, so it reports 'Delivered <ts>, Ack: none'.

## Approvals

| Time | By | Decision | Note |
| --- | --- | --- | --- |
| 2026-09-29T14:00:39+08:00 | Needle | approved | Risk 88 is over the tolerance of 80; block is temporary and reversible. |

## Containment actions

| Action | Type | Target | Mode | Approved by | Status | Expires | Snapshot |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ACT-0007 | block_ip | 203.0.113.45 | autonomous | Needle | active | 2026-09-29T14:02:40+08:00 | `070707070707` |

## Hash-chain proof

| Seq | Time | Type | Agent | Hash |
| --- | --- | --- | --- | --- |
| 1040 | 2026-09-29T13:54:00+08:00 | event | Collector | `0101010101010101...` |
| 1041 | 2026-09-29T13:54:01+08:00 | incident_opened | Saguaro | `0202020202020202...` |
| 1042 | 2026-09-29T13:54:02+08:00 | notification_delivered | Herald | `0303030303030303...` |
| 1043 | 2026-09-29T13:54:03+08:00 | needle_review | Needle | `0404040404040404...` |
| 1044 | 2026-09-29T13:54:04+08:00 | action_applied | Saguaro | `0505050505050505...` |

Chain valid: **True**. Head hash: `b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6`

_Durations are in demo hours (DEMO_SPEED=3600: 1 real minute = 60 demo hour(s))._

---

<sub>🛡️ SentrAI · ER-RSK-2026-081 · generated 2026-09-29T14:05:00+08:00 · chain head b6b6b6b6b6b6b6b6...</sub>
