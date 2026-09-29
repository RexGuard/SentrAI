# SentrAI

## Cybersecurity + AI

An accountability-based security system that follows **CIANA** and gives CXOs proof, not just alerts.

> *"A sentry doesn't chase you. It just guards the gate."*

All factual claims were verified on 27 Sep 2026; sources are in `mvp/research/SOURCES.md`. Items marked **[FILL]** still need input.

**How this document is organized**
- **Sections 1 to 3:** the problem, our principles and the team.
- **Part A, Final product (sections 4 to 14):** the full design we are building toward.
- **Part B, MVP product (sections 15 and 16):** what we built for the 29 Sep pitch and what the demo shows.

---

## 1. Problem & Target Organization

**Target:** Singapore SMEs and private education institutions that hold large amounts of personal data but have only one or two IT staff and no 24/7 security team.

**Problem statement**
> Small organizations already get security alerts. The breach happens because nobody acts on them in time, and afterwards nobody can prove who knew what and when.

**Why this target**
- They are bound by the PDPA. Since 1 Oct 2022, s48J lets the PDPC impose a financial penalty of up to S$1 million or 10% of annual Singapore turnover (where that turnover exceeds S$10M), whichever is higher. Source: PDPC Guide on Active Enforcement (Oct 2022), https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/other-guides/active-enforcement/guide-on-active-enforcement_oct2022.pdf
- They cannot afford a SOC, so alerts pile up (alert fatigue).
- Many PDPC enforcement decisions involve basic weaknesses left unfixed:
  - **ChampionTutor (Oct 2021, S$10,000), the video's opening hook.** A Dec 2020 pentest found an SQL-injection hole that was never fixed. By Feb 2021, 4,625 students' data was being sold on the dark web, and the company only learned of it from the PDPC. https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/decision--championtutor-inc-private-limited--10082021.pdf
  - **PPLingo / LingoAce ([2023] SGPDPC 12, published May 2024, S$74,000).** Its admin password was "lingoace123", unchanged for 2+ years, with no MFA, and was brute-forced. 557,144 users were affected, 303,238 of them students. https://www.pdpc.gov.sg/-/media/files/pdpc/pdf-files/commissions-decisions/gd_pplingo-pte-ltd-(revised)_241023.pdf
  - **North London Collegiate School (Singapore) (Feb 2022, S$10,000).** Applicants' passports, NRICs and birth certificates sat in a website folder that search engines indexed, protected only by robots.txt. https://www.pdpc.gov.sg/-/media/Files/PDPC/PDF-Files/Commissions-Decisions/Decision---NLCS---01122021.pdf
- Alert fatigue: SOC teams receive ~4,484 alerts a day and ignore 67% of them (Vectra AI, 2023 State of Threat Detection, vendor survey of 2,000 SOC analysts). https://www.vectra.ai/resources/2023-state-of-threat-detection

**Customer hypothesis (not yet validated)**
> We have not tested this positioning with a real customer. Treat it as a working assumption for the pitch, not a validated finding.

- **Initial wedge:** small Singapore tuition and private education businesses with limited IT support. Other Singapore SMEs remain future customers once the wedge is proven.
- **Everyday user:** the IT administrator or outsourced IT provider who watches the alerts.
- **Buyer:** the business owner or operations head who signs off on spend.
- **Central promise:** help small teams act on security warnings before they become prolonged incidents, with a clear record of the response.

## What if humans were not enough

Human errors are bound to happen. Humans stay in charge, but when the risk crosses the tolerance the organization itself set, SentrAI applies a **temporary, reversible** fix and records exactly who was warned and when.

## Accountability Based System

To minimize the risk of human error, our team has formulated a plan that can be turned into a system: every alert, acknowledgement and action is recorded in a tamper-evident log, so responsibility is always provable.

---

## 2. Two Principles: CIA + NA

| CIA | NA |
| --- | --- |
| **Confidentiality** | **Non-repudiation** |
| **Integrity** | **Authentication** |
| **Availability** | |

---

## 3. Team Members & Roles

| Member | Role | Owns | Deliverable for the 29th |
| --- | --- | --- | --- |
| **Erick Sientaro** | Developer | Demo lab, collectors, risk engine, Jev integration, hotpatch playbooks, dashboard, Telegram bot | Working demo |
| **Ishmail** | CEO | Problem story, business case, pitch narration, final call on scope | Pitch script and video narration |
| **Hozen** | Notetaker | Meeting notes, this document, keeping sources in `mvp/research/SOURCES.md` current, slide content, recording checklist | Slides and verified sources |

Erick carries the whole build, so the MVP (section 15) is scoped to what one developer can finish in two days.

---

# Part A: Final Product

The full design SentrAI is built toward. Part B (section 15) says which pieces the MVP already runs.

## 4. How SentrAI Gets the Data from Each System Layer

Lightweight collector agents on each host read logs the system already produces. Nothing is installed inside the application code.

| Layer | Data source | What we look for | How we collect it |
| --- | --- | --- | --- |
| Web application | Nginx/Apache access log, app auth log, ModSecurity WAF log | Failed logins, SQLi/XSS payloads, 4xx/5xx spikes | Python agent tails log files |
| Database | PostgreSQL `pgaudit` / MySQL audit log | Bulk `SELECT`/`COPY` off-hours, new DB users, privilege grants | Tail audit log, poll `pg_stat_activity` |
| OS (Linux) | `/var/log/auth.log`, `auditd`, `journald`, process list (`psutil`), open ports (`ss -tulpn`) | Web server spawning a shell, new SUID files, new listening ports | Python agent + `psutil` |
| OS (Windows) | Windows Event Log (4625 failed logon, 4688 process creation, 4720 user created), Sysmon | Same as above | `pywin32` / `wevtutil` |
| Network | Suricata or Zeek alerts, firewall drop logs | Port scans, brute force, beaconing | Read `eve.json` |
| Cloud config | AWS API (S3 bucket ACLs, security groups, IAM) | Public buckets, port 22 open to 0.0.0.0/0 | `boto3` scheduled scan |

**Flow:** Collector → normalize to one JSON event format (section 14) → Redis stream → Rules + Jev classifier → Risk Engine → Dashboard / Notifier / Responder.

The MVP covers only the **web, database and OS** layers, read from the demo portal's log files (section 15).

---

## 5. Risk Level: How It Is Calculated

### Base severity

| Severity | Base Score | Example Anomalies |
| --- | --- | --- |
| Low | +5 to +10 | 5 failed logins on admin, SSL certificate expiring soon |
| Medium | +15 to +25 | Port scan detected, unusual admin login time |
| High | +30 to +45 | SQL injection payload detected, brute force on admin portal |
| Critical | +50 to +70 | Web server spawned a shell, bulk database dump during off-hours |

### Formula (0 to 100 index)

A 0 to 100 index is appropriate: executives read it instantly and it maps cleanly to traffic-light bands. Plain addition can pass 100 (Critical +70 plus penalties), so the raw points are passed through a curve that can never exceed 100.

```
event_points  = base_severity × ai_confidence × asset_criticality
raw_score     = Σ open event_points + inaction_penalty − resolved_decay
risk_index    = round(100 × (1 − e^(−raw_score / 60)))
```

- `ai_confidence`: 0.5 to 1.0, from Jev (section 6).
- `asset_criticality`: 1.0 normal, 1.5 holds PII, 2.0 crown jewels.
- `inaction_penalty`: +5 per hour per unacknowledged incident, capped at +30 per incident.
- `resolved_decay`: points of an incident are removed once it is fixed and verified.

Examples: raw 35 → **44**, raw 70 → **69**, raw 97 → **80**, raw 140 → **90**.

### Risk tolerance bands (threshold configurable per organization)

| Index | Band | What happens |
| --- | --- | --- |
| 0 to 29 | Green | Logged only |
| 30 to 59 | Amber | Operator notified, guided fix offered |
| 60 to 79 | Red | Hourly reminders, supervisor copied |
| 80 to 100 | Critical | Autonomous temporary containment + evidence report |

### Risk Escalation Over Time

The inaction penalty is what makes the index climb while nobody acts. Slide graphic: plot the index against time for the demo incident, marking when each alert was sent and when the 80 threshold was crossed.

---

## 6. AI Risk Categorization with Jev (TypeSafe System One)

**Jev** is TypeSafe's System One model. It answers narrow, structured questions about text and returns typed answers with probabilities, in about 100 ms per query. Code keeps control of the workflow; Jev only makes the judgment calls. Python SDK: `typesafe_sdk`.

**Three-stage pipeline**
1. **Rules (microseconds, local):** signatures for obvious cases (`UNION SELECT`, 5 failed logins in 60 s). Confidence fixed at 1.0. Also groups raw log lines into events so Jev is not called on every line.
2. **Jev (≈100 ms):** classifies every event the rules cannot settle. Its probability becomes the **AI Confidence Factor**.
3. **Claude (seconds, off the hot path):** writes the plain-English explanation, recommended fix text and the evidence report. It never sets the score or runs commands.

**Questions asked to Jev in parallel over one event**

```python
# pip install typesafe-sdk   ; set TYPESAFE_API_KEY in the environment
from typesafe_sdk import Choice, Noul, TypeSafeClient

state = {"event": {"layer": "web", "raw": "POST /login 401 user=admin src=203.0.113.45"}}

questions = {
    "category": Choice(
        instructions="What kind of activity does `event.raw` show?",
        criteria={
            "benign": "Normal user or system activity",
            "brute_force": "Repeated login/password guessing",
            "sql_injection": "SQL syntax injected into input",
            "xss": "Script/HTML injected into input",
            "port_scan": "Probing many ports or services",
            "privilege_escalation": "Gaining higher rights than granted",
            "data_exfiltration": "Unusual bulk data leaving the system",
            "misconfiguration": "Insecure setting or exposed resource",
        },
    ),
    "malicious": Noul(
        instructions="Is `event.raw` likely part of an attack rather than normal use?"
    ),
}

with TypeSafeClient() as client:        # model defaults to jev-latest
    answer = client.system_one(state=state, questions=questions)

category = answer.choices["category"].choice
ai_confidence = min(1.0, max(0.5, answer.choices["category"].probabilities[category]))
p_malicious = answer.nouls["malicious"].noul   # P(yes), 0 to 1
```

- `category` picks the base severity from the table in section 5.
- The probability of the chosen category, clipped to 0.5 to 1.0, is the `ai_confidence`.
- **Confidence-gated routing:** if Jev is uncertain (0.4 to 0.6), no automatic action is taken; the event goes to the operator as "needs review".

SDK fields verified against https://docs.typesafe.ai/sdk/python.md and https://docs.typesafe.ai/api.md (27 Sep 2026). Install `typesafe-sdk`; auth via `TYPESAFE_API_KEY` (from https://console.typesafe.ai/). Choice answers expose `.choice`, `.probabilities` and `.confidence`; Noul answers expose `.noul` (P(yes)). Docs claim "about 100 ms" per query. **[FILL]** get a TypeSafe API key before building.

---

## 7. Main Features

### Risk Tolerance Monitoring

Monitors the current risk index against the organization's threshold. If the index crosses it, corrective action is taken (section 8).

### Preventive Actions

- **Proactive Scanning & Asset Monitoring:** daily scans of every monitored endpoint.
- **Early-Warning Risk Scoring:** risk rises before an incident, not after.
- **Guided Operator Mitigations:** AI-recommended one-click fixes offered before the threshold is reached.
- **Baseline State Preservation:** signed backup/snapshot taken before any corrective action is needed.

**Example incident card (vulnerability feed)**
> **VULN-ID #2 · Critical · Exposure**
> Unencrypted production database dump `db_prod_members_backup.sql` found on public bucket `s3://aegis-temp-dev-share` (ACL `public-read`).
> Cause: an employee uploaded a manual dump to troubleshoot, bypassing standard IAM and encryption policy.
> Records at risk: 1,240,000 PII · AI confidence: 99.8%
> Recommended: remove the public ACL, enable default encryption, rotate DB credentials.

Dashboard tile (mockup data): **Endpoints Monitored 1,482 · +10% daily coverage**

> "Our Preventive Actions maintain continuous hygiene through daily scanning, enforce accountability by penalizing unaddressed risks with +5 points per hour, offer guided one-click operator fixes to cool down the risk gauge, and maintain cryptographically signed baseline backups before any threat can materialize."

### Corrective Actions

- **Emergency State Freeze:** captures a read-only snapshot of critical system components.
- **Autonomous Containment & Temporary Fixes:** deploys defensive firewall rules, isolates compromised components and terminates malicious connections (section 8).
- **Non-repudiation Report:** end-to-end audit report covering root cause, affected components, system modifications and incident timeline.
- **Human Handoff & Rollback:** technical and incident reports go to the operator for review and recovery.

---

## 8. Temporary Hotpatch Workflow

```
Detect → Snapshot → Pick playbook → Apply with TTL → Verify → Notify → Human decides
```

1. **Detect:** risk index crosses the threshold, or the operator presses Approve & Patch.
2. **Snapshot:** save current firewall rules, affected config files, account states and DB role grants. Hash and sign the snapshot.
3. **Pick playbook:** only from a pre-approved allowlist, matched to the category:
   - `brute_force` → block IP (`iptables`), lock account, enable rate limit
   - `sql_injection` → add WAF rule, block IP
   - `privilege_escalation` / shell spawned → kill process, isolate container/host from the network
   - `data_exfiltration` → revoke the DB session, block outbound traffic to the destination
   - `misconfiguration` (public S3 / open port 22) → remove the public ACL, restrict the security group to an allowlist
4. **Apply with TTL:** every hotpatch expires (default 2 h) unless a human makes it permanent, so temporary fixes never silently become permanent config drift.
5. **Verify:** re-run the check (retry the attack signature, re-scan the port). If the fix failed or broke a health check, roll back automatically from the snapshot.
6. **Notify:** send what changed, with a one-click Rollback.
7. **Human decides:** Make Permanent / Extend / Rollback, with a justification written to the audit log.

---

## 9. Notification to Operator

**Channels:** dashboard (always) → Telegram bot (MVP) → email (backup). SMS/phone call on the roadmap.

**Escalation ladder**

| Trigger | Who is notified |
| --- | --- |
| Incident opened (Amber) | On-duty operator |
| No acknowledgement after SLA (default 2 h) | Operator reminder + team lead |
| Red band | Team lead + IT manager |
| Critical / autonomous action | IT manager + CXO, evidence report attached |

**Non-repudiation, stated honestly:** we can prove an alert was *delivered* (Telegram message ID and timestamp) and *acknowledged* (button press tied to the operator's account). If no button is pressed we cannot prove it was *read*, so the report says "Delivered 14:00, Ack: none" rather than "the admin saw it". Every notification and acknowledgement is appended to the hash chain.

---

## 10. Executive Escalation & Accountability Workflow

### Metadata

Every action taken is stored in a hash-chained audit log: each record carries the hash of the previous one, so any edit or deletion breaks the chain and is detectable.

### "Higher-Ups" Evidence Report

| Report Field | Prototype Data Example | Why Higher-Ups Need This |
| --- | --- | --- |
| Responsible Entity | Admin: John Doe (ID: SEC-409) / Shift Bravo | Identifies who was on duty during the inaction window |
| SLA Violation | Overdue by 7 hrs 15 mins (Policy SLA: 2 hrs) | Clear metric proving operational neglect against company policy |
| Timeline of Inaction | 14:00 anomaly detected (+25) · 16:00 reminder 1 (+10) · 21:00 critical limit breached (+45) | Proves progressive neglect, not a sudden incident |
| Forced Action Taken | Autonomous override engaged: port 22 isolated | Shows the AI had to step in because no human responded |
| Proof of Non-Repudiation | Delivered to operator @ 14:00 (Ack: none) | Hash-chained delivery receipt removes the "I was never notified" excuse |

### Active Risk Registry Data Schema

| Field | Example Value | Description |
| --- | --- | --- |
| Risk ID | RSK-2026-081 | Unique incident tracker |
| Detected Anomaly | Unrestricted SSH port 22 open | Identified by breach scanner |
| Base Risk Points | +20 pts | Initial severity weight |
| Time Unaddressed | 3 hours | Time since alert without response |
| Inaction Penalty | +15 pts | 3 hrs × 5 pts/hr |
| Current Risk Contribution | 35 pts | Base + inaction penalty |
| Recommended Preventive Action | Apply IP whitelist rule to port 22 | AI-suggested preventive fix |
| Action Buttons | [Approve & Patch] or [Reject with Justification] | The only two ways to clear this risk |

> "Most security platforms stop at alerting the administrator. Our system introduces true administrative accountability: if an operator neglects warnings and allows the risk score to breach the tolerance threshold, the system not only takes autonomous corrective action to protect the company, but it also compiles an immutable Executive Evidence Report for leadership, proving the timeline of inaction with non-repudiable audit receipts."

---

## 11. Ethics of the Sentry Response

*Left alone, a sentry does no harm. Try to get past it, and it stops you.*

**Position: SentrAI never attacks back. It holds the line and never crosses it.**

Why "hack back" is ruled out:
- **Illegal:** accessing or disrupting the attacker's machine without authorization is an offence under Singapore's Computer Misuse Act 1993, whatever the motive. Unauthorised access is s3 (up to S$5,000 and/or 2 years, first offence). Unauthorised modification is s5, and unauthorised obstruction/interference ("interferes with, or interrupts or obstructs") is s7 (each up to S$10,000 and/or 3 years). https://sso.agc.gov.sg/Act/CMA1993
- **Wrong target:** attacks usually come through spoofed IPs, VPNs or hijacked innocent computers. Striking back hurts a victim.
- **Escalation:** retaliation invites a bigger attack and exposes the company to liability.

What the "prick" actually is (all inside our own perimeter):
- **Block and isolate:** firewall rule, account lock, rate limit.
- **Tarpit:** slow the attacker's connections so the attack becomes expensive.
- **Deception:** honeypot login pages, honeytoken DB rows and credentials. Any touch is a near-certain alert.
- **Evidence:** preserve logs and hand them to SingCERT or the police. The attacker is pricked by attribution and prosecution, not retaliation.

**In the MVP:** the demo portal has a honeypot login page, a planted credential, bait member rows and a tarpit, all off by default (`run_demo -Tripwires`). Any touch becomes a confidence 1.0 incident (see `mvp/lab/README.md`).

---

## 12. Agentic Multi-Agent Design

Each agent specializes in one layer or OS, which gives a different approach for each computer system.

| Agent | Equivalent in the reference team | Does | Can execute? |
| --- | --- | --- | --- |
| **Warden** (Lead / Orchestrator) | Dumbledore (CEO) | Receives incidents, delegates, merges findings, owns the risk index | No |
| **Gatehouse** (Web layer) | Ron (CTO) | Reads web/WAF logs, proposes WAF rules | Propose only |
| **Watchtower** (Network / Scanner) | Fred + Scanner | Scans own assets, reads Suricata alerts | Propose only |
| **Vault** (Database / Storage) | George (Storage) | DB audit log, backups, S3 checks | Propose only |
| **Garrison-Linux / Garrison-Win** (OS agents) | Arthur Weasley (Security Engineer) | Linux: auditd/iptables. Windows: Event Log/`netsh advfirewall` | Runs allowlisted playbooks |
| **Countersign** (Reviewer) | Mad-Eye Moody | Must approve every autonomous action (two-key rule) | Approve/deny only |
| **Watchdog** | Watchdog | Heartbeats; alerts if any agent or collector goes silent | No |
| **Scribe** (Auditor) | (new) | Writes the hash-chained log and evidence report | Write-only log |
| **Help Desk** | Help Desk | Answers operator questions in Telegram ("why was my IP blocked?") | No |

**Safety rules**
- No agent gets a free shell. Execution happens only through allowlisted playbooks with a TTL.
- Every autonomous action needs Countersign's approval.
- Jev and Claude judge and explain; deterministic code scores and executes.

**In the MVP:** the agents are Python classes inside the core, with Warden calling them in turn (section 15). Separate agent services are on the roadmap.

---

## 13. Programming Language & Stack

**Target stack.** The MVP (section 15) uses Python throughout, stores state in memory plus the audit chain, and needs no Redis or Docker.

| Part | Tool |
| --- | --- |
| Collectors | Python (`psutil`, file tailing, `boto3`) |
| AI categorization | Jev via `typesafe_sdk`; Claude for reports |
| Core API | FastAPI |
| Dashboard | Streamlit |
| Notifications | `python-telegram-bot` |
| Storage | SQLite + Redis streams |
| Lab | Docker Compose |

Roadmap: production collectors rewritten in Go or Rust for a small single-binary footprint.

---

## 14. Specific Inputs & Outputs

**Input: normalized event (from any collector)**
```json
{
  "event_id": "evt-20260929-000142",
  "timestamp": "2026-09-29T14:00:03+08:00",
  "host": "web-01",
  "layer": "web",
  "source": "nginx_access",
  "src_ip": "203.0.113.45",
  "user": "admin",
  "raw": "POST /login 401 ...",
  "asset_criticality": 1.5
}
```

**Output 1: classification (Jev)**
```json
{ "event_id": "evt-20260929-000142", "category": "brute_force",
  "severity": "high", "base_points": 30, "ai_confidence": 0.94, "points": 42.3 }
```

**Output 2: risk update (to dashboard)**
```json
{ "timestamp": "2026-09-29T14:00:04+08:00", "risk_index": 44, "band": "amber",
  "open_incidents": ["RSK-2026-081"] }
```

**Output 3: operator alert (Telegram)**
> ⚠️ RSK-2026-081 · Brute force on admin login (web-01) · Risk 44/100
> Recommended: block 203.0.113.45 for 2 h and enforce a login rate limit.
> [Approve & Patch] [Reject with Justification]

**Output 4: containment action record**
```json
{ "action_id": "act-0007", "incident": "RSK-2026-081", "type": "block_ip",
  "target": "203.0.113.45", "ttl_hours": 2, "mode": "autonomous",
  "approved_by": "Countersign", "prev_hash": "9f2c…", "hash": "b71a…" }
```

**Output 5: evidence / non-repudiation report** (PDF + JSON): incident timeline, alerts sent, acknowledgements, SLA breach, action taken, rollback status, hash-chain proof.

---

# Part B: MVP Product

What we built for the 29 Sep pitch and what the demo video shows. The code is in `mvp/` of the repo; `mvp/README.md` has the full run instructions.

## 15. System Workflow & Minimum Viable Prototype

Everything runs natively on one Windows laptop (Python, no Docker, no Redis). One command, `run_demo.ps1`, starts every component in its own window.

**Components**
1. **Target app** (`lab/target_app/`, port 5000): the fictional "Aegis Academy Student Portal". It writes web, login, database and OS logs, and it enforces SentrAI's blocklist by answering blocked IPs and accounts with HTTP 403 "Blocked by SentrAI".
2. **Core** (`core/`, port 8000): FastAPI with the risk engine, the agents (Warden, Gatehouse, Watchtower, Vault, Garrison, Countersign, Watchdog, Scribe, Help Desk) as Python classes in one process, TTL hotpatches, the hash-chained audit log and the evidence reports. The generated report is titled "Security Evidence Report" and downloads as Markdown, JSON or PDF.
3. **Dashboard** (`dashboard/`, port 8501): Streamlit console (see below).
4. **Notifier** (`notifier/`): Telegram bot with Approve / Reject buttons, or console output when no bot token is set.
5. **Attack and replay scripts** (`lab/attacks/`, `lab/replay/`): benign traffic, brute force, SQL injection, bulk export and a simulated shell. They refuse any target other than localhost:5000.

**The three pluggable parts**

SentrAI is a pipeline of three parts. Each is one small base class with one job, so a new log source, detector or fix can be added without touching the rest.

| Part | What it does | Base class | Built-in versions |
| --- | --- | --- | --- |
| 1. Collector | Reads logs and turns them into events for the core (`POST /events`) | `Source` | `JsonLogSource` (tails the portal's logs), `HeartbeatSource` |
| 2. Classifier | Decides what each event is; the first classifier that answers wins | `Classifier` | `RulesClassifier` → `JevClassifier` → `FallbackClassifier` |
| 3. Action taker (responder) | Applies a temporary fix and undoes it on expiry or rollback | `Responder` | `BlocklistResponder` (block IP, lock account), `SimulatedResponder` (the rest) |

Between parts 2 and 3 sit the risk engine and Countersign: an action only reaches a responder after an operator approves it, or after Countersign approves it once risk crosses the threshold. This also prepares us for the surprise features at the 2 to 3 Nov hackathon, which can slot in as a new source, classifier or responder.

**First-run setup wizard**

On a new machine, `run_demo.ps1` first asks a few questions, one section per part:
1. **Collector:** logs directory and log file names.
2. **Classifier:** brute-force and bulk-export thresholds, TypeSafe (Jev) API key.
3. **Responder:** risk threshold, block expiry, SLA, and IPs and accounts that must never be touched.
4. **Notifications:** Telegram bot token and chat ID.

Pressing Enter keeps the demo defaults. Answers are saved to `%USERPROFILE%\.cactai\config.json` and read by every component on start. Change them later with `python cactai_config.py setup` or on the dashboard's Configuration page.

**Dashboard**

A sidebar menu, opening on Configuration:
- **Decide:** Approvals (requests waiting on a person, with Approve, Reject, Rollback and Make Permanent).
- **Pipeline:** Collector, Classifier and Action taker, one page per part. A red bubble on each button counts the new malicious activity that reached that part since it was last opened.
- **Oversight:** Review (0 to 100 gauge, threshold and risk accumulated), Reports (one evidence report per incident) and Audit trail (every step, hash-chained, with a "chain valid" check).

**Demo script (about 1 minute of video at `-DemoSpeed 600`, run by `lab/scenario.py`)**
1. Benign staff traffic: no incidents, gauge green.
2. Brute force from `203.0.113.45`: incident `RSK-2026-081`, risk about 39 (amber), operator alert on Telegram or in the notifier window, Collector and Classifier bubbles light up.
3. Nobody acknowledges: demo time runs fast (1 real minute = 10 demo hours) and the inaction penalty adds +5 per demo hour. The script's default 6-second pause is only about 1 demo hour, under the 2-hour SLA, so no SLA reminder fires; run `scenario.py --pause 15` (about 2.5 demo hours) to show one on camera.
4. SQL injection from `198.51.100.23`: risk crosses 80, Countersign approves, both attacker IPs are blocked and `admin` is locked for 2 demo hours. The portal returns "Blocked by SentrAI" (403). The demo machine itself (127.0.0.1) is never blocked.
5. The evidence report shows the timeline of inaction, "Ack: none" and the audit chain hash.
6. The operator presses **Rollback** or **Make Permanent** on the Approvals page, and it appears in the audit trail.

**Real vs simulated in the MVP**
- Real: log collection, rules classification, risk index and inaction penalty, IP blocks and account locks (enforced by the portal), TTL expiry, audit chain, evidence reports, dashboard.
- Simulated: rate limit, WAF rule, kill process and revoke ACL are recorded but have no effect. No firewall, OS or network setting is ever changed.
- Not yet tested live: Jev (no TypeSafe API key yet; the fallback heuristic classifies what the rules cannot) and a real Telegram bot.

**Fallbacks:** if Jev is unavailable during recording, the chain still runs the rules first and then a keyword fallback classifier (its confidence depends on what matched, and unmatched events count as benign), and we say so. If the live attack is flaky, `lab/replay/simulate.py` posts a scripted incident (benign, brute force, SQL injection, simulated shell) straight to the core, and we say in the video that it is a replay.

**Tests:** core 27, lab 36, dashboard 25, notifier 8 and one end-to-end story test, all passing.

---

## 16. Plan Until the 29th

1. ~~**Erick:** lab + collector + risk engine + auto-block (the demo spine).~~ Done 27 Sep.
2. ~~**Erick:** three pluggable parts, setup wizard, sidebar dashboard.~~ Done 28 Sep.
3. **Erick:** live Jev test once the TypeSafe API key arrives; real Telegram alerts once a bot token is set. Neither is needed for the video.
4. **Ishmail:** pitch script and narration, built around section 1 and the demo.
5. **Hozen:** finalize slides from `mvp/pitch/SLIDES.md` (sources in `mvp/research/SOURCES.md`): problem, sentry ethics, 0 to 100 index, architecture and the three parts, demo, roadmap.
6. **All:** record the demo, with the replay script as backup.
