---
title: SentrAI Roadmap
---

# 🛡️ SentrAI Roadmap

From the working hackathon MVP (27 Sep 2026) to a product a Singapore SME or private school can run in production.

[← Home](./) · [Full plan](https://rexguard.github.io/cactai/Cybersecurity%20+%20AI.html) · [MVP code](https://github.com/RexGuard/cactai/tree/main/mvp)

**How to read this:** 9 phases, each with a goal, the features it adds, a done-when check, the owner, and a rough effort in developer-days for one developer (Erick). Effort figures are estimates made from the current codebase, not measurements; treat them as ±50%. Phases 2 to 6 can overlap once Phase 1 is done.

---

## Where we are today (MVP, done)

| Area | In the MVP | Still simulated or missing |
| --- | --- | --- |
| Data collection | Web, DB and OS logs from the demo portal via a Python collector | Real servers, Windows, network, cloud |
| Classification | Rules engine + fallback heuristic; Jev client written | Jev never called live (no API key); no accuracy measurement |
| Risk engine | 0 to 100 index, inaction penalty, SLA, bands, threshold | Per-organization settings, on-duty roster |
| Containment | IP block and account lock via the portal's blocklist (real 403), TTL, rollback, make permanent | Firewall, WAF, AD, DB, cloud actions are only recorded; no tarpit or honeytokens |
| Agents | Warden, Gatehouse, Vault, Garrison, Countersign, Watchdog, Scribe, HelpDesk as Python classes in one process | Separate services, separate keys, LLM-assisted HelpDesk |
| Notifications | Dashboard, console, Telegram code with buttons | Telegram untested live; no email, SMS, Teams/Slack |
| Accountability | Hash-chained audit log, security evidence report (Markdown/JSON/PDF) | Signatures, fair-process features, board reporting |
| Platform | Runs on one Windows laptop; in-memory state; no login | Persistence, auth, multi-tenant, installer, CI |

---

## Timeline at a glance

| Phase | Name | Effort (dev-days) | Target window |
| --- | --- | --- | --- |
| 0 | Finish the hackathon | 2 | 28–29 Sep 2026 |
| 1 | Harden the core | 10 | Oct wk 1–2 |
| 2 | Real data collection on every layer | 18 | Oct wk 2 – Nov wk 1 |
| 3 | AI classification that can be trusted | 10 | Oct wk 3 – Nov wk 1 |
| 4 | Real containment and tripwires | 16 | Nov |
| 5 | Notifications and escalation | 7 | Nov (parallel) |
| 6 | Accountability and evidence reporting | 9 | Nov – Dec wk 1 |
| 7 | Agents as separate services | 12 | Dec |
| 8 | Product, pilot and security of SentrAI itself | 21 | Jan – Feb 2027 |
| | **Total** | **≈ 105 dev-days** | ≈ 5 months for one developer |

```
Sep   Oct               Nov               Dec          Jan–Feb 2027
P0 ■
      P1 ■■■■
          P2 ■■■■■■■■
            P3 ■■■■■
                        P4 ■■■■■■■
                        P5 ■■■
                            P6 ■■■■
                                          P7 ■■■■■
                                                       P8 ■■■■■■■■
```

**Critical path:** P1 (persistence + auth) → P2 (real collectors) → P4 (real containment) → P8 (pilot). Everything else can slip without blocking the pilot.

---

## Phase 0 · Finish the hackathon (28–29 Sep)

**Goal:** submit a strong video. No new product features.

| Task | Owner |
| --- | --- |
| Build the PowerPoint deck from `mvp/pitch/SLIDES.md` (scripts in `mvp/deck/`) | Hozen, Erick |
| Generate video title cards and charts (`mvp/assets/make_assets.py`) | Erick |
| Add a "Why SentrAI" competitor slide (Darktrace/Defender, PagerDuty, Vanta vs SentrAI) | Ishmail |
| Reframe the "Negligence Dossier" as a **Security Evidence Report** in the pitch | Ishmail |
| Record the demo with `run_demo.ps1 -DemoSpeed 600` and `scenario.py --pause 40`; keep a replay take as backup | Erick |
| Optional: try Jev live with a TypeSafe key and Telegram live with a bot token | Erick |

**Done when:** video submitted; deck and repo links on the submission.

---

## Phase 1 · Harden the core (≈10 days)

**Goal:** SentrAI survives restarts, knows who is using it, and every change is tested automatically.

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 1.1 | Persistence | Store incidents, actions, notifications and events in SQLite (Postgres option). Restore state on restart, including active TTLs. | 3 |
| 1.2 | Authentication and roles | API tokens for collectors and the notifier; operator login for the dashboard; roles: Operator, Team Lead, IT Manager, Executive, Auditor (read-only). Only Operators+ can approve; only Auditors+ can export reports. | 3 |
| 1.3 | Organization settings | A settings file / page: risk threshold, SLA, TTL, penalty rate and cap, protected IPs and users, escalation contacts. Every change is written to the audit chain. | 1.5 |
| 1.4 | On-duty roster | Shifts and who is on duty, so "Responsible Entity" in reports comes from the roster, not an env var. | 1 |
| 1.5 | CI and quality | GitHub Actions: run the 74 existing tests + e2e on every push; lint; dependency audit (`pip-audit`). | 1 |
| 1.6 | Contract v2 | Fold the extra endpoints (`/heartbeat`, `/agents`, `/why`, `/demo/advance`) and the notification item shape into `CONTRACT.md`; version the event schema. | 0.5 |

**Done when:** killing and restarting core mid-incident keeps the incident, penalty and active blocks; an unauthenticated request to any write endpoint gets 401; CI is green on `main`.

**Depends on:** nothing. **Unblocks:** everything.

---

## Phase 2 · Real data collection on every layer (≈18 days)

**Goal:** monitor real servers, not just the demo portal (plan section 4).

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 2.1 | Agent framework | One collector codebase with plug-in sources, local buffering to disk, TLS to core, per-agent token, heartbeat, config pulled from core, schema version. | 3 |
| 2.2 | Linux OS source | `/var/log/auth.log`, `journald`, `auditd` (execve by web user, new SUID files), open ports via `ss`, process tree via `psutil`. | 3 |
| 2.3 | Windows OS source | Event Log: 4625 failed logon, 4688 process creation, 4720 user created, 4732 admin group change; optional Sysmon. Runs as a Windows service. | 3 |
| 2.4 | Web source | Nginx/Apache access logs, ModSecurity audit log. | 1.5 |
| 2.5 | Database source | PostgreSQL `pgaudit` + `pg_stat_activity`; MySQL audit log. Bulk-read and privilege-grant detection. | 2 |
| 2.6 | Network source | Suricata `eve.json` (alerts, flows) and optional Zeek; port-scan and beaconing rules. | 2 |
| 2.7 | Cloud config scan | AWS via `boto3`: public S3 buckets, security groups open to 0.0.0.0/0 on admin ports, IAM users without MFA. Scheduled scan, read-only role. Azure/GCP later. | 3 |
| 2.8 | Asset inventory | Hosts, owners and criticality (1.0 / 1.5 PII / 2.0 crown jewels) managed in core, so criticality is no longer hard-coded in collectors. | 0.5 |

**Done when:** a Linux VM, a Windows VM, a Postgres DB and an AWS test account all report into one SentrAI; each layer's example attack from plan section 5 opens the right incident.

**Depends on:** 1.1, 1.2. **Later:** rewrite the collector in Go or Rust as a single binary (plan section 13), ≈8 extra days, only after the Python version is stable.

---

## Phase 3 · AI classification that can be trusted (≈10 days)

**Goal:** prove Jev's accuracy before letting it influence autonomous actions (plan section 6).

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 3.1 | Jev live | Run with a TypeSafe API key; tune the Choice criteria text; log latency and cost per call. | 1 |
| 3.2 | Evaluation set | Labelled events from CSIC 2010 (web attacks) and CIC-IDS2017 (network), plus our own lab logs. Report precision, recall and false-positive rate per category for rules, Jev and fallback. | 3 |
| 3.3 | Confidence calibration | Check that Jev's probabilities match reality; adjust the 0.5–1.0 clip and the 0.4–0.6 "needs review" band from data. | 1.5 |
| 3.4 | Needs-review queue | Dashboard view for uncertain events; operator verdict (attack / benign) is stored as a label. | 1.5 |
| 3.5 | Feedback loop | Use operator verdicts to add rules and improve the criteria descriptions; track accuracy over time. | 1 |
| 3.6 | Claude for explanations (System 2) | Claude writes the plain-English explanation and report narrative from the incident record only. It never scores or executes. Cached, rate-limited, with a template fallback. | 2 |

**Done when:** a published accuracy table exists; false-positive rate on benign traffic is under an agreed target (proposed: under 1% of benign events open an incident); autonomous actions only use rules or Jev results above the calibrated threshold.

**Depends on:** 2.x for real data (the eval set can start in parallel).

---

## Phase 4 · Real containment and tripwires (≈16 days)

**Goal:** replace "recorded (simulated)" actions with real, reversible enforcement, and add the tripwires (plan sections 8 and 11). Every adapter follows the same contract: dry-run → snapshot → apply with TTL → verify → rollback.

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 4.1 | Enforcement adapter framework | Common interface, dry-run mode, per-adapter allowlist, protected assets, automatic rollback if verification or a health check fails. | 2 |
| 4.2 | Linux firewall | `nftables` / `iptables` rule with comment tag and TTL, run by the Linux agent. | 1.5 |
| 4.3 | Windows firewall | `netsh advfirewall` / Windows Firewall API, run by the Windows agent. | 1.5 |
| 4.4 | WAF and rate limit | ModSecurity rule and Nginx `limit_req` snippets, reloaded safely. | 2 |
| 4.5 | Account actions | Disable/re-enable a local, Active Directory or Entra ID account; revoke a DB role or kill a DB session. | 2.5 |
| 4.6 | Cloud actions | S3 Block Public Access, security-group rule revoke, with the previous policy saved for rollback. | 1.5 |
| 4.7 | Tarpit | Slow down connections from a flagged IP instead of dropping them (makes attacks expensive). | 1 |
| 4.8 | Honeypot login and honeytokens | A decoy admin page and fake DB rows / credentials; any touch is a near-certain alert with confidence 1.0. | 2 |
| 4.9 | Evidence pack for SingCERT / police | Export of the incident, raw events and audit-chain proof with a chain-of-custody sheet. No contact with the attacker's systems, ever. | 2 |

**Done when:** on the test VMs, each playbook applies, verifies, expires on its TTL and rolls back cleanly; the Computer Misuse Act rule holds: no action ever touches a system we do not own.

**Depends on:** 2.1–2.3 (agents on hosts), 1.2 (auth for agent commands).

---

## Phase 5 · Notifications and escalation (≈7 days)

**Goal:** the right person hears about it on a channel they actually read (plan section 9).

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 5.1 | Telegram live | Test with a real bot; buttons tied to the operator's Telegram account; delivery receipts. | 1 |
| 5.2 | Email | SMTP with signed links for Approve / Reject (short-lived, single-use). | 1.5 |
| 5.3 | Microsoft Teams / Slack | Adaptive cards / Block Kit with the same buttons. | 2 |
| 5.4 | SMS and voice call | Via a provider such as Twilio for Critical only (costs money per message; needs budget approval). | 1 |
| 5.5 | Escalation policy editor | Who gets what at Amber / Red / Critical, reminder interval, quiet hours, backup contact when the on-duty person is on leave. | 1.5 |

**Done when:** an unacknowledged incident reaches the operator, then the team lead, then management, on at least two channels, and every delivery and acknowledgement is in the audit chain.

**Depends on:** 1.2, 1.4.

---

## Phase 6 · Accountability and evidence reporting (≈9 days)

**Goal:** reports that protect the company and treat staff fairly (plan section 10), and that answer the PDPC's question: did the organization make reasonable security arrangements?

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 6.1 | Security Evidence Report (PDF) | Done in the MVP: renamed from the old negligence report, PDF export with the audit-chain proof. | 1.5 |
| 6.2 | Signed audit chain | Ed25519 signature on each chain head; periodic external timestamp (RFC 3161) so even an admin with DB access cannot rewrite history unnoticed. | 2 |
| 6.3 | Fair-process features | Operator can add context before a report is final; report shows the operator's alert load at the time (so an overloaded person is not blamed for a staffing problem); HR-sensitive fields visible only to Executive/Auditor roles. | 2 |
| 6.4 | Team metrics | Mean time to acknowledge and to resolve, SLA compliance, alerts per person, per week and per month. | 1.5 |
| 6.5 | Board / PDPA report | Monthly summary for management: risk trend, incidents, response times, open risks, mapped to the PDPA Protection Obligation. | 1.5 |
| 6.6 | Privacy of monitoring | Data retention settings, staff notice template, and a short data protection impact assessment for monitoring employees' actions. | 0.5 |

**Done when:** a sample monthly board report and a sample incident evidence report can be handed to a PDPC-style reviewer without explanation; signature verification detects any altered record.

**Depends on:** 1.1, 1.4, 5.x.

---

## Phase 7 · Agents as separate services (≈12 days)

**Goal:** turn the agent design (plan section 12) from classes in one process into independent services, so a compromise of one agent cannot approve its own actions.

| # | Feature | Detail | Days |
| --- | --- | --- | --- |
| 7.1 | Message bus | Redis Streams or NATS between Warden and the agents; events and proposals as typed messages. | 3 |
| 7.2 | Agent identity | Each agent has its own key and permissions; Garrison can only execute signed, Countersign-approved actions. | 2 |
| 7.3 | Countersign as a separate service | True two-key rule: Countersign runs apart from Warden, with its own key and policy file. | 2 |
| 7.4 | Watchdog for agents | Heartbeats from every agent and collector; alert when any goes silent or is tampered with. | 1 |
| 7.5 | HelpDesk chat | Operators ask "why was this blocked?" in Telegram/Teams; Claude answers only from the incident record and audit chain. | 2 |
| 7.6 | Per-agent budgets and limits | Token and action budgets per agent; pause on overspend. | 2 |

**Done when:** stopping Countersign stops all autonomous actions (fail-safe), and no single agent key can both propose and approve.

**Depends on:** 1.x, 4.1.

---

## Phase 8 · Product, pilot and security of SentrAI itself (≈21 days)

**Goal:** a first real customer, and confidence that SentrAI is not itself the weakest link.

| # | Feature | Detail | Days | Owner |
| --- | --- | --- | --- | --- |
| 8.1 | Threat model of SentrAI | What if core, an agent or the dashboard is compromised? Least privilege for agents, secret storage, signed updates. | 2 | Erick |
| 8.2 | Installer | Single command install (Docker Compose and a Windows installer); onboarding wizard for assets, contacts and thresholds. | 4 | Erick |
| 8.3 | Multi-tenant option | One SentrAI serving several small organizations (for an MSP), with strict tenant isolation. | 5 | Erick |
| 8.4 | Independent pentest and SBOM | External test of SentrAI; software bill of materials; dependency pinning. | 2 + vendor | Erick, Ishmail |
| 8.5 | Pilot | One Singapore private education institution or SME, read-only first (monitor + alerts), containment enabled only after 2 weeks of tuning. | 5 | Ishmail |
| 8.6 | Pricing and packaging | Per-endpoint or per-organization pricing aimed below one security hire; compare with MDR services. | 1 | Ishmail |
| 8.7 | Documentation site | Setup, admin, operator and auditor guides on GitHub Pages. | 1 | Hozen |
| 8.8 | Compliance mapping | Map features to PDPA obligations and CSA's Cyber Essentials / Cyber Trust marks for the sales story. **[CHECK]** requirements against CSA. | 1 | Hozen |

**Done when:** the pilot runs for 30 days with agreed accuracy and response-time targets, and the pentest has no open high-severity findings.

---

## Differentiators and where they are built

| Why someone picks SentrAI | Built in |
| --- | --- |
| One product for small teams: detect, escalate, temporarily fix, prove | P2, P4, P5, P6 |
| Risk grows with inaction, so ignored alerts get louder | MVP; tuned in P1.3 |
| Every automatic fix expires unless a human keeps it | MVP; real enforcement in P4 |
| Evidence built for the PDPC's "reasonable security arrangements" question | P6 |
| Two-key autonomous actions (Countersign) and no hack-back, ever | MVP; hardened in P7 |
| Fair to staff: context, workload and role-based visibility | P6.3 |

---

## Risks and how we handle them

| Risk | Effect | Mitigation |
| --- | --- | --- |
| False positives trigger blocks | Lost trust, blocked customers | P3 accuracy gates; protected assets; TTL; pilot starts read-only |
| Staff see it as surveillance / blame | Pushback, HR issues | P6.3 fair-process features; reframe as evidence; staff notice |
| SentrAI itself is compromised | Attacker gets an enforcement tool | P7 separate keys, P8.1 threat model, P8.4 pentest |
| Jev API cost or outage | Classification slows or stops | Time budget and fallback already in the MVP; cost tracking in P3.1 |
| One developer | Schedule slips | Critical path only (P1 → P2 → P4 → P8); other phases are optional for the pilot |
| Legal questions on active defense | Liability | No action outside our own perimeter (P4 done-when); legal review before the pilot |

---

## Team owners

| Member | Owns |
| --- | --- |
| **Erick Sientaro** (Developer) | Phases 1–7 build, 8.1–8.4 |
| **Ishmail** (CEO) | Pilot, pricing, partner and customer conversations, competitor slide |
| **Hozen** (Notetaker) | Docs site, compliance mapping, meeting notes, keeping this roadmap current |

*Last updated: 28 Sep 2026.*
