# CactAI core

This is the FastAPI service on `http://127.0.0.1:8000`. It implements every Core API endpoint in `../CONTRACT.md`. It handles:

- event ingestion
- classification: rules, then Jev, then a fallback heuristic
- incident aggregation
- the risk engine
- the multi-agent layer
- the hotpatch workflow
- the notifications queue
- the hash-chained audit log
- negligence reports

## Setup and run (PowerShell)

```powershell
cd mvp\core
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Tests:

```powershell
.venv\Scripts\python -m pytest -q
```

## Environment variables (all optional)

| Var | Default | Meaning |
| --- | --- | --- |
| `DEMO_SPEED` | `60` | Demo hours per real hour. At 60, 1 real minute is 1 demo hour. |
| `RISK_THRESHOLD` | `80` | Risk index at which autonomous containment starts. |
| `SLA_HOURS` | `2` | Acknowledgement SLA, in demo hours. |
| `HOTPATCH_TTL_HOURS` | `2` | How long a hotpatch lasts, in demo hours. |
| `ON_DUTY` | `John Doe (SEC-409) / Shift Bravo` | The responsible entity named in reports and notifications. |
| `TEAM_LEAD`, `IT_MANAGER`, `CXO` | role names | Escalation recipients. |
| `TYPESAFE_API_KEY` | unset | Turns on Jev (TypeSafe System One). Without it the fallback classifier is used. |
| `JEV_TIMEOUT_S` | `3` | Timeout for each Jev call. After 3 failures in a row a 60 s circuit breaker opens. |
| `CACTAI_DB` | `data/cactai.db` | SQLite audit chain. |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | `5` / `60` | Brute-force rule: this many failed logins from the same IP within this many seconds. |
| `EXPORT_ROWS_THRESHOLD` | `100` | `/export` with at least this many rows counts as data exfiltration. |
| `WATCHDOG_SILENCE_S` | `30` | Watchdog flags a collector after this many seconds of silence. |
| `PROTECTED_IPS` | empty | Comma-separated IPs that Needle will never approve blocking. |
| `CACTAI_ENGINE` | `cyanide` | Orchestrator. `cyanide` plans with Claude when a key is set; `saguaro` keeps the fixed playbooks only. |
| `ANTHROPIC_API_KEY` | unset | Turns on Cyanide's planner (Claude). Without it Cyanide behaves exactly like Saguaro. |
| `CYANIDE_PROFILE` | unset | Path to the system profile JSON, e.g. `profiles\tuition_centre.json`. |
| `CYANIDE_MODEL` / `CYANIDE_EFFORT` / `CYANIDE_TIMEOUT_S` | `claude-opus-5` / `low` / `20` | Model, effort level and per-call timeout for planning. |
| `CYANIDE_ENABLED` | `1` | Set to `0` to switch the planner off without removing the key (tests do this). |
| `CACTAI_BACKGROUND` | `1` | Set to `0` to turn off the 1 s background tick (tests do this). |

## Cyanide (the orchestrator)

Cyanide (`app/cyanide.py`) replaces Saguaro's fixed judgement with Claude, and keeps everything that must stay predictable.

- **What Claude decides.** When an incident opens, Cyanide sends Claude the system profile, the incident, its log lines and the list of installed actions. Claude answers with an assessment in plain words, the containment steps that fit this system, and whether CactAI may act alone or must wait for a human.
- **What stays fixed.** The risk index, SLA, inaction penalty, notifications, TTLs and the audit chain are Saguaro's code, unchanged. Needle still reviews every autonomous action.
- **Guardrails.** Claude can only pick installed action types. IP, account and host targets must appear in the incident's own events; anything else is dropped and logged. Accounts and IPs listed as protected in the profile go to Needle, which refuses them. A plan can make CactAI more careful ("hold: exam week, the admin account is shared") but never bypass the threshold or the TTL.
- **Fallback.** No key, a timeout or a bad answer means the default playbook is used, and the timeline says so.
- **Adapting to a new system.** Write a profile (see `profiles/tuition_centre.json`): what the hosts do, which accounts matter, business hours, what must never be touched. A new responder (a new action type) is offered to Claude automatically.
- **Speed.** Planning runs on a background thread, so ingestion never waits on the model. The playbook text shows until the plan arrives, usually a few seconds later.

Audit records: `cyanide_plan` (actions, reasons, dropped steps), `cyanide_hold` and `cyanide_fallback`.

## How it works

1. **Ingest** (`POST /events`). Saguaro sends each event to a layer agent based on its `layer`:
   - `web` goes to Root
   - `db` goes to Reservoir
   - `os` goes to AreoleLinux, or to AreoleWin when the host or source contains "win"
   - `network` and `cloud` go to SpineNet
2. **Classify**:
   - **Rules first**, always with confidence 1.0. They cover SQLi, XSS, a shell being spawned, `/export` bulk exports, port scans, misconfigurations, and 5 or more failed logins from one IP within 60 s. Failed logins below that threshold are held as benign; when the threshold is reached, all of them are attached to the incident.
   - **Jev** if the rules cannot decide.
   - **Fallback heuristic** otherwise. It gives confidence 0.5 to 0.8 and `classified_by="fallback"`.
   - Confidence is always clipped to 0.5 to 1.0.
   - If P(malicious) is below 0.4, no incident is opened.
   - If P(malicious) is between 0.4 and 0.6, the incident gets `needs_review=true`. It is never auto-contained, and the operator is notified right away.
3. **Aggregate**. Incidents are grouped by `(category, src_ip or user or host)`. IDs run `RSK-2026-081`, `RSK-2026-082`, and so on.
   - `points = base × confidence × asset_criticality`
   - `raw` is the sum over incidents that are `open` or `acknowledged`, each counting its points plus its inaction penalty. The penalty is +5 per full demo hour unacknowledged, capped at +30. It freezes when the incident is acknowledged.
   - Contained, resolved and rejected incidents no longer count.
4. **Hotpatch**. When the risk index reaches the threshold, every incident that is open, unacknowledged and not flagged for review goes through these steps:
   1. Snapshot: sha256 of the blocklist state.
   2. Needle review: the incident needs confidence of at least 0.6, and the action must be on the allowlist.
   3. Areole applies the playbook with a TTL of 2 demo hours.
   4. Verify.
   5. Notify.

   This is containment inside the app only. The target app polls `/blocklist`. **No firewall, shell or OS changes are ever made.** Expired actions drop out of `/blocklist`.
5. **Audit**. Every agent decision is appended to an SQLite hash chain, with the agent's name in `data.agent`. The hash is `sha256(prev_hash + canonical_json({seq, ts, type, data}))`. SQL triggers block UPDATE and DELETE. `/audit` re-verifies the whole chain on each call.

## Endpoints

These follow the contract:
- `/health`
- `/events`
- `/risk` (takes `?history=N`, default 600, max 3600)
- `/incidents`
- `/incidents/{id}`
- `/incidents/{id}/decision`, `/rollback`, `/permanent`, `/ack`
- `/audit` (takes `?limit=N&incident=ID`)
- `/reports/{id}` and `/reports/{id}.md`
- `/blocklist`
- `/notifications/pending`
- `/notifications/{id}/delivered`
- `/demo/reset`

Additions that do not change the contract:
- `GET /incidents/{id}/why`: HelpDesk explanation.
- `GET /helpdesk/why?target=<ip|user>`: "why was my IP blocked?"
- `GET /agents`: status of each agent and of Jev.
- `GET /notifications`: all notifications, including delivered ones.
- `POST /heartbeat {"collector": "web-01"}`: collector heartbeat for Watchdog. An event with `"source": "heartbeat"` does the same.
- `POST /demo/advance {"demo_hours": 3}`: fast-forwards the demo clock, for tests and to skip ahead during a take.

### Response shapes the contract leaves open

- `/audit` returns `{"chain_valid", "first_invalid_seq", "count", "head_hash", "records": [{"seq","ts","type","data","prev_hash","hash"}]}`.
- A notification has these fields: `id`, `incident`, `kind`, `title`, `text`, `recipients`, `risk_index`, `band`, `buttons`, `report_url`, `created_at`, `delivered`, `delivered_at`, `channel`, `message_id`, `deliveries`.
  - `kind` is one of `incident_opened`, `needs_review`, `sla_reminder`, `escalation`, `autonomous_action`, `operator_action`, `needs_operator`, `action_expired` or `watchdog`.
  - `buttons` is a list of `[{label, action}]`, where `action` is one of `approve`, `reject`, `ack`, `rollback` or `permanent`.
- Incidents have extra fields beyond the contract: `asset_criticality`, `malicious_probability`, `needs_review`, `contribution`, `time_unaddressed_hours`, `classification_reason`, `analyzed_by`, `notifications`, `timeline`, `decisions`, `ack_channel`. Actions also carry `verified`, `enforcement`, `applied_at`, `executed_by` and `proposed_by`.

### Operator verbs

| Verb | What it does |
| --- | --- |
| `decision=approve` | Acknowledges the incident and applies the recommended playbook straight away (`mode: "operator"`, `approved_by: <operator>`). If containment is already active, the approval is recorded as an endorsement. |
| `decision=reject` | Requires a justification (HTTP 400 without one). Sets the status to `rejected` and rolls back any active actions. |
| `rollback` | Rolls back active actions. The incident becomes `acknowledged`, so its points count again but it will not be auto-contained. Returns 409 if nothing is active. |
| `permanent` | Makes active or expired actions permanent (no expiry). The incident becomes `resolved`. |
| `ack` | Records who acknowledged, when and on which channel. Freezes the inaction penalty. Idempotent. |
| `/demo/reset` | Moves the audit DB to `data/archive/` (the old chain is kept, not destroyed), clears all in-memory state, and starts a new chain. |

## Limitations

- State is in memory. Incidents, notifications and actions are lost on restart; only the audit chain persists.
- The only containment with a real effect is `block_ip` and `lock_user`, through `/blocklist`. `rate_limit`, `waf_rule`, `kill_process` and `revoke_public_acl` are recorded and reported as "recorded (simulated)".
- Claude-written explanations are not used. Explanations and reports come from deterministic templates.
