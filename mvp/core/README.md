# SentrAI core

This is the FastAPI service on `http://127.0.0.1:8000`. It implements every Core API endpoint in `../CONTRACT.md`. It handles:

- event ingestion
- classification: rules, then Jev, then a fallback heuristic
- incident aggregation
- the risk engine
- the multi-agent layer
- the hotpatch workflow
- the notifications queue
- the hash-chained audit log
- evidence reports (Markdown, JSON, PDF)

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
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | Addresses never blocked, by the portal or the firewall. Add your own admin IP before turning the firewall on, e.g. `PROTECTED_IPS=127.0.0.1,::1,localhost,198.51.100.200`. |
| `CACTAI_FIREWALL` | `off` | Mirror `block_ip` into the host firewall: `auto`, `nftables`, `iptables` (Linux) or `netsh` (Windows). `off` keeps blocking portal-only. |
| `CACTAI_FIREWALL_ENFORCE` | `0` | `0` is a dry run: the command is logged and written to the audit trail, never run. `1` runs it (admin/root). Loopback, link-local, multicast and `PROTECTED_IPS` are never sent to the firewall. |
| `CACTAI_DB` | `data/cactai.db` | SQLite audit chain. |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | `5` / `60` | Brute-force rule: this many failed logins from the same IP within this many seconds. |
| `EXPORT_ROWS_THRESHOLD` | `100` | `/export` with at least this many rows counts as data exfiltration. |
| `SSH_BRUTE_FORCE_COUNT` / `SSH_BRUTE_FORCE_WINDOW_S` | `5` / `600` | SSH brute force: this many failed guesses (not log lines) from one IP within this many seconds. |
| `WEB_SCAN_4XX_COUNT` / `WEB_SCAN_WINDOW_S` | `10` / `120` | Web path scanning: this many 4xx replies to one IP within this many seconds (crawlers such as Googlebot, `favicon.ico`, `robots.txt` and ACME challenges do not count). |
| `AUTO_CLOSE_QUIET_MIN` | `60` | Resolve an open scan or brute-force incident after this many real minutes with no new event and no containment in force. `0` turns it off. |
| `AUTO_CLOSE_CATEGORIES` | `port_scan,brute_force` | Which categories auto-close. Other incidents always wait for an operator. |
| `WATCHDOG_SILENCE_S` | `30` | Watchdog flags a collector after this many seconds of silence. |
| `INTEGRITY_CHECK_S` | `30` | How often the integrity guard re-checks the audit chain and the clock. |
| `CLOCK_JUMP_S` | `120` | A clock change bigger than this (core host or a collector) counts as log tampering. |
| `PROTECTED_IPS` | empty | Comma-separated IPs that Countersign will never approve blocking. |
| `CACTAI_ENGINE` | `cyanide` | Orchestrator. `cyanide` plans with Claude when a key is set; `saguaro` keeps the fixed playbooks only. |
| `CACTAI_LLM_API_KEY` | unset | The one AI key the setup wizard saves; used by whichever provider `CACTAI_LLM_PROVIDER` names. With no key, Cyanide behaves exactly like Warden. A provider's own variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `COMMANDCODE_API_KEY`) still works and wins when set. |
| `CACTAI_LLM_PROVIDER` | `auto` | `anthropic`, `openai`, `deepseek`, `commandcode` (also set `CACTAI_LLM_MODEL`), or `compatible` (any OpenAI-compatible API: also set `CACTAI_LLM_BASE_URL` and `CACTAI_LLM_MODEL`). `auto` uses the first provider-specific key set. The dashboard's Configuration page has a Fetch models button that lists the models your key can use. |
| `CYANIDE_PROFILE` | unset | Path to the system profile JSON, e.g. `profiles\tuition_centre.json`. |
| `CYANIDE_MODEL` / `CYANIDE_EFFORT` / `CYANIDE_TIMEOUT_S` | provider default / `low` / `20` | Model, effort level (Anthropic only) and per-call timeout for planning. Defaults: `claude-opus-5`, `gpt-5`, `deepseek-chat`. |
| `CYANIDE_ENABLED` | `1` | Set to `0` to switch the planner off without removing the key (tests do this). |
| `CACTAI_BACKGROUND` | `1` | Set to `0` to turn off the 1 s background tick (tests do this). |

## Cyanide (the orchestrator)

Cyanide (`app/cyanide.py`) replaces Warden's fixed judgement with Claude, and keeps everything that must stay predictable.

- **What the model decides.** Claude by default; OpenAI, DeepSeek or any OpenAI-compatible API also work (`mvp/cactai_llm.py`, keys in `python cactai_config.py setup`, section 5). When an incident opens, Cyanide sends the model the system profile, the incident, its log lines and the list of installed actions. The model answers with an assessment in plain words, the containment steps that fit this system, and whether SentrAI may act alone or must wait for a human.
- **What stays fixed.** The risk index, SLA, inaction penalty, notifications, TTLs and the audit chain are Warden's code, unchanged. Countersign still reviews every autonomous action.
- **Guardrails.** Claude can only pick installed action types. IP, account and host targets must appear in the incident's own events; anything else is dropped and logged. Accounts and IPs listed as protected in the profile go to Countersign, which refuses them. A plan can make SentrAI more careful ("hold: exam week, the admin account is shared") but never bypass the threshold or the TTL.
- **Fallback.** No key, a timeout or a bad answer means the default playbook is used, and the timeline says so.
- **Adapting to a new system.** Write a profile (see `profiles/tuition_centre.json`): what the hosts do, which accounts matter, business hours, what must never be touched. A new responder (a new action type) is offered to Claude automatically.
- **Speed.** Planning runs on a background thread, so ingestion never waits on the model. The playbook text shows until the plan arrives, usually a few seconds later.

Audit records: `cyanide_plan` (actions, reasons, dropped steps), `cyanide_hold` and `cyanide_fallback`.

## How it works

1. **Ingest** (`POST /events`). Warden sends each event to a layer agent based on its `layer`:
   - `web` goes to Gatehouse
   - `db` goes to Vault
   - `os` goes to Garrison-Linux, or to Garrison-Win when the host or source contains "win"
   - `network` and `cloud` go to Watchtower
2. **Classify**:
   - **Rules first**, always with confidence 1.0. They cover SQLi, XSS, a shell being spawned, `/export` bulk exports, port scans, misconfigurations, and 5 or more failed logins from one IP within 60 s. Failed logins below that threshold are held as benign; when the threshold is reached, all of them are attached to the incident.
   - **Log tampering** (`log_tampering`, critical 55): commands that wipe, edit or silence the record (deleting or emptying files under `/var/log` or shell history, `journalctl --vacuum`, `chattr -a`, stopping rsyslog/auditd/journald, `wevtutil cl`, Windows event 1102), a collector notice that a log shrank, vanished or was swapped with no rotated copy (`log_integrity`), and the integrity guard's findings (`audit_integrity`: audit chain broken, audit database deleted, clock jumped). On its own it stays below the autonomous line, so a person decides; it only proposes blocking the source IP.
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
   2. Countersign review: the incident needs confidence of at least 0.6, and the action must be on the allowlist.
   3. Garrison applies the playbook with a TTL of 2 demo hours.
   4. Verify.
   5. Notify.

   This is containment inside the app only. The target app polls `/blocklist`. **No firewall, shell or OS changes are ever made.** Expired actions drop out of `/blocklist`.
5. **Audit**. Every agent decision is appended to an SQLite hash chain, with the agent's name in `data.agent`. The hash is `sha256(prev_hash + canonical_json({seq, ts, type, data}))`. SQL triggers block UPDATE and DELETE. `/audit` re-verifies the whole chain on each call.

## Agent names

People see the sentry names. The Python classes keep their older cactus names so saved state,
env vars and imports keep working. Old names in saved incidents and audit records are mapped
to the new ones (`LEGACY_AGENT_NAMES` in `app/saguaro.py`, `LEGACY_AGENTS` in the dashboard).

| Shown as | Class (file) |
| --- | --- |
| Warden | `Saguaro` (`app/saguaro.py`) |
| Gatehouse, Vault, Watchtower | `Root`, `Reservoir`, `SpineNet` (`app/agents.py`) |
| Garrison-Linux, Garrison-Win | `AreoleLinux`, `AreoleWin` |
| Countersign | `Needle` (setting `NEEDLE_MIN_CONFIDENCE`, audit type `needle_review`) |
| Tripwires | lab `target_app/spines.py`, `CACTAI_SPINES`, `--spines` (alias `--tripwires`) |

## Process scan (finding logs automatically)

Scout follows a technician through the folders. The process scan (`app/procscan.py`, `app/discovery.py`) is the automatic half: it lists the programs running on this computer, recognises the known ones (IIS, nginx, Apache, Tomcat, MySQL, PostgreSQL, SQL Server, MongoDB, Redis, SSH, Docker, syslog, Node and Python apps, and the SentrAI lab portal) and looks for their log files in the usual places, next to the program, in options such as `--log-file`, and (on Linux) in the files each process has open.

- **How.** Windows: PowerShell/CIM (`Win32_Process`, plus `Win32_Service` for the service account). Linux: `/proc`. macOS: `ps`. Standard library only, no admin rights needed; processes it cannot read are listed by name only.
- **Read-only.** It never starts, stops or signals a process and never reads log contents. It only checks which files exist.
- **Private details stay out.** Command lines are cut down to log options with secrets masked, home folders show as `~`, personal accounts as `(user)`. Credential stores and sensitive system processes (lsass, KeePass, 1Password, ssh-agent and similar) are skipped, and the profile can add more with `"process_scan": {"skip_processes": ["veyon*"]}` or turn scanning off with `"enabled": false`.
- **Nothing is watched until an operator says so.** Each file in a scan has an id. The dashboard's Collector page (Find logs on this computer) and Cyanide's chat buttons approve a file by that id, so neither the model nor a crafted request can point the collector at an arbitrary path. Approved files go to the same list Scout writes (`lab/scout/sources.json`), and the running collector starts tailing them within a few seconds, from the end of the file.
- **Cyanide.** Chat has two new tools: `scan_system` and `suggest_log_source` (a button, like `suggest_action`). Without an AI key, asking the chat to "scan" gives the scanner's own list with buttons.

Audit records: `system_scan` and `log_source_added`.

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
- `POST /system/scan {"operator": "erick"}` and `GET /system/scan` (latest): read-only process scan with suggested log files.
- `GET /log-sources` and `POST /log-sources {"operator", "file_id", "layer"?}`: extra log files the collector watches; a file is added only by its id from the latest scan.
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
| `/demo/reset` | Moves the audit DB to `data/archive/` (the old chain is kept, not destroyed), clears all state (the saved incident state lives in the same file), and starts a new chain. |

## Limitations

- Incidents, actions (blocks) and notifications are saved to `state_*` tables in the audit database (WAL mode) after every change, and restored on startup (`app/state.py`). Blocks still in force are put back with their original expiry; blocks whose TTL ran out while the core was down are rolled back, logged as `action_expired` with `while_core_down: true`, and summarised in a `state_restored` audit record. Rules-engine windows, the watchdog, the risk chart history and the chat history are not saved.
- The only containment with a real effect is `block_ip` and `lock_user`, through `/blocklist`. `rate_limit`, `waf_rule`, `kill_process` and `revoke_public_acl` are recorded and reported as "recorded (simulated)".
- Claude-written explanations are not used. Explanations and reports come from deterministic templates.
