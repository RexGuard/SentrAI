# SentrAI MVP: Shared Contract

Every component MUST follow this file. The design source of truth is `../Cybersecurity + AI.md`.

## Environment facts

- Windows 11, PowerShell, Python 3.12 (`python`), Node 24. **No Docker.** WSL Ubuntu exists but do not depend on it.
- Everything runs natively on Windows on one laptop, on localhost.
- Each component has its own `requirements.txt` and its own venv at `mvp/<component>/.venv` (create with `python -m venv`). Never share or modify another component's venv.
- Python only. Type hints, small modules, no frameworks beyond those listed.

## Directory layout (each owner writes ONLY inside its folder)

```
mvp/
  CONTRACT.md            (this file, owned by lead)
  core/                  owner: core agent      FastAPI on http://127.0.0.1:8000
  lab/                   owner: lab agent       collector, Scout
  dashboard/             owner: ui agent        Streamlit on http://127.0.0.1:8501
  notifier/              owner: ui agent        Telegram bot (optional at runtime)
  run.ps1 / run.sh       owner: lead (integration)
```

## Shared data (JSON over HTTP)

### Event (collector → core, `POST /events`)
```json
{
  "event_id": "evt-...",            // string, unique
  "timestamp": "2026-09-29T14:00:03+08:00",  // ISO 8601
  "host": "web-01",
  "layer": "web" | "db" | "os" | "network" | "cloud",
  "source": "flask_access" | "flask_auth" | "db_query" | "os_process" | "replay" | "...",
  "src_ip": "203.0.113.45" | null,
  "user": "admin" | null,
  "raw": "POST /login 401 user=admin",
  "asset_criticality": 1.0 | 1.5 | 2.0
}
```
`POST /events` also accepts a JSON list of events. Returns `{"accepted": n, "risk_index": int}`.

#### Parsed fields (optional `parsed` object on an Event)

The collector adds `parsed` when it understands the line. `raw` stays the original line (for
journald: the message). Rules should read `parsed` first and fall back to `raw`. Missing values are
`null`. `timestamp` is the log's own time when the line has one, and `host` is the host named in the
line (syslog/journald) or the collector machine's name (`CACTAI_HOST`); demo portal events keep
`web-01`.

Every `parsed` has `format` and `kind`:

| format | kind | fields |
| --- | --- | --- |
| `nginx_access` | `http_request` | `method`, `path` (URL-decoded, no query), `query` (as sent), `protocol`, `status` (int), `bytes` (int), `referrer`, `user_agent`, `request` (the whole request line), `malformed_request` (true for empty/binary/TLS-on-port-80 requests: scanners) |
| `nginx_error` | `http_error` | `level` (error, crit, ...), `pid`, `message`, `request`, `method`, `path`, `query`, `server`, `vhost` |
| `syslog`, `journald` | `ssh` (program sshd, sshd-session, sshd-auth) | `program`, `pid`, `message`, `ssh_event`, `outcome` (`success`, `failure`, `info`), `auth_method` (password, publickey, keyboard-interactive), `invalid_user` (bool: the account does not exist), `preauth` (bool), `port` (client port), sometimes `reason`, `count`; journald adds `unit` |
| `syslog`, `journald` | `log` (any other program) | `program`, `pid`, `message` |
| `cactai_demo` | `http_request` / `web_login` / `db_query` / `log` | demo portal: `method`, `path`, `status` / `outcome` / `rows` |
| `jsonl`, `text` | `log` | nothing else; `src_ip` and `user` are taken from JSON keys or guessed from the text |
| `winevent` | `auth` (4624 network/RDP sign-in, 4625, 4771, 4776, 4740, 18456 SQL Server) | `event_id`, `win_event`, `channel`, `provider`, `record_id`, `message` (first line), `service` (`windows_logon`, `rdp`, `kerberos`, `ntlm`, `mssql`), `outcome`, `logon_type` (`network`, `remote_desktop`, ...), `status`, `workstation`, `reason` |
| `winevent` | `windows_event` (1102/104 log cleared, 4720, 4728/4732/4756, 4688, 4697/7045, Defender 1116/1117) | as above plus, by event: `log`; `group`, `member`, `by`; `process`, `parent`, `command_line`; `service_name`, `image_path`, `account`; `threat`, `path`, `severity`, `action` |
| `suricata` | `network_alert` (eve.json `alert` records only) | `signature`, `signature_id`, `alert_category` (classtype), `severity` (1 high .. 3 low), `action` (`allowed`, `blocked`), `proto`, `app_proto`, `src_ip`, `src_port`, `dest_ip`, `dest_port`, `direction` (`inbound`, `outbound`), `interface`, sometimes `http_host`, `http_url`, `user_agent`. The Event's `src_ip` is the far end: `dest_ip` for an outbound alert |
| `mysql`, `postgres`, `mongodb` | `auth` | `service`, `auth_event`, `outcome`, `session`; MySQL `password_used`; PostgreSQL `pid`, `level`, `invalid_user`; MongoDB `mechanism`, `database`, `reason` |
| `mysql`, `postgres` | `db_query` (MySQL general log, PostgreSQL `statement:` lines) | `sql`, `session`; the Event's `raw` is the SQL text |
| `mysql`, `postgres` | `log` (warnings and errors) | `level`, `message`, `session` |

`auth_event` values: MySQL `access_denied`, `connected`, `aborted_preauth`, `aborted`,
`host_blocked`; PostgreSQL `password_failed` (or `<method>_failed`), `no_hba_entry`, `no_such_role`,
`connection_received`, `connected`; MongoDB `auth_failed`, `connected`, `connection_received`.
`session` (`postgres:<pid>`, `mysql:<thread>`, `mongodb:<ctx>`) lets the collector give a line with
no client address the address of an earlier line of the same connection. Lines the formats write
but SentrAI has no use for (Suricata flows, MySQL notes, PostgreSQL checkpoints, MongoDB storage
messages, Windows service sign-ins) are not sent at all.

`ssh_event` values (`src_ip` and `user` are set on the Event where the line has them):
`accepted`, `failed_auth` ("Failed password/publickey for [invalid user] X"), `invalid_user`
("Invalid user X from IP"), `max_auth_exceeded`, `auth_failure_pam` and `auth_failures_more` (PAM
repeats of the same attempts), `pam_check_pass`, `user_not_allowed`, `connection_closed`,
`disconnected`, `disconnecting`, `received_disconnect`, `connection_reset`, `no_identification`,
`banner_error`, `negotiation_failed`, `timeout_preauth`, `bad_protocol`, `connection_from`,
`session_opened`, `session_closed`, `other`.

For counting SSH guesses: one failed attempt shows up as `failed_auth` (password servers) or as
`invalid_user` (every server, once per connection); PAM lines repeat them, so don't add them on
top. `src_ip` + `port` identifies one connection.

### Webhook source (any tool → core, `POST /webhook/<name>`)
Same token as `/events`. The body is a JSON object, a list of objects, or an object holding a list
under `events`, `alerts`, `records`, `items`, `logs` or `data`. Each object becomes one Event
(`core/app/webhook.py`): fields come from the `<name>` entry of `CACTAI_WEBHOOK_MAPS` (dotted paths,
or `=value` for a fixed value), then from common key names (`src_ip`/`client_ip`/`remote_addr`,
`message`/`msg`/`full_log`, `host`/`hostname`/`agent.name`, ...). `source` is always
`webhook_<name>`, `raw` is capped at 8,000 characters (the whole object as JSON when no text field
is found), `event_id` is `wh-<name>-<id or hash of the object>`, and `?layer=` / `?host=` set
defaults. Returns `{"accepted": n, "risk_index": int, "events": [event ids]}`.

### Line chain
Every event the collector sends carries `chain: {"stream", "seq", "prev", "hash"}`:
`hash = sha256(prev + json([event_id, timestamp, host, layer, source, raw]))` (compact JSON, `ensure_ascii=False`),
`prev` is the previous event's hash (64 zeros for #1), `seq` counts up from 1 per `stream` (one per collector,
kept in `collector-state.json` once delivered). The core checks each one (`integrity.py`): a changed line, a
missing run of events or one that does not follow its predecessor becomes an `audit_integrity` event
(log tampering). Events without `chain` are accepted as before.

### Categories (exact strings)
`benign, brute_force, sql_injection, xss, port_scan, privilege_escalation, data_exfiltration, misconfiguration, log_tampering, malware, prompt_injection`

### Severity → base points
low 5-10, medium 15-25, high 30-45, critical 50-70. Default mapping:
brute_force=high(30), sql_injection=high(40), xss=medium(20), port_scan=medium(15), privilege_escalation=critical(60), data_exfiltration=critical(70), misconfiguration=medium(20), log_tampering=critical(55), malware=critical(65), prompt_injection=critical(60), benign=0.

### Risk index
`risk_index = round(100 * (1 - exp(-raw/60)))`, raw = sum of open incident points (base × ai_confidence × asset_criticality) + inaction penalty (+5 per hour unacknowledged, capped +30 per incident) − resolved incidents.
Bands: green 0-29, amber 30-59, red 60-79, critical 80-100. Autonomous threshold default 80.

### Demo clock
Core exposes a speed factor: `DEMO_SPEED` env var (default 60 → 1 real minute = 1 demo hour). All penalties/SLAs use demo time. SLA default 2 demo hours.

## Core API (owner: core)

A machine that joined a central panel (`lab/agent`, `/fleet/*` below) sends its own key `sa_...` instead:
it may only `POST /events` and `POST /heartbeat` (stamped with its own machine name, whatever the log says),
`GET /blocklist` (its own) and `GET /fleet/me`; anything else is 403.
Every endpoint except `GET /health`, `GET /blocklist` and `POST /fleet/enrol` needs the API token, sent as
`Authorization: Bearer <token>` (or `X-CactAI-Token: <token>`); without it the core answers 401.
The token is `CACTAI_API_TOKEN`, generated by the setup wizard and saved in the settings file;
`python cactai_config.py token` prints it. The launchers hand it to every component.
`GET /reports/{id}.md?sig=...` also opens without it: the `report_url` in a notification carries
that signature (HMAC of the path with the token), which fits that one report only.

| Method | Path | Body / returns |
| --- | --- | --- |
| GET | `/health` | `{"ok": true}` |
| POST | `/events` | Event or [Event] → `{"accepted", "risk_index"}` |
| GET | `/risk` | `{"risk_index", "band", "raw_score", "threshold", "open_incidents": [...ids], "history": [{"t","risk_index"}]}` |
| GET | `/incidents` | list of Incident |
| GET | `/incidents/{id}` | Incident |
| POST | `/incidents/{id}/decision` | `{"operator": "erick", "decision": "approve" \| "reject", "justification": "..."}` |
| POST | `/incidents/{id}/rollback` | `{"operator", "justification"}` |
| POST | `/incidents/{id}/permanent` | `{"operator", "justification"}` |
| POST | `/incidents/{id}/ack` | `{"operator", "channel"}` records acknowledgement |
| GET | `/audit` | hash-chained records `[{"seq","ts","type","data","prev_hash","hash"}]` + `{"chain_valid": bool}` |
| GET | `/audit/fingerprint` | `{"seq","head","at","line"}`: the current signed fingerprint (`SENTRAI-FP v1 ...`) |
| GET | `/audit/remote-copy` | `{"enabled", "url", "ok", "audit_seq", "lines_sent", "last_sent_at", "error", ...}`: the off-box copy |
| GET | `/audit/verify?fingerprint=<line>` | `{"ok": bool, "reason": str}`: does the chain on disk still match a fingerprint sent earlier |
| GET | `/reports/{incident_id}` | evidence report JSON |
| GET | `/reports/{incident_id}.md` | same report as Markdown |
| GET | `/protection` | `{"protection": "on" \| "off", "monitor_only", "changed_at", "changed_by", "reason", "active_actions": [...ids]}` |
| POST | `/protection` | `{"operator", "on": bool, "reason"}` (reason required to turn it off). Off = monitor-only: events are still collected, classified and scored, but no containment is applied, autonomous or approved (approve returns 409). Actions already in force stay until they expire or are rolled back. Kept across restarts in `core/data/protection.json`; `CACTAI_MONITOR_ONLY=1/0` overrides it at start. Every switch is audited as `protection_changed`; each skipped containment as `containment_skipped`. `/risk` also carries `monitor_only`. |
| GET | `/blocklist` | `{"ips": [...], "users": [...]}` active (non-expired) containment, polled by target app. `?host=` (token or that machine's key) gives only that machine's blocks in host scope; an agent key always gets its own |
| GET | `/risk?host=` | one machine's own index, incidents and history (`"risk_scope"`: `fleet` adds every machine into one score, `host` scores each on its own; set with `CACTAI_RISK_SCOPE`) |
| GET | `/incidents?host=` | that machine's incidents |
| GET | `/machines` | `[{"host","risk_index","band","raw_score","open_incidents","contained_incidents","blocked","last_seen","silent"}]`, worst first |
| POST | `/fleet/join-codes` | `{"operator", "name": optional}` → `{"code": "ABCD-EFGH-JKLM", "expires_at", "name"}`: one-time, 24 h; audited as `join_code_created` |
| POST | `/fleet/enrol` | open (no token): `{"code", "host"}` → `{"agent_id", "host", "key": "sa_..."}`; the key is shown once. 10 wrong codes in 10 min → 429 for everyone; audited as `machine_joined` |
| GET | `/fleet/agents` | joined machines `[{"agent_id","host","joined_at","invited_by","last_seen","revoked_at","revoked_by"}]` |
| POST | `/fleet/agents/{id}/revoke` | `{"operator"}`: that machine's key stops working; audited as `machine_revoked` |
| GET | `/fleet/me` | agent key only: `{"agent_id","host","risk_scope"}` |
| GET | `/notifications/pending` | alerts not yet delivered (polled by notifier) |
| POST | `/notifications/{id}/delivered` | `{"channel","message_id"}` |
| GET | `/chat` | `{"assistant", "model", "messages": [{"id","role": "operator" \| "assistant","text","ts","incident", ...}]}` |
| POST | `/chat` | `{"operator", "message", "incident": id or null}` → the assistant message, with `"looked_at": [...]` and `"suggestions": [{"incident","decision","label","reason","status"}]`. Read-only: a suggestion changes nothing until the operator confirms it through the decision/rollback/permanent/ack endpoints above. Logged to the audit trail as `operator_chat`. |
| POST | `/chat/clear` | empties the chat history |
| POST | `/chat/setup/interpret` | guided setup in the Chat page. `{"question", "options": [{"value","label"}], "answer"}` → `{"ai": bool, "choice": an option value or "", "reply"}`. The model maps an answer the scripted setup could not match to an option, or answers the user's question. Without an AI model `{"ai": false, "choice": "", "reply": ""}`. Never sent secrets; saves nothing, not audited. |
| GET | `/ai` | the AI model Cyanide and the chat use now: `{"engine","planner","chat","online","provider","model","key_source","off_reason"}`; `off_reason` says why it is off (no key, missing model, package not installed...) |
| POST | `/ai/reload` | reads the saved AI settings again and switches Cyanide and the chat to them (no restart); returns the same shape as `GET /ai` |
| POST | `/ai/test` | one real request to the provider. Body `{"provider","api_key","base_url","model"}` tests those values (saved or not) without switching anything; no body tests what Cyanide uses now. Returns `{"ok","provider","model","ms","error","hint","tested"}` |
| GET | `/integrations` | outside services (cloudflare, abuseipdb, slack, webhook, telegram, email): `[{"name","title","kind","what","configured","detail","last_ok","last_error","testable","settings","docs"}]`. Never returns keys |
| POST | `/integrations/{name}/test` | one harmless call with the saved key (reads Cloudflare, looks up 1.1.1.1, posts a Slack test line) → `{"ok","detail"\|"error"}`; 404 for an unknown name |
| POST | `/threats/scan` | `{"operator", "paths": optional list}`: read-only threat scan of the folders in `threat_scan.paths` (or `paths`); returns `{"roots","files_checked","counts","findings":[{"id","path","entry","line","key","kind","severity","label","snippet","sha256"}],"new_alerts"}`. New critical/high findings are ingested as events with `source: "threat_scan"` (category `malware`), each once; audited as `threat_scan` |
| GET | `/threats` | latest threat scan, same shape |
| POST | `/threats/{id}/quarantine` | `{"operator", "reason": optional}`: moves that file (by finding id, only if unchanged since the scan) into quarantine; audited as `file_quarantined` |
| GET | `/quarantine` | files in quarantine: `[{"id","name","original","sha256","finding","operator","at"}]` |
| POST | `/quarantine/{id}/restore` | `{"operator"}`: puts the file back; audited as `file_restored` |
| GET | `/backups` | backup settings and every backup kept: `{"enabled","every_hours","keep","folders","include_sentrai","copy_to","stored_in","next_due","overdue","last_error","backups":[{"id","created","by","reason","folders","files","bytes","sha256","verified","copy"}]}` |
| POST | `/backups` | `{"operator"}`: back up now; returns the backup (`ok` false with `error` when it failed, which also queues a `backup_failed` notice). Audited as `backup_made` / `backup_failed` |
| POST | `/backups/{id}/verify` | `{"operator"}`: checks the archive against its note, the `backup_made` audit record and every file's SHA-256; returns `{"ok","files_checked","problems"}`; audited as `backup_verified` |
| POST | `/backups/{id}/restore` | `{"operator", "in_place": false, "confirm": "", "target": optional}`: checks the backup, then unpacks it into a new folder (default) or, with `in_place` and `confirm` set to the id, over the original folders after a safety backup. 409 if the check fails or confirmation is missing. Returns `{"ok","files_restored","failed","restored_to","safety_backup","note"}`; audited as `backup_restored` and sent as a `backup_restored` notice |
| GET | `/log-sources` | extra log files the collector watches (approved from a process scan, or from Scout) |
| GET | `/log-sources/pending` | Scout proposals waiting for an operator: `[{"id","name","path","layer","format","why","goal","proposed_at"}]` |
| POST | `/log-sources/pending/{id}` | `{"operator", "approve": bool, "layer": optional, "reason": optional}`: approve adds the file to the collector list, reject drops it; audited as `log_source_added` / `log_source_rejected` |

### Incident
```json
{
  "id": "RSK-2026-081",
  "category": "brute_force", "severity": "high",
  "base_points": 30, "ai_confidence": 0.94, "points": 42.3,
  "classified_by": "rules" | "jev" | "fallback",
  "src_ip": "...", "user": "...", "host": "...", "layer": "web",
  "opened_at": "...", "status": "open" | "acknowledged" | "contained" | "resolved" | "rejected",
  "acked": false, "acked_by": null, "acked_at": null,
  "inaction_penalty": 15, "sla_breached": false,
  "recommended_action": "Block 203.0.113.45 for 2 h and rate-limit /login",
  "explanation": "plain English",
  "actions": [Action], "event_ids": [...]
}
```

### Action (containment record)
```json
{ "action_id": "act-0007", "incident": "RSK-2026-081", "type": "block_ip" | "lock_user" | "rate_limit" | "waf_rule" | "kill_process" | "revoke_public_acl",
  "target": "203.0.113.45", "ttl_hours": 2, "expires_at": "...", "mode": "autonomous" | "operator",
  "approved_by": "Countersign" | "<operator>", "status": "active" | "expired" | "rolled_back" | "permanent",
  "snapshot_hash": "..." }
```
Containment is enforced by the target app polling `/blocklist` (real effect: blocked IPs/users get HTTP 403). No host firewall changes by default.

## Witness (owner: core; `witness/witness.py`)
The off-box copy. The core sends `POST /append {"stream", "items"}` with the append token as it goes:
- `audit-<host>-<first 12 of record 1's hash>`: audit records exactly as stored (`seq, ts, type, data, prev_hash, hash`).
  Each must continue the copy (`seq` = last + 1, `prev_hash` = last hash) and match its own hash, else `409`.
  The same record sent twice is accepted once.
- `lines-<collector stream>`: events with their `chain` (see "Line chain"). A stream may start mid-chain; one that
  does not follow is kept with a note.
`GET /head?stream=` answers `{"stream","seq","hash"}` to either token. `GET /records?stream=&from=` and
`GET /streams` need the read token. There is no way to change or delete anything (`PUT`/`DELETE`/`PATCH` are `405`).

## Target app (owner: lab)
- Flask on :5000: `/` , `/login` (POST form user/password), `/search?q=` (deliberately naive, logs SQLi-looking queries; uses SQLite with a fake `members` table of synthetic data), `/export` (bulk export, triggers data_exfiltration events), `/admin/run?cmd=` simulated command endpoint that NEVER executes anything, only logs "shell spawned" style event.
- Writes JSON-lines logs to `mvp/lab/logs/*.jsonl`. Honors core `/blocklist` (poll every 2 s; if core down, allow).
- Tripwires (off unless `CACTAI_SPINES=1`): honeypot `/admin-legacy`, a planted credential, bait `members` rows and a tarpit. Each touch goes to `mvp/lab/logs/deception.jsonl`; the collector sends it with `"source": "tripwire"` and a raw text starting `tripwire <kind>:` (the older `cactus_spine` / `cactus-spine` forms are still accepted), and core rules turn it into an incident at confidence 1.0 (only for that source).
- Because clients are local, the attacker IP is taken from header `X-Demo-Src-IP` when present (demo spoofing so different "attackers" can be shown), else remote_addr.

## Rules for all agents
- Do NOT call any `mcp__hearthbot__*` tool. Do not push to git; the lead integrates and pushes.
- Write only inside your own folder. If you need a contract change, write it in `<your folder>/CONTRACT_REQUESTS.md` and code defensively.
- No real attacks against anything but 127.0.0.1. No real command execution from web input.
- Include a `README.md` in your folder with run commands, and smoke tests (`pytest`) where reasonable.
- All synthetic data must be obviously fake (e.g. `Member 0001`).
