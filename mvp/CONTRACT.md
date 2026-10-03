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
  lab/                   owner: lab agent       target app on http://127.0.0.1:5000, collector, attacks, replay
  dashboard/             owner: ui agent        Streamlit on http://127.0.0.1:8501
  notifier/              owner: ui agent        Telegram bot (optional at runtime)
  run_demo.ps1           owner: lead (integration)
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

### Categories (exact strings)
`benign, brute_force, sql_injection, xss, port_scan, privilege_escalation, data_exfiltration, misconfiguration, log_tampering`

### Severity → base points
low 5-10, medium 15-25, high 30-45, critical 50-70. Default mapping:
brute_force=high(30), sql_injection=high(40), xss=medium(20), port_scan=medium(15), privilege_escalation=critical(60), data_exfiltration=critical(70), misconfiguration=medium(20), log_tampering=critical(55), benign=0.

### Risk index
`risk_index = round(100 * (1 - exp(-raw/60)))`, raw = sum of open incident points (base × ai_confidence × asset_criticality) + inaction penalty (+5 per demo-hour unacknowledged, capped +30 per incident) − resolved incidents.
Bands: green 0-29, amber 30-59, red 60-79, critical 80-100. Autonomous threshold default 80.

### Demo clock
Core exposes a speed factor: `DEMO_SPEED` env var (default 60 → 1 real minute = 1 demo hour). All penalties/SLAs use demo time. SLA default 2 demo hours.

## Core API (owner: core)

Every endpoint except `GET /health` and `GET /blocklist` needs the API token, sent as
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
| GET | `/reports/{incident_id}` | evidence report JSON |
| GET | `/reports/{incident_id}.md` | same report as Markdown |
| GET | `/protection` | `{"protection": "on" \| "off", "monitor_only", "changed_at", "changed_by", "reason", "active_actions": [...ids]}` |
| POST | `/protection` | `{"operator", "on": bool, "reason"}` (reason required to turn it off). Off = monitor-only: events are still collected, classified and scored, but no containment is applied, autonomous or approved (approve returns 409). Actions already in force stay until they expire or are rolled back. Kept across restarts and `/demo/reset` in `core/data/protection.json`; `CACTAI_MONITOR_ONLY=1/0` overrides it at start. Every switch is audited as `protection_changed`; each skipped containment as `containment_skipped`. `/risk` also carries `monitor_only`. |
| GET | `/blocklist` | `{"ips": [...], "users": [...]}` active (non-expired) containment, polled by target app |
| GET | `/notifications/pending` | alerts not yet delivered (polled by notifier) |
| POST | `/notifications/{id}/delivered` | `{"channel","message_id"}` |
| GET | `/chat` | `{"assistant", "model", "messages": [{"id","role": "operator" \| "assistant","text","ts","incident", ...}]}` |
| POST | `/chat` | `{"operator", "message", "incident": id or null}` → the assistant message, with `"looked_at": [...]` and `"suggestions": [{"incident","decision","label","reason","status"}]`. Read-only: a suggestion changes nothing until the operator confirms it through the decision/rollback/permanent/ack endpoints above. Logged to the audit trail as `operator_chat`. |
| POST | `/chat/clear` | empties the chat history (also cleared by `/demo/reset`) |
| POST | `/chat/setup/interpret` | guided setup in the Chat page. `{"question", "options": [{"value","label"}], "answer"}` → `{"ai": bool, "choice": an option value or "", "reply"}`. The model maps an answer the scripted setup could not match to an option, or answers the user's question. Without an AI model `{"ai": false, "choice": "", "reply": ""}`. Never sent secrets; saves nothing, not audited. |
| GET | `/ai` | the AI model Cyanide and the chat use now: `{"engine","planner","chat","online","provider","model","key_source","off_reason"}`; `off_reason` says why it is off (no key, missing model, package not installed...) |
| POST | `/ai/reload` | reads the saved AI settings again and switches Cyanide and the chat to them (no restart); returns the same shape as `GET /ai` |
| POST | `/ai/test` | one real request to the provider. Body `{"provider","api_key","base_url","model"}` tests those values (saved or not) without switching anything; no body tests what Cyanide uses now. Returns `{"ok","provider","model","ms","error","hint","tested"}` |
| GET | `/log-sources` | extra log files the collector watches (approved from a process scan, or from Scout) |
| GET | `/log-sources/pending` | Scout proposals waiting for an operator: `[{"id","name","path","layer","format","why","goal","proposed_at"}]` |
| POST | `/log-sources/pending/{id}` | `{"operator", "approve": bool, "layer": optional, "reason": optional}`: approve adds the file to the collector list, reject drops it; audited as `log_source_added` / `log_source_rejected` |
| POST | `/demo/reset` | clears state for a fresh take |

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
