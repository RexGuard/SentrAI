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
  notifier/              owner: ui agent        alerts: console, email and the alert extensions
  extensions/<name>/     one folder per extension: extension.json, core.py and/or notifier.py, tests/
  run.ps1 / run.sh       owner: lead (integration)
```

Runtime data is never written inside `mvp/`. Every file a part keeps goes in the data root described
in [`DATA.md`](DATA.md), at the place `sentrai_paths.py` gives it (`sentrai_paths.path("<key>")`). A new
file first gets an entry in `ENTRIES` there and a row in `DATA.md`. The launchers' `.run_logs/` and
`.run_pids.json` are output, not data.

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
line (syslog/journald) or the collector machine's name (`SENTRAI_HOST`); demo portal events keep
`web-01`.

Every `parsed` has `format` and `kind`:

| format | kind | fields |
| --- | --- | --- |
| `nginx_access` | `http_request` | `method`, `path` (URL-decoded, no query), `query` (as sent), `protocol`, `status` (int), `bytes` (int), `referrer`, `user_agent`, `request` (the whole request line), `malformed_request` (true for empty/binary/TLS-on-port-80 requests: scanners) |
| `nginx_error` | `http_error` | `level` (error, crit, ...), `pid`, `message`, `request`, `method`, `path`, `query`, `server`, `vhost` |
| `syslog`, `journald` | `ssh` (program sshd, sshd-session, sshd-auth) | `program`, `pid`, `message`, `ssh_event`, `outcome` (`success`, `failure`, `info`), `auth_method` (password, publickey, keyboard-interactive/pam, hostbased), `key_type` (`ED25519`, `RSA`, `ECDSA`, `ED25519-CERT` ...) and `key_fingerprint` (`SHA256:...`) when the line names the key a sign-in used (`Accepted publickey for erick from 203.0.113.5 port 51234 ssh2: ED25519 SHA256:...`, also `Failed publickey ...`; else null), `invalid_user` (bool: the account does not exist), `preauth` (bool), `port` (client port), sometimes `reason`, `count`; journald adds `unit` |
| `syslog`, `journald` | `sudo` (program sudo) | `program`, `pid`, `message`, `sudo_event` (`command`, `not_in_sudoers`, `not_allowed`, `wrong_password`, `auth_failure`, `refused`, `session_opened`, `session_closed`, `other`), `by` (the account that ran sudo), `target_user` (the account it ran as, `root` mostly), `tty` (`pts/0`; null when sudo wrote `unknown`), `command`, `outcome` (`success`, `failure`, `info`), `count` (wrong password attempts, else null). The Event's `user` is `by`, never the `USER=root` target |
| `syslog`, `journald` | `su` (program su, su-l) | `program`, `pid`, `message`, `su_event` (`switched`, `failed`, `auth_failure`, `session_opened`, `session_closed`, `other`), `by` (the account that ran su), `target_user`, `tty`, `outcome`. The Event's `user` is `by` |
| `syslog`, `journald` | `login_session` (program systemd-logind: `New session 5 of user erick.`, `Removed session 5.`, `Session 5 logged out.`) | `program`, `pid`, `message`, `session_event` (`started`, `ended`), `user` (null on `ended`), `tty` (null), `origin` (null), `session_id` (logind's id), `since` (null) |
| `who`, `quser` | `login_session` (the collector's sign-in poll, source `sessions`, layer `os`) | `session_event` (`existing`, `started`, `ended`), `user`, `tty` (`pts/0`, `tty1`, `:0`; Windows: the session name `console`, `rdp-tcp#3`, or `session-<id>` for a disconnected one), `origin` (an address, a host name, or a display such as `:0`; null at the console and always on Windows), `session_id` (null; Windows: quser's ID column), `since` (ISO 8601 with the collector machine's UTC offset) |
| `syslog`, `journald` | `log` (any other program) | `program`, `pid`, `message` |
| `sentrai_demo` | `http_request` / `web_login` / `db_query` / `log` | demo portal: `method`, `path`, `status` / `outcome` / `rows` |
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

Who is signed in (the collector's session poll, `collector.SessionSource`): every collector and agent
runs `who` (Linux, macOS) or `quser` (Windows) every 15 s and sends one Event per change, with
`source: "sessions"`, `layer: "os"`, `user`, `src_ip` (the origin when it is an address) and the
`login_session` parsed object above. `raw` is exactly
`session <existing|started|ended>: <user> on <tty>[ from <origin>][ since <ISO-8601>]`, for example
`session started: erick on pts/0 from 203.0.113.5 since 2026-10-28T10:21:00+08:00`. The sign-ins
present when the collector starts are sent once as `existing`, then each change as `started` or
`ended` (a session is the same user, terminal and start time); every sign-in still open is sent again
as `existing` about once an hour, so the core keeps it in its session table. Where the command is
missing, the collector says so once and sends nothing; `SENTRAI_SESSIONS=off` switches the poll off.
The core (`core/app/admins.py`) ties each sudo/su command to the sign-in on its terminal.

### Webhook source (any tool → core, `POST /webhook/<name>`)
Same token as `/events`. The body is a JSON object, a list of objects, or an object holding a list
under `events`, `alerts`, `records`, `items`, `logs` or `data`. Each object becomes one Event
(`core/app/webhook.py`): fields come from the `<name>` entry of `SENTRAI_WEBHOOK_MAPS` (dotted paths,
or `=value` for a fixed value), then from common key names (`src_ip`/`client_ip`/`remote_addr`,
`message`/`msg`/`full_log`, `host`/`hostname`/`agent.name`, ...). `source` is always
`webhook_<name>`, `raw` is capped at 8,000 characters (the whole object as JSON when no text field
is found), `event_id` is `wh-<name>-<id or hash of the object>`, and `?layer=` / `?host=` set
defaults. Returns `{"accepted": n, "risk_index": int, "events": [event ids]}`.

### Line chain
Every event the collector sends carries `chain: {"stream", "seq", "prev", "hash"}`:
`hash = sha256(prev + json([event_id, timestamp, host, layer, source, raw]))` (compact JSON, `ensure_ascii=False`),
`prev` is the previous event's hash (64 zeros for #1), `seq` counts up from 1 per `stream` (one per collector,
kept in the collector's `state.json` once delivered). The core checks each one (`integrity.py`): a changed line, a
missing run of events or one that does not follow its predecessor becomes an `audit_integrity` event
(log tampering). Events without `chain` are accepted as before.

### Categories (exact strings)
`benign, brute_force, sql_injection, xss, port_scan, privilege_escalation, data_exfiltration, misconfiguration, log_tampering, malware, prompt_injection`
(`staff_report` is also an incident category, but only a staff report makes it; classifiers never return it.
`unauthorised_admin`, "Root access from an unrecognised sign-in", likewise: only root work from a sign-in the
core does not know as an administrator's makes it, `core/app/admins.py`. A known administrator's root work is
recorded as `admin_action`, never an incident.)

### Severity → base points
low 5-10, medium 15-25, high 30-45, critical 50-70. Default mapping:
brute_force=high(30), sql_injection=high(40), xss=medium(20), port_scan=medium(15), privilege_escalation=critical(60), data_exfiltration=critical(70), misconfiguration=medium(20), log_tampering=critical(55), malware=critical(65), prompt_injection=critical(60), staff_report=medium(20, times 1.5 / 1 / 0.5 for high / medium / low urgency), unauthorised_admin=critical(60, times 0.75 when the command itself reads as benign; always needs review, never contained on its own), benign=0.

### Risk index
`risk_index = round(100 * (1 - exp(-raw/60)))`, raw = sum of open incident points (base × ai_confidence × asset_criticality) + inaction penalty (+5 per hour unacknowledged, capped +30 per incident) − resolved incidents.
Bands: green 0-29, amber 30-59, red 60-79, critical 80-100. Autonomous threshold default 80.

### Demo clock
Core exposes a speed factor: `DEMO_SPEED` env var (default 60 → 1 real minute = 1 demo hour). All penalties/SLAs use demo time. SLA default 2 demo hours.

## Core API (owner: core)

A machine that joined a central panel (`lab/agent`, `/fleet/*` below) sends its own key `sa_...` instead:
it may only `POST /events` and `POST /heartbeat` (stamped with its own machine name, whatever the log says),
`GET /blocklist` (its own), `GET /fleet/me`, `POST /fleet/services` and `POST /fleet/offline-report`; anything
else is 403. On a panel these are also served on the agents' HTTPS port (`SENTRAI_PANEL_PORT`, `app/serve.py`),
which answers nothing else and only to a machine key.
Every endpoint except `GET /health`, `GET /blocklist`, `POST /fleet/enrol` and the `GET /docs` page needs the API token, sent as
`Authorization: Bearer <token>` (or `X-SentrAI-Token: <token>`); without it the core answers 401.
The token is `SENTRAI_API_TOKEN`, generated by the setup wizard and saved in the settings file;
`python sentrai_config.py token` prints it. The launchers hand it to every component.
The full reference, with examples and error codes for every endpoint, is `docs/api/` on the website
(https://rexguard.github.io/SentrAI/docs/api/); `core/tests/test_api_docs.py` fails when an endpoint has no
section there. `GET /docs` is a page that asks for the token in the browser and then shows every endpoint;
`GET /openapi.json` needs the token (`core/app/apidocs.py`). The table below is the short form.
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
| POST | `/incidents/{id}/mine` | `{"operator", "channel"}`: "This was me" on a root-access incident. The sign-in behind it (address, SSH key fingerprint, account on that host) becomes a known administrator's, its blocks are rolled back, the incident is resolved (decision `mine`, timeline `admin_confirmed`) along with the same person's other open incidents on that host → Incident plus `{"learned": ["address 203.0.113.5", ...], "also_closed": [ids]}`. 400 while `ADMIN_SESSIONS` is off, 404 unknown, 409 already closed. Audited as `admin_confirmed`; "Not me" (approve) on such an incident is audited as `admin_distrusted` |
| GET | `/audit` | hash-chained records `[{"seq","ts","type","data","prev_hash","hash"}]` + `{"chain_valid": bool}` |
| GET | `/audit/fingerprint` | `{"seq","head","at","line"}`: the current signed fingerprint (`SENTRAI-FP v1 ...`) |
| GET | `/audit/remote-copy` | `{"enabled", "url", "ok", "audit_seq", "lines_sent", "last_sent_at", "error", ...}`: the off-box copy |
| GET | `/audit/verify?fingerprint=<line>` | `{"ok": bool, "reason": str}`: does the chain on disk still match a fingerprint sent earlier |
| GET | `/reports/{incident_id}` | evidence report JSON |
| GET | `/reports/{incident_id}.md` | same report as Markdown |
| GET | `/protection` | `{"protection": "on" \| "off", "monitor_only", "changed_at", "changed_by", "reason", "active_actions": [...ids]}` |
| POST | `/protection` | `{"operator", "on": bool, "reason"}` (reason required to turn it off). Off = monitor-only: events are still collected, classified and scored, but no containment is applied, autonomous or approved (approve returns 409). Actions already in force stay until they expire or are rolled back. Kept across restarts in `protection.json` next to the core database; `SENTRAI_MONITOR_ONLY=1/0` overrides it at start. Every switch is audited as `protection_changed`; each skipped containment as `containment_skipped`. `/risk` also carries `monitor_only`. |
| GET | `/blocklist` | `{"ips": [...], "users": [...]}` active (non-expired) containment, polled by target app. `?host=` (token or that machine's key) gives only that machine's blocks in host scope; an agent key always gets its own |
| GET | `/risk?host=` | one machine's own index, incidents and history (`"risk_scope"`: `fleet` adds every machine into one score, `host` scores each on its own; set with `SENTRAI_RISK_SCOPE`) |
| GET | `/incidents?host=` | that machine's incidents |
| GET | `/machines` | `[{"host","risk_index","band","raw_score","open_incidents","contained_incidents","blocked","last_seen","silent","sessions"}]`, worst first; `sessions` is how many people are signed in on it now |
| GET | `/admins?host=` | the administrators the core knows and who is signed in: `{"on", "accounts": [{"account","host","how","by","at",...}], "addresses": [{"address","how","by","at","label","last_seen"}], "keys": [{"fingerprint","type","users","how","by","at","last_seen"}], "sign_ins", "sessions": [{"session","host","user","via","address","tty","key","key_type","method","trust","why","since","last_seen","ended","preexisting","actions","incident"}], "activity", "suspect", "settings"}` (full shapes in `docs/api/status.md`). `how` is `setting` (`ADMIN_IPS` / `ADMIN_SSH_KEYS` / `ADMIN_ACCOUNTS`), `taught` or `learned`; `host` keeps one machine's sessions, activity and accounts. Kept in `people/admins.json` next to the database (`SENTRAI_ADMINS`) |
| POST | `/admins` | `{"operator", "action": "add" \| "forget", "kind": "address" \| "key" \| "account", "value", "label": optional, "host": optional}` → the same object as `GET /admins`; 400 with a plain-words `detail` for a bad value. Audited as `admin_changed` |
| POST | `/admins/sign-in` | `{"email", "role", "address"}`: the dashboard reports a sign-in with the authenticator; Owner and Admin vouch for the address for `ADMIN_SIGNIN_HOURS` → `{"ok", "vouched", "address", "until"}`. Audited as `admin_signed_in` when it vouched |
| POST | `/fleet/join-codes` | `{"operator", "name": optional}` → `{"code": "ABCD-EFGH-JKLM", "expires_at", "name", "panel_url", "pin"}`: one-time, 24 h; audited as `join_code_created` |
| POST | `/fleet/enrol` | open (no token): `{"code", "host"}` → `{"agent_id", "host", "key": "sa_..."}`; the key is shown once. 10 wrong codes in 10 min → 429 for everyone; audited as `machine_joined` |
| GET | `/fleet/agents` | joined machines `[{"agent_id","host","joined_at","invited_by","last_seen","revoked_at","revoked_by"}]` |
| POST | `/fleet/agents/{id}/revoke` | `{"operator"}`: that machine's key stops working; audited as `machine_revoked` |
| GET | `/fleet/me` | agent key only: `{"agent_id","host","risk_scope"}` |
| GET | `/fleet/panel` | `{"panel_url", "pin": "sha256:..."}`: where agents reach this panel and its certificate pin (`SENTRAI_PANEL_URL`, `SENTRAI_PANEL_CERT`); also added to every `/fleet/join-codes` answer |
| POST | `/fleet/offline-report` | agent key only: `{"from","to","scored","actions":[{"ip","category","reason","score","at","until","applied","event_ids"}]}`: what its local rules blocked while the panel was unreachable. Audited as `agent_local_block` (each) and `agent_offline_report`; alerts `agent_offline_actions` when anything was blocked; the agent's `/fleet/agents` entry gets `"offline"` |
| GET | `/notifications/pending` | alerts not yet delivered (polled by notifier) |
| POST | `/notifications/{id}/delivered` | `{"channel","message_id"}` |
| GET | `/chat` | `{"assistant", "model", "messages": [{"id","role": "operator" \| "assistant","text","ts","incident", ...}]}` |
| POST | `/chat` | `{"operator", "message", "incident": id or null}` → the assistant message, with `"looked_at": [...]` and `"suggestions": [{"incident","decision","label","reason","status"}]`. Read-only: a suggestion changes nothing until the operator confirms it through the decision/rollback/permanent/ack endpoints above. Logged to the audit trail as `operator_chat`. |
| POST | `/chat/clear` | empties the chat history |
| POST | `/chat/setup/interpret` | guided setup in the Chat page. `{"question", "options": [{"value","label"}], "answer"}` → `{"ai": bool, "choice": an option value or "", "reply"}`. The model maps an answer the scripted setup could not match to an option, or answers the user's question. Without an AI model `{"ai": false, "choice": "", "reply": ""}`. Never sent secrets; saves nothing, not audited. |
| GET | `/ai` | the AI model Cyanide and the chat use now: `{"engine","planner","chat","online","provider","model","key_source","off_reason"}`; `off_reason` says why it is off (no key, missing model, package not installed...) |
| POST | `/ai/reload` | reads the saved AI settings again and switches Cyanide and the chat to them (no restart); returns the same shape as `GET /ai` |
| POST | `/ai/test` | one real request to the provider. Body `{"provider","api_key","base_url","model"}` tests those values (saved or not) without switching anything; no body tests what Cyanide uses now. Returns `{"ok","provider","model","ms","error","hint","tested"}` |
| GET | `/extensions` | every installed extension (Cloudflare, TypeSafe, Telegram, Slack, AbuseIPDB, ... from `mvp/extensions/*/extension.json`), then the built-in `webhook` and `email`. Extension row: `{"name","title","kind","what","about","docs","settings": [env names],"on_when","parts","source","requires","built_in": false,"added","added_by": "SENTRAI_EXTENSIONS" \| "dashboard" \| "settings","running","configured","detail","last_ok","last_error","testable","error","changed_by","changed_at"}`. Built-in rows have `"built_in": true, "added": true, "added_by": "built_in"`. Never returns keys |
| POST | `/extensions/{name}/add` | `{"operator"}`: turns it on now and keeps the choice → the row. Audited as `extension_added`. 404 unknown name; 409 while `SENTRAI_EXTENSIONS` is set on the server |
| POST | `/extensions/{name}/remove` | `{"operator"}`: turns it off now; its settings are kept → the row plus `"cleanup": {"released","left_in_place": [{"action_id","target","error"}], ...}` (what it took out of its service, e.g. `cloudflare_removed`). Audited as `extension_removed`. 404 / 409 as for add |
| POST | `/extensions/{name}/test` | one harmless call with the saved settings (reads Cloudflare, looks up 1.1.1.1, posts a Slack test line, classifies one line with Jev) → `{"ok","detail"\|"error"}`; 404 for an unknown name |
| POST | `/extensions/reload` | reads the settings file again and starts, stops or restarts each extension to match it → the rows. Audited as `extensions_reloaded` when something changed. The dashboard calls it after saving settings |
| GET | `/integrations` | the same rows as `GET /extensions` (the name before extensions) |
| POST | `/integrations/{name}/test` | the same as `POST /extensions/{name}/test`; a built-in name answers `{"ok": false, "error"}` |
| POST | `/telegram/link-codes` | Telegram extension (404 while it is not added): `{"contact","operator"}` → `{"contact","name","code","expires_at","valid_minutes","send"}` |
| POST | `/telegram/link` | Telegram extension, called by the bot: `{"code","chat_id","username"}` → the link |
| POST | `/telegram/unlink` | Telegram extension: `{"chat_id"}` or `{"contact"}`, plus `"operator"` |
| GET | `/telegram/links` | Telegram extension: linked private chats `[{"contact_id","chat_id","name",...}]` |
| POST | `/threats/scan` | `{"operator", "paths": optional list}`: read-only threat scan of the folders in `threat_scan.paths` (or `paths`); returns `{"roots","files_checked","counts","findings":[{"id","path","entry","line","key","kind","severity","label","snippet","sha256"}],"new_alerts"}`. New critical/high findings are ingested as events with `source: "threat_scan"` (category `malware`), each once; audited as `threat_scan` |
| GET | `/threats` | latest threat scan, same shape |
| POST | `/threats/{id}/quarantine` | `{"operator", "reason": optional}`: moves that file (by finding id, only if unchanged since the scan) into quarantine; audited as `file_quarantined` |
| GET | `/quarantine` | files in quarantine: `[{"id","name","original","sha256","finding","operator","at"}]` |
| POST | `/quarantine/{id}/restore` | `{"operator"}`: puts the file back; audited as `file_restored` |
| POST | `/staff-reports` | `{"text", "reporter", "contact", "where", "channel", "sender", "host"}` (only `text` required; `host` is the machine it is about, a name from `GET /machines` on a central panel, and becomes the incident's host, 10-4000 characters; `sender` is the reporter's address or chat id for the limit of 5 per 10 minutes) → `{"id","status","kind","kind_label","urgency","advice"}`, the answer for the reporter. 400 for too little text, 429 when the limit is hit. Sorted by the AI model or keyword rules, ingested as an event with `source: "staff_report"` (category `staff_report`, needs review, never contained); audited as `staff_report_received` |
| GET | `/staff-reports?status=` | `{"reports": [...newest first], "counts": {"new","reviewing","resolved","not_a_threat"}}`; `status` filters, `open` = new + reviewing. A report: `{"id","received_at","channel","reporter","contact","where","host","text","triage": {"kind","urgency","summary","advice","for_tech","by": "ai" \| "keywords"},"status","assignee","incident","notes","history","kind_label"}` |
| GET | `/staff-reports/{id}` | one report |
| POST | `/staff-reports/{id}` | `{"operator", "status": optional, "assignee": optional, "note": optional}`. Status `new`, `reviewing`, `resolved` or `not_a_threat`; closing needs a note. An assignee or note on a new report makes it `reviewing` and acknowledges its incident; closing the last open report on an incident resolves it (or rejects it when every report was `not_a_threat`). Audited as `staff_report_updated` |
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
  "actor": {"host", "user", "via", "address", "key", "session", "trust": "trusted" | "unknown" | "suspect", "why", "since"} | null,
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
- Writes JSON-lines logs to `*.jsonl` in the collector's logs folder (`SENTRAI_LAB_LOGS`, by default `logs/` in the data root). Honors core `/blocklist` (poll every 2 s; if core down, allow).
- Tripwires (off unless `SENTRAI_SPINES=1`): honeypot `/admin-legacy`, a planted credential, bait `members` rows and a tarpit. Each touch goes to `deception.jsonl` in that folder; the collector sends it with `"source": "tripwire"` and a raw text starting `tripwire <kind>:` (the older `cactus_spine` / `cactus-spine` forms are still accepted), and core rules turn it into an incident at confidence 1.0 (only for that source).
- Because clients are local, the attacker IP is taken from header `X-Demo-Src-IP` when present (demo spoofing so different "attackers" can be shown), else remote_addr.

## Rules for all agents
- Do NOT call any `mcp__hearthbot__*` tool. Do not push to git; the lead integrates and pushes.
- Write only inside your own folder. If you need a contract change, write it in `<your folder>/CONTRACT_REQUESTS.md` and code defensively.
- No real attacks against anything but 127.0.0.1. No real command execution from web input.
- Include a `README.md` in your folder with run commands, and smoke tests (`pytest`) where reasonable.
- All synthetic data must be obviously fake (e.g. `Member 0001`).
