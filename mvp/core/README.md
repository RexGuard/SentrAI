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
| `DEMO_SPEED` | `1` | Timer hours per real hour. 1 is real time; for testing, 60 makes 1 real minute count as 1 hour. |
| `RISK_THRESHOLD` | `80` | Risk index at which autonomous containment starts. |
| `SLA_HOURS` | `2` | Acknowledgement SLA, in hours. |
| `HOTPATCH_TTL_HOURS` | `2` | How long a hotpatch lasts, in hours. |
| `ACTION_TTL_HOURS` | unset | Per-type expiry, e.g. `lock_user=1,block_ip=4`. Types not listed use `HOTPATCH_TTL_HOURS`. |
| `MAX_TTL_HOURS` | `24` | Business limit: no temporary action lasts longer than this (0 = no limit). |
| `AUTO_ACTIONS` | `block_ip,rate_limit,waf_rule` | Action types SentrAI may take on its own. Anything else (lock an account, kill a process, revoke access) waits for a person to approve it. Making any action permanent always needs a person. |
| `MAX_AUTO_ACTIONS_PER_HOUR` | `10` | Business limit on automatic actions in any rolling hour; past it a person decides (0 = never act alone). |
| `CHECK_AFTER_MIN` | `10` | After-action check, this many minutes after an action starts: did the target still get through, and did everyone else's traffic, server errors or the health page get worse? Problems are alerted to the on-duty person. |
| `SENTRAI_HEALTH_URL` | unset | A page that should keep answering while SentrAI blocks things (probed when an action starts and at its check). |
| `UNDO_RETRY_S`, `UNDO_RETRIES` | `60`, `3` | A failed undo (the firewall rule or webhook did not confirm removal) is retried this often, this many times, then left to a person. Every undo is recorded as `action_undone` or `action_undo_failed`. |
| `ON_DUTY` | `On-duty responder` | The responsible entity named in reports and notifications, e.g. `Amir Tan (SEC-409) / Night shift`. |
| `TEAM_LEAD`, `IT_MANAGER`, `CXO` | role names | Escalation recipients. |
| `SENTRAI_ROUTING` | `routing.json` next to the database | Contacts, routing rules and follow-up policy (see "Owners, routing and escalation"). Without the file, the four names above form the chain. |
| `SENTRAI_SUMMARY` | `daily` | How often the one-page client summary goes out on the alert channels: `daily`, `weekly` or `off`. A choice saved on the dashboard (Reports page, kept in `summary.json` next to the database) wins over this. |
| `SENTRAI_SUMMARY_AT` / `SENTRAI_SUMMARY_DAY` | `08:00` / `mon` | Local time it goes out, and the weekday for `weekly`. |
| `SENTRAI_SUMMARY_TO` | `Client` | Who the summary is addressed to (shown on the page). |
| `TYPESAFE_API_KEY` | unset | Turns on Jev (TypeSafe System One). Without it the fallback classifier is used. |
| `JEV_TIMEOUT_S` | `3` | Timeout for each Jev call. After 3 failures in a row a 60 s circuit breaker opens. |
| `JEV_CACHE_SIZE` / `JEV_CACHE_TTL_S` | `2048` / `3600` | Jev answers kept per log template (the line with IPs, times, ids, pids and ports replaced), so the same request from many addresses is asked about once. Size `0` turns the cache off. |
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | Addresses never blocked, by the portal or the firewall. Add your own admin IP before turning the firewall on, e.g. `PROTECTED_IPS=127.0.0.1,::1,localhost,198.51.100.200`. |
| `SENTRAI_FIREWALL` | `off` | Mirror `block_ip` into the host firewall: `auto`, `nftables`, `iptables` (Linux) or `netsh` (Windows). `off` keeps blocking portal-only. |
| `SENTRAI_WEBHOOK_MAPS` | unset | Field maps for `POST /webhook/<name>` (inline JSON or a file path), e.g. `{"wazuh": {"src_ip": "data.srcip", "raw": "full_log", "layer": "=os"}}`. Without a map, common key names are guessed. See CONTRACT.md. |
| `SENTRAI_RESPONDER_WEBHOOK_URL` | unset | Also hand approved actions to another system (a firewall API, WAF or SOAR) as JSON POSTs `{"op": "apply"\|"revert", "type", "target", ...}`. An action counts as in force only on a 2xx answer. Blocks still go on `/blocklist` too. |
| `SENTRAI_RESPONDER_WEBHOOK_ACTIONS` | all six | Which action types go to the webhook (`block_ip,lock_user,rate_limit,waf_rule,kill_process,revoke_public_acl`). |
| `SENTRAI_RESPONDER_WEBHOOK_SECRET` | unset | Sent as `Authorization: Bearer` and used to sign each body (`X-SentrAI-Signature: sha256=<HMAC>`). `_FILE` works too. |
| `CLOUDFLARE_API_TOKEN` | unset | Also block each `block_ip` address at Cloudflare (app/cloudflare.py) and remove it when the block ends. `_FILE` works too. Needs `CLOUDFLARE_ZONE_ID` (one site) or `CLOUDFLARE_ACCOUNT_ID` (every site). A Cloudflare failure never weakens the local block; a failed removal is a failed undo (retried, on-duty told). |
| `CLOUDFLARE_METHOD` / `CLOUDFLARE_MODE` | `access_rule` / `block` | `list` puts addresses in an account IP list (`CLOUDFLARE_LIST_ID`) for your own WAF custom rule. Mode: `block`, `managed_challenge`, `challenge`, `js_challenge`. |
| `ABUSEIPDB_API_KEY` | unset | Look up each public attacking address on AbuseIPDB in the background and note it on the incident (context only, no score change). Answers kept `ABUSEIPDB_CACHE_HOURS` (24). |
| `SLACK_WEBHOOK_URL` | unset | The notifier posts a copy of every alert there. The core only uses it for `POST /integrations/slack/test`. |
| `SENTRAI_FIREWALL_ENFORCE` | `0` | `0` is a dry run: the command is logged and written to the audit trail, never run. `1` runs it (admin/root). Loopback, link-local, multicast and `PROTECTED_IPS` are never sent to the firewall. |
| `SENTRAI_DB` | `data/sentrai.db` | SQLite audit chain. |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | `5` / `60` | Brute-force rule: this many failed logins from the same IP within this many seconds. |
| `EXPORT_ROWS_THRESHOLD` | `100` | `/export` with at least this many rows counts as data exfiltration. |
| `SSH_BRUTE_FORCE_COUNT` / `SSH_BRUTE_FORCE_WINDOW_S` | `5` / `600` | SSH brute force: this many failed guesses (not log lines) from one IP within this many seconds. |
| `SLOW_BRUTE_FORCE_COUNT` / `SSH_SLOW_BRUTE_FORCE_COUNT` / `SLOW_BRUTE_FORCE_WINDOW_S` | `20` / `10` / `86400` | Slow brute force: failed logins from one IP across web, Windows and SSH within this many seconds (SSH uses the lower count). `0` turns it off. |
| `WEB_SCAN_4XX_COUNT` / `WEB_SCAN_WINDOW_S` | `10` / `120` | Web path scanning: this many 4xx replies to one IP within this many seconds (crawlers such as Googlebot, `favicon.ico`, `robots.txt` and ACME challenges do not count). |
| `AUTO_CLOSE_QUIET_MIN` | `60` | Resolve an open scan or brute-force incident after this many real minutes with no new event and no containment in force. `0` turns it off. |
| `AUTO_CLOSE_CATEGORIES` | `port_scan,brute_force` | Which categories auto-close. Other incidents always wait for an operator. |
| `WATCHDOG_SILENCE_S` | `30` | Watchdog flags a collector after this many seconds of silence. |
| `INTEGRITY_CHECK_S` | `30` | How often the integrity guard re-checks the audit chain and the clock. |
| `CLOCK_JUMP_S` | `120` | A clock change bigger than this (core host or a collector) counts as log tampering. |
| `ANCHOR_EVERY_MIN` | `60` | Send the signed record fingerprint to the alert channels this often (real minutes, only when new records exist; 0 = never). |
| `SENTRAI_ANCHOR_KEY` | (made on first use) | Fingerprint signing key. Default: `anchor.key` next to the audit database, mode 0600. |

### Owners, routing and escalation

Every incident gets an owner the moment it opens. `app/routing.py` reads a routing file
(`SENTRAI_ROUTING`, sample `profiles/routing.example.json`) with:

- **contacts**: name, role (`on_duty`, `team_lead`, `it_manager`, `cxo`), email, Telegram handle and a **backup** contact.
- **rules**: match on `category`, `severity`, `host` (patterns like `db-*`) and `layer`. The first match wins: its
  `owner` owns the incident and hears every reminder; the people under `notify` hear about it once.
- **follow_up**: `escalate_after_reminders` (default 2), `max_escalations` (3), `resolve_within_hours` (24).

Without a file, the defaults are: critical incidents tell the team lead, IT manager and CXO; malware, data export,
log tampering and privilege escalation tell the team lead and IT manager; high tells the team lead; the on-duty
operator owns all of them, backed up by the team lead, then the IT manager, then the CXO.

Unanswered alerts: once the SLA passes, the owner gets a reminder every hour. After `escalate_after_reminders`
unanswered reminders, the incident is handed to the owner's backup (`escalated` notification to both,
`incident_escalated` audit record), up to `max_escalations` times. Acknowledging stops it. An acknowledged incident
that is still not resolved after `resolve_within_hours` gets a `resolve_reminder` to its owner (up to 3).

The dashboard's **Incidents > Who gets what** draws this as a map (incident, rules, owner, also told, backup) and has
forms to add or remove people, change which incident types go to whom, reorder rules and set the follow-up. They save
through `POST /routing`, which checks the whole file first (owners and backups must be people in it, categories and
severities must be known ones) and writes it in one step, so a bad edit never half-applies. Owners and Admins can edit;
Auditors see the forms greyed out. Each save is a `routing_changed` audit record with who did it.

Each notification carries `deliver_to` (the recipients' email and Telegram from the contacts): the notifier
emails those addresses instead of `ALERT_EMAIL_TO`. The Telegram **Take it** button makes whoever pressed it the owner.

### Alerts in each person's own Telegram chat

A Telegram bot can only message someone who has opened a private chat with it, so each contact links their
chat once (`app/telegram_links.py`):

1. On the dashboard's Incidents page (Who gets what), pick the person and press **Make link code**
   (or `POST /telegram/link-codes {"operator", "contact"}`). The code works once, for 30 minutes.
2. The person sends `/link CODE` to the bot in a private chat (`/start CODE` from a `t.me/<bot>?start=CODE` link works too).
3. The notifier passes the code and the chat on to `POST /telegram/link`. Links are kept in `telegram_links.json`
   next to the database (`SENTRAI_TELEGRAM_LINKS` to move it). A contact whose `telegram` in the routing file is a
   numeric chat id counts as linked already. `/unlink` in that chat, or the dashboard's Unlink button, stops it.

From then on `deliver_to` carries each person's `telegram_chat`, and the notifier sends the alert, with its buttons,
to each of them directly. A button pressed there is recorded under the contact's name. The team group
(`TELEGRAM_CHAT_ID`) still gets notices that are for nobody in particular, and alerts for anyone who has not
linked a chat yet (they are @mentioned there); `TELEGRAM_GROUP_COPY=always` gives the group a copy of everything,
`off` keeps it quiet unless nobody could be reached. A direct message that fails (the person blocked the bot) goes
to the group instead. Each delivery is recorded per person (`deliveries[].to`), and linking, codes and unlinking
are audited (`telegram_link_code`, `telegram_linked`, `telegram_unlinked`).

The evidence report has a **Who handled it** section: the owner and backup, the routing rule, every hand-over,
escalation and the resolution from the audit records (each step with its record number), and who was reached in
their own chat. The plain-words summary tells the same story in a few sentences.

### Off-box copy

With `SENTRAI_REMOTE_COPY_URL` (and the append token in `SENTRAI_REMOTE_COPY_TOKEN` or a file named by
`SENTRAI_REMOTE_COPY_TOKEN_FILE`; `SENTRAI_REMOTE_COPY_CA` for a self-signed certificate), the core sends every
audit record and every sealed log line to a SentrAI witness on another machine as it happens (about 4 ms from
append to stored, measured locally). The witness can only add, and the core's token cannot read the copy back.
If the witness refuses a record because the chain here no longer continues its copy, the core opens a
**Log tampering** incident. To see exactly what changed, with the witness's read token:

```
python -m app.remote_copy compare --url https://198.51.100.20:8600 --read-token-file read.token
```

Status: `GET /audit/remote-copy`. Setup: `deploy/install-witness.sh` on the second machine, then
`deploy/install.sh --remote-copy ...` here (deploy/README.md, "Off-box copy").

### Record fingerprints

The audit chain proves its own consistency, but root on the server could rebuild it. So the core
sends the newest record's signed fingerprint off the box (Telegram/email) every `ANCHOR_EVERY_MIN`,
and every notification carries the full signed line as its `witness` (shown at the bottom of each
Telegram, email and console alert):

```
SENTRAI-FP v1 seq=1234 head=3fa9...e1 at=2026-10-02T10:00:00Z sig=8b12...
```

To check the chain on disk still matches a fingerprint you kept (`OK:` exit 0, `TAMPERED:` exit 1):

```
python -m app.anchor verify "SENTRAI-FP v1 seq=1234 head=... at=... sig=..."
python -m app.anchor show        # the current fingerprint
```

or `GET /audit/verify?fingerprint=...`. The notifier keeps the newest witness it delivered
(`notifier/data/last_witness.txt`), so `/verify` in the Telegram chat, or
`python notifier.py --verify`, checks the live chain against it without pasting anything
(`/verify <line>` checks an older one). An archived chain in `data/archive/` can be checked too;
pass it with `--db`.
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | Comma-separated IPs or networks that Countersign will never approve blocking. |
| `PROTECTED_NETS` | private ranges | Networks Countersign will not block on its own (RFC 1918, 100.64.0.0/10, fc00::/7); an operator can still approve a block. `off` disables. |
| `INFRA_ALLOWLIST` | empty | Infrastructure never blocked. The DNS servers and default gateway are added automatically unless `INFRA_AUTODETECT=0`. |
| `PROTECTED_USERS` | empty | Extra accounts never auto-locked. Admin and service accounts are always protected. |
| `CONTAIN_MIN_SEVERITY` / `CONTAIN_MIN_POINTS` | `high` / `20` | The incident's own bar for autonomous containment, on top of the overall risk threshold. Lower incidents wait for a person. |
| `SENTRAI_ENGINE` | `cyanide` | Orchestrator. `cyanide` plans with Claude when a key is set; `saguaro` keeps the fixed playbooks only. |
| `SENTRAI_LLM_API_KEY` | unset | The one AI key the setup wizard saves; used by whichever provider `SENTRAI_LLM_PROVIDER` names. With no key, Cyanide behaves exactly like Warden. A provider's own variable (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `COMMANDCODE_API_KEY`) still works and wins when set. |
| `SENTRAI_LLM_PROVIDER` | `auto` | `anthropic`, `openai`, `deepseek`, `commandcode` (also set `SENTRAI_LLM_MODEL`), or `compatible` (any OpenAI-compatible API: also set `SENTRAI_LLM_BASE_URL` and `SENTRAI_LLM_MODEL`). `auto` uses the first provider-specific key set. The dashboard's Configuration page has a Fetch models button that lists the models your key can use. |
| `CYANIDE_PROFILE` | unset | Path to the system profile JSON, e.g. `profiles\tuition_centre.json`. |
| `CYANIDE_MODEL` / `CYANIDE_EFFORT` / `CYANIDE_TIMEOUT_S` | provider default / `low` / `20` | Model, effort level (Anthropic only) and per-call timeout for planning. Defaults: `claude-opus-5`, `gpt-5`, `deepseek-chat`. |
| `CYANIDE_ENABLED` | `1` | Set to `0` to switch the planner off without removing the key (tests do this). |
| `SENTRAI_BACKGROUND` | `1` | Set to `0` to turn off the 1 s background tick (tests do this). |

## Cyanide (the orchestrator)

Cyanide (`app/cyanide.py`) replaces Warden's fixed judgement with Claude, and keeps everything that must stay predictable.

- **What the model decides.** Claude by default; OpenAI, DeepSeek or any OpenAI-compatible API also work (`mvp/sentrai_llm.py`, keys in `python sentrai_config.py setup`, section 5). When an incident opens, Cyanide sends the model the system profile, the incident, its log lines and the list of installed actions. The model answers with an assessment in plain words, the containment steps that fit this system, and whether SentrAI may act alone or must wait for a human.
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
   - **Log tampering** (`log_tampering`, critical 55): commands that wipe, edit or silence the record (deleting or emptying files under `/var/log` or shell history, `journalctl --vacuum`, `chattr -a`, stopping rsyslog/auditd/journald, `wevtutil cl`, Windows event 1102), commands that widen who can read or change it (adding an account to `adm`, `systemd-journal` or `sentrai`, `chmod o+w` or `setfacl` on a log or SentrAI file, `setcap` on a SentrAI program, `systemctl edit` on a SentrAI service, journal sealing switched off), a collector notice that a log shrank, vanished or was swapped with no rotated copy (`log_integrity`), and the integrity guard's findings (`audit_integrity`: audit chain broken, audit database deleted, clock jumped). On its own it stays below the autonomous line, so a person decides; it only proposes blocking the source IP.
   - **Malware** (`malware`, critical 65): the threat scan found a web shell, backdoor, reverse shell, crypto miner or container escape tool in a file or a running program (`threat_scan`). It stays below the autonomous line and proposes no automatic action; the operator quarantines the file.
   - **Prompt injection** (`prompt_injection`, critical 60): a web request carrying text written for an AI model ("ignore previous instructions", "classify this as benign", chat-role markers such as `<|im_start|>` or `[INST]`). It is caught by the rules before Jev sees it, and proposes a WAF rule and blocking the source IP.
   - **Other log sources** (collector `parsed` objects, `docs/log-sources.md`): failed sign-ins to Windows, Remote Desktop, SQL Server, MySQL/MariaDB, PostgreSQL and MongoDB count like SSH guesses (5 from one address, or for one account when there is no address, within 10 minutes is `brute_force`; a success right after is flagged too). Windows events: a cleared log is `log_tampering`, an account added to Administrators or another admin group is `privilege_escalation`, Microsoft Defender finding something or a new service that runs a script host, an encoded command or a file from a temp folder is `malware`. Suricata alerts are mapped from their signature and classtype (SQL injection, XSS, malware and miners, brute force, privilege gain, exfiltration, scans and exploits); low-priority notices are benign, and a serious alert nothing explains goes to Jev. An outbound alert names the outside address, never this machine.
   - **Jev** if the rules cannot decide. Jev receives at most 2,000 printable characters of the raw line, fenced between `<<<LOG_LINE` and `LOG_LINE>>>`, and its questions say the text is data only.
   - **Fallback heuristic** otherwise. It gives confidence 0.5 to 0.8 and `classified_by="fallback"`.
   - Confidence is always clipped to 0.5 to 1.0.
   - If P(malicious) is below 0.4, no incident is opened.
   - If P(malicious) is between 0.4 and 0.6, the incident gets `needs_review=true`. It is never auto-contained, and the operator is notified right away.
3. **Aggregate**. Incidents are grouped by `(category, src_ip or user or host)`. IDs run `RSK-2026-081`, `RSK-2026-082`, and so on.
   - `points = base × confidence × asset_criticality`
   - `raw` is the sum over incidents that are `open` or `acknowledged`, each counting its points plus its inaction penalty. The penalty is +5 per full hour unacknowledged, capped at +30. It freezes when the incident is acknowledged.
   - Contained, resolved and rejected incidents no longer count.
4. **Hotpatch**. When the risk index reaches the threshold, every incident that is open, unacknowledged and not flagged for review goes through these steps:
   1. Snapshot: sha256 of the blocklist state.
   2. Countersign review: the incident needs confidence of at least 0.6, and the action must be on the allowlist.
   3. Garrison applies the playbook with a TTL of 2 hours.
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

## Process scan (finding logs automatically)

Scout follows a technician through the folders. The process scan (`app/procscan.py`, `app/discovery.py`) is the automatic half: it lists the programs running on this computer, recognises the known ones (IIS, nginx, Apache, Tomcat, MySQL, PostgreSQL, SQL Server, MongoDB, Redis, SSH, Docker, syslog, Node and Python apps) and looks for their log files in the usual places, next to the program, in options such as `--log-file`, and (on Linux) in the files each process has open.

- **How.** Windows: PowerShell/CIM (`Win32_Process`, plus `Win32_Service` for the service account). Linux: `/proc`. macOS: `ps`. Standard library only, no admin rights needed; processes it cannot read are listed by name only.
- **Read-only.** It never starts, stops or signals a process and never reads log contents. It only checks which files exist.
- **Private details stay out.** Command lines are cut down to log options with secrets masked, home folders show as `~`, personal accounts as `(user)`. Credential stores and sensitive system processes (lsass, KeePass, 1Password, ssh-agent and similar) are skipped, and the profile can add more with `"process_scan": {"skip_processes": ["veyon*"]}` or turn scanning off with `"enabled": false`.
- **Nothing is watched until an operator says so.** Each file in a scan has an id. The dashboard's Collector page (Find logs on this computer) and Cyanide's chat buttons approve a file by that id, so neither the model nor a crafted request can point the collector at an arbitrary path. Approved files go to the same list Scout writes (`lab/scout/sources.json`), and the running collector starts tailing them within a few seconds, from the end of the file.
- **Cyanide.** Chat has two new tools: `scan_system` and `suggest_log_source` (a button, like `suggest_action`). Without an AI key, asking the chat to "scan" gives the scanner's own list with buttons.

Audit records: `system_scan` and `log_source_added`. The process scan also flags programs that look hostile (a known crypto miner, a mining-pool address or a reverse shell in the command line, a program running from `/tmp` or `/dev/shm`, or one whose file was deleted after it started); each is raised once as a `malware` alert (see below).

## Threat scan (signs of a break-in)

The process scan finds logs; the threat scan (`app/threatscan.py`, `app/threats.py`) looks inside files for what an intruder leaves behind: web shells and PHP backdoors, reverse shells, download-and-run one-liners, crypto miners, container escape tools used on shared game hosts (proot root systems, Alpine minirootfs, Harbor/Ptero-VM), `ld.so.preload` rootkit tricks, cron jobs and SSH keys added for persistence, and long encoded blobs. Ideas taken from a Pterodactyl malware scanner and rewritten for SentrAI's rules.

- **Which folders.** Only the ones you choose: `"threat_scan": {"paths": ["/var/lib/pterodactyl/volumes"], "every_minutes": 60}` in the system profile, or `SENTRAI_THREAT_PATHS` (separated by `:` on Linux, `;` on Windows). `every_minutes` repeats the scan in the background (default 60 when paths are set). SentrAI's own folders are always skipped.
- **What it reads.** Scripts and web pages (`.php`, `.sh`, `.py`, `.js`, `.jsp`, `.asp`, `.ps1`, ...), configuration files (including `config.yml`), extensionless scripts that start with `#!`, cron files, and the text and class files inside `.jar` plugins (only strong signs count there: miners, reverse shells, escape tools). `tmp/` and `logs/` are scanned on purpose, since that is where malware hides. Package caches (`node_modules`, `.git`, virtualenvs) and minified bundles are skipped. Files over `max_file_mb` (default 10) are skipped.
- **Tuning.** `"allow": ["*/plugins/dynmap/*"]` skips known-good paths; `"known_bad_sha256": [...]` flags exact files.
- **Each finding is raised once.** Critical and high findings become events (`source: "threat_scan"`) that the rules classify as `malware` (critical, 65), so they open an incident and notify like any other. A fingerprint of the file contents and signature is kept in `data/threat_seen.json` (`SENTRAI_THREAT_STATE`), so an hourly scan does not repeat the same alert; a file that changes is new again. Medium findings are only listed.
- **Nothing is deleted, and nothing happens on its own.** There is no auto-delete and no auto-suspend. An operator quarantines a file by its finding id (dashboard Collector page, or Cyanide's `suggest_quarantine` button). The file must be unchanged since the scan; it moves to `data/quarantine` (`SENTRAI_QUARANTINE`), read-only, with a note of where it came from, and `POST /quarantine/{id}/restore` puts it back.
- **Private details stay out.** Matched lines are cut to 160 characters with secrets masked and home folders shown as `~`; the model sees them labelled as untrusted text.

Audit records: `threat_scan`, `file_quarantined`, `file_restored`.

## Backups (putting a system back)

`app/backups.py` copies chosen folders, plus SentrAI's own data, on a schedule, so a defaced site or a wiped game server can be put back.

- **What.** The folders in `"backup": {"paths": ["/var/www"], "every_hours": 24, "keep": 7}` in the system profile, or `SENTRAI_BACKUP_PATHS`. SentrAI's own settings file, data folder (protection switch, signing key, threat state) and a consistent snapshot of the audit database are always included (`"include_sentrai": false` turns that off). `"exclude": ["*.log", "cache/*"]` skips files; `max_total_mb` (default 5120) refuses a backup that would fill the disk.
- **Where.** One `.tar.gz` per backup in `backups/` next to the database (`SENTRAI_BACKUP_DIR`), readable by SentrAI's account only, with a note beside it. `"copy_to": "/mnt/usb/sentrai"` (or `SENTRAI_BACKUP_COPY_TO`) puts a second copy on another drive or share. The newest `keep` are kept.
- **Proof.** Inside each archive, `manifest.json` lists every file with its SHA-256. The archive's own SHA-256 goes into the audit trail (`backup_made`), so **Check** (`POST /backups/{id}/verify`) catches a backup that was edited or swapped later.
- **Alerts.** A failed backup (or a failed second copy) sends a `backup_failed` notice to the on-duty contact; a failed scheduled one is retried after an hour, not every minute.
- **Restore needs a person**, and checks the backup first. By default files go into `restores/<id>-<time>/` next to the database and nothing live changes. Putting them back in place needs `in_place` and the backup id typed as `confirm`, and first takes a `before_restore` safety backup of the folders it will overwrite, so the restore can itself be undone. SentrAI's own data is never written over while the core runs; it is unpacked with a note on how to swap it in. The chat can show backups and offer a **Back up now** button, but cannot restore.
- **On a hardened server** (`deploy/install.sh`), the core runs as its own account and may only write under `/var/lib/sentrai/core`. Files it cannot read are skipped and listed on the backup. To restore in place there, add the folders to `ReadWritePaths=` in `sentrai-core.service`, or restore into a new folder and copy back by hand.
- **With the central panel** (planned agents on each machine), each agent runs this same code on its own machine and reports its backups to the panel.

Audit records: `backup_made`, `backup_failed`, `backup_verified`, `backup_restored`, `backup_pruned`.

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

Additions that do not change the contract:
- `GET /incidents/{id}/why`: HelpDesk explanation.
- `GET /summary/{daily|weekly}` (JSON), `.md` and `.pdf`: the one-page client summary for the last 24 hours or 7 days, in plain words, with counts, what needs attention and what to do next, a per-machine table and the audit fingerprint to check it by. `?until=<unix time>` ends the period earlier. The link sent to the client is signed (`?until=...&sig=...`) so it opens without the API token, for that period only.
- `GET /summary/schedule`, `POST /summary/schedule` (`{"operator", "every", "at", "day", "to"}`): the client's preference. `POST /summary/send` (`{"operator"}`) sends one now. Each send is audited as `summary_sent`, each change as `summary_schedule_changed`.
- Each incident carries `next_steps`: what a person should do next, in everyday words. The evidence report adds `in_plain_words`, `outcome`, `next_steps` and `how_to_check`, and its Markdown and PDF name each internal part by its job ("safety check", "record keeper") instead of its code name.
- `GET /helpdesk/why?target=<ip|user>`: "why was my IP blocked?"
- `GET /agents`: status of each agent and of Jev.
- `GET /limits`: the business limits on protective actions (what may run on its own, expiry per type, hourly cap and how much of it is used, after-action check delay).
- `GET /notifications`: all notifications, including delivered ones.
- `POST /heartbeat {"collector": "web-01"}`: collector heartbeat for Watchdog. An event with `"source": "heartbeat"` does the same.
- `POST /system/scan {"operator": "erick"}` and `GET /system/scan` (latest): read-only process scan with suggested log files.
- `POST /threats/scan {"operator": "erick"}`, `GET /threats`, `POST /threats/{id}/quarantine`, `GET /quarantine`, `POST /quarantine/{id}/restore`: threat scan and quarantine.
- `POST /incidents/{id}/assign {"operator", "assignee", "note"?}`: give the incident to a contact (id, name, role or Telegram handle) or anyone by name.
- `POST /incidents/{id}/resolve {"operator", "note"}`: close it with a note on what was done (400 without one). Blocks in force stay until they expire or are rolled back.
- `GET /routing`: the contacts, rules and follow-up policy in use; each contact has `telegram_linked`.
- `POST /routing` `{"operator", "routing": {"contacts", "rules", "follow_up"}}`: replace the routing file (same shape as
  `profiles/routing.example.json`). 400 with a plain reason when it does not check out; nothing is written then.
- `POST /telegram/link-codes {"operator", "contact"}`, `POST /telegram/link {"code", "chat_id", "username"}`,
  `POST /telegram/unlink {"operator", "contact" | "chat_id"}`, `GET /telegram/links`: personal Telegram chats (see above).
- `POST /notifications/{id}/delivered` takes an optional `"to"`: the one person a direct message reached.
- `GET /backups`, `POST /backups`, `POST /backups/{id}/verify`, `POST /backups/{id}/restore`: backups and restore.
- `GET /log-sources` and `POST /log-sources {"operator", "file_id", "layer"?}`: extra log files the collector watches; a file is added only by its id from the latest scan.

### Response shapes the contract leaves open

- `/audit` returns `{"chain_valid", "first_invalid_seq", "count", "head_hash", "records": [{"seq","ts","type","data","prev_hash","hash"}]}`.
- A notification has these fields: `id`, `incident`, `kind`, `title`, `text`, `recipients`, `risk_index`, `band`, `buttons`, `report_url`, `created_at`, `delivered`, `delivered_at`, `channel`, `message_id`, `deliveries`.
  - `deliver_to` lists `{id, name, email, telegram}` for each recipient found in the routing contacts, and `owner` is the incident's owner.
  - `kind` is one of `incident_opened`, `needs_review`, `sla_reminder`, `escalated`, `assigned`, `resolve_reminder`, `escalation`, `autonomous_action`, `operator_action`, `needs_operator`, `action_expired`, `action_check` (an action did not work or may be disrupting others), `undo_failed` (an action could not be confirmed removed) or `watchdog`.
  - `buttons` is a list of `[{label, action}]`, where `action` is one of `approve`, `reject`, `ack`, `rollback` or `permanent`.
- Incidents have extra fields beyond the contract: `asset_criticality`, `malicious_probability`, `needs_review`, `contribution`, `time_unaddressed_hours`, `classification_reason`, `analyzed_by`, `notifications`, `timeline`, `decisions`, `ack_channel`, and the ownership fields `owner`, `owner_id`, `backup`, `backup_id`, `assigned_by`, `assigned_at`, `route`, `notify`, `escalation_level`, `escalations`, `resolved_by`, `resolution`. Actions also carry `verified`, `enforcement`, `applied_at`, `executed_by`, `proposed_by`, `check_at` and `check` (the after-action check: `worked`, `worked_note`, `disruption`, `disruption_note` and the counts behind them), and once they stop, `ended_at` and `undo` (`ok`, `at`, `attempts`, `error`).

### Operator verbs

| Verb | What it does |
| --- | --- |
| `decision=approve` | Acknowledges the incident and applies the recommended playbook straight away (`mode: "operator"`, `approved_by: <operator>`). If containment is already active, the approval is recorded as an endorsement. |
| `decision=reject` | Requires a justification (HTTP 400 without one). Sets the status to `rejected` and rolls back any active actions. |
| `rollback` | Rolls back active actions. The incident becomes `acknowledged`, so its points count again but it will not be auto-contained. Returns 409 if nothing is active. |
| `permanent` | Makes active or expired actions permanent (no expiry). The incident becomes `resolved`. |
| `assign` | Makes someone the owner. A contact's backup comes from the contact book; someone outside it keeps the previous owner as backup. Tells the new owner unless they took it themselves. 409 on a closed incident. |
| `resolve` | Requires a note (HTTP 400 without one). Acknowledges if needed and sets the status to `resolved`. |
| `ack` | Records who acknowledged, when and on which channel. Freezes the inaction penalty. Idempotent. |

## Limitations

- Incidents, actions (blocks) and notifications are saved to `state_*` tables in the audit database (WAL mode) after every change, and restored on startup (`app/state.py`). Blocks still in force are put back with their original expiry; blocks whose TTL ran out while the core was down are rolled back, logged as `action_expired` with `while_core_down: true`, and summarised in a `state_restored` audit record. Rules-engine windows, the watchdog, the risk chart history and the chat history are not saved.
- The only containment with a real effect is `block_ip` and `lock_user`, through `/blocklist`. `rate_limit`, `waf_rule`, `kill_process` and `revoke_public_acl` are recorded and reported as "recorded (simulated)".
- Claude-written explanations are not used. Explanations and reports come from deterministic templates.
