# SentrAI MVP

A working prototype of SentrAI that runs natively on one Windows laptop or Linux machine (no Docker).

| Component | Folder | What it does | URL |
| --- | --- | --- | --- |
| Core | `core/` | FastAPI risk engine, rules + Jev classifier, agents (Warden, Gatehouse, Vault, Garrison, Countersign, Watchdog, Scribe, HelpDesk), TTL hotpatches, hash-chained audit log, evidence reports (Markdown/JSON/PDF) | http://127.0.0.1:8000 |
| Collector | `lab/collector/` | Tails the logs you approve (nginx, sshd, journald, or JSON-lines app logs) and sends normalized events to core | |
| Scout | `lab/scout/` | Finds the security logs on a new system | |
| Dashboard | `dashboard/` | Streamlit console with a sidebar menu: Configuration (home), Approvals, Collector, Classifier, Action taker, Review (gauge, threshold, risk accumulated), Reports, Audit trail. Menu bubbles flag new malicious activity per part | http://127.0.0.1:8501 |
| Notifier | `notifier/` | Telegram bot with Approve / Reject buttons, or console mode without a token | |

The interface between components is defined in [`CONTRACT.md`](CONTRACT.md).

## Run SentrAI

Requirements (Windows): Windows 10/11, Python 3.12 on PATH. Each component gets its own `.venv`, created automatically on first run.

```powershell
cd mvp
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

Stop everything with `.\stop.ps1`.

The timers (SLA, inaction penalty, block expiry) run in real time. For a quicker test,
`.\run.ps1 -Speed 60` makes 1 real minute count as 1 hour.

### On Linux (or macOS)

Requirements: Python 3.11+ with the `venv` module (Debian/Ubuntu: `sudo apt install python3-venv`).
`run.sh` does the same as `run.ps1`, but runs each component in the background and
writes its output to `mvp/.run_logs/<name>.log` instead of opening a window.

```bash
cd mvp
./run.sh                                # also: --speed 60, --no-dashboard, --no-browser
tail -f .run_logs/core.log              # to watch a component
./stop.sh
```

If port 8000 or 8501 is taken, pick others: `./run.sh --core-port 8100 --dashboard-port 8601`
(`.\run.ps1 -CorePort 8100 -DashboardPort 8601` on Windows, or set `CACTAI_CORE_PORT` /
`CACTAI_DASHBOARD_PORT`).

### Point it at real logs

SentrAI only sees the logs you approve. On a Linux server, `cd lab && .venv/bin/python -m collector.collector --add-system-logs`
approves nginx and SSH logs; anywhere else, use Scout or the dashboard's **Collector** page
(process scan, Scout proposals). See [lab/README.md](lab/README.md).

Blocking an IP only takes effect outside SentrAI when `CACTAI_FIREWALL` is on (or a responder
webhook is set): without it, blocks are recorded on SentrAI's own blocklist (`/blocklist`)
for your app or proxy to enforce. Add your own IP to `PROTECTED_IPS` first.

### On a server (systemd services)

To keep SentrAI running on a Linux server, install it as services instead of using `run.sh`:
`sudo ./deploy/install.sh --protect <your admin IP>`. It opens the dashboard over HTTPS to that IP
only and prints the address and the sign-in. See [deploy/README.md](deploy/README.md).

## Configuration

### First-run setup

On a new machine, `run.ps1` / `run.sh` (and the collector when started on its own) first runs a
short setup wizard. It starts with a **security preset** (Strict, Moderate or Balanced), which
sets the detection and response values, or **Advanced** to set each of them yourself. Then one section per part: **collector** (logs directory and log file names),
**classifier** (brute-force and bulk-export thresholds, TypeSafe key), **responder** (risk
threshold, block expiry, SLA, IPs and accounts never to touch) and **notifications**
(Telegram). Press Enter at every question to keep the defaults.

The answers are saved to `%USERPROFILE%\.cactai\config.json` (or the path in `CACTAI_CONFIG`)
and every component reads that file on start. A variable set in the environment still wins.

```powershell
python cactai_config.py            # show the current settings (runs the wizard on a new machine)
python cactai_config.py setup      # change them
```

The file holds the TypeSafe key and Telegram token in plain text, so keep it in your own
user folder. `run.ps1` / `run.sh` never delete logs.

### Set up with Cyanide (no Configuration page)

The dashboard's **Chat** page can do the same setup as a conversation. Until a machine has
been set up, the dashboard opens on Chat with a **Set up with Cyanide** offer (the **Setup**
button on Chat, or **Set up with Cyanide** on Configuration, starts it any time). Cyanide asks
what SentrAI guards and suggests a preset, then the logs folder, IPs and accounts never to
touch, your name, how to alert you (Telegram and/or email), the AI key, and the dashboard:
who may open it (this computer, or named IP addresses), its port, and the sign-in email and
password (saved only as a hash, used from the next sign-in). Opening the dashboard to other
computers changes the firewall, so Cyanide ends with the one `sudo ./deploy/install.sh
--dashboard-allow ...` command that applies it on a Linux server. Answer with the buttons or by typing. Keys and passwords go in a hidden field and are
never shown in the chat. Nothing is saved until you confirm the summary; it then saves through
the same settings file, switches Cyanide to the new AI settings, and says what needs a restart.

It is scripted, so it works without an AI key (and with the core stopped). With an AI model
set, Cyanide also understands answers that match no button ("we're a dental clinic") and
answers questions asked along the way (`POST /chat/setup/interpret`; secrets are never sent).
The settings file records how setup was finished (`"setup_done"`).

### Security presets

| Value | Strict | Moderate (default) | Balanced |
| --- | --- | --- | --- |
| Brute force: failed logins / seconds (`BRUTE_FORCE_COUNT` / `_WINDOW_S`) | 3 / 120 | 5 / 60 | 8 / 60 |
| Rows in one export that count as exfiltration (`EXPORT_ROWS_THRESHOLD`) | 50 | 100 | 250 |
| Risk at which temporary blocks start (`RISK_THRESHOLD`) | 65 | 80 | 90 |
| Hours before a block expires (`HOTPATCH_TTL_HOURS`) | 4 | 2 | 1 |
| Hours a person has to respond (`SLA_HOURS`) | 1 | 2 | 4 |
| AI confidence needed to act without a person (`NEEDLE_MIN_CONFIDENCE`) | 0.5 | 0.6 | 0.75 |

Strict acts early and holds longer (more alerts, some false positives). Moderate is what the
demo uses. Balanced puts day-to-day operations first. Advanced sets each value by hand. The
settings file keeps the choice (`CACTAI_PRESET`) and every value; values that no longer match
their preset are saved as Advanced. On the dashboard's Configuration page, changing any value
under **Advanced settings** switches the preset to Advanced, and every other section is folded
behind an arrow.

### Variables

| Variable | Default | Used by |
| --- | --- | --- |
| `DEMO_SPEED` | 60 | core |
| `RISK_THRESHOLD` | 80 | core |
| `SLA_HOURS` / `HOTPATCH_TTL_HOURS` | 2 / 2 | core |
| `ON_DUTY`, `TEAM_LEAD`, `IT_MANAGER`, `CXO` | sample names | core (reports, escalation) |
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | core: never auto-blocked (blocklist or firewall); add your admin IP here before enabling `CACTAI_FIREWALL` |
| `PROTECTED_USERS` | empty | core: more accounts never auto-locked; admin and service accounts (root, admin, administrator, www-data, nginx, postgres, ...) are always protected |
| `PROTECTED_NETS` | private ranges | core: networks Countersign never blocks on its own (an operator still can); `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7` by default, `off` for a lab whose attackers sit on a private network |
| `INFRA_ALLOWLIST` | empty | core: gateways, DNS, monitoring and other infrastructure never blocked (addresses or networks). This machine's DNS servers and default gateway are added automatically (`INFRA_AUTODETECT=0` turns that off) |
| `CONTAIN_MIN_SEVERITY` / `CONTAIN_MIN_POINTS` | `high` / `20` | core: an incident is only contained without a person when its own severity and points reach these, whatever the overall risk index |
| `CACTAI_FIREWALL` | `off` | core: also block IPs in the host firewall (`auto`, `nftables`, `iptables`, `netsh`); `off` keeps blocks on SentrAI's own blocklist only |
| `CACTAI_FIREWALL_ENFORCE` | `0` | core: `0` is a dry run that only logs the firewall command; `1` really runs it (needs admin/root) |
| `CACTAI_RISK_SCOPE` | `fleet` | core: `host` scores and blocks each machine on its own, for a central panel (set `CACTAI_FIREWALL=off` with it) |
| `CACTAI_PUBLIC_URL` | `http://127.0.0.1:8000` | core and dashboard: the core's address as other machines see it; fills in **Add machine** and report links |
| `CACTAI_AGENT_OFFLINE_HOLD_H` | `24` | agent: hours blocks stay in place while the panel cannot be reached |
| `AUTO_ACTIONS` | `block_ip,rate_limit,waf_rule` | core: action types SentrAI may take on its own; any other type waits for a person |
| `MAX_AUTO_ACTIONS_PER_HOUR` | `10` | core: automatic actions allowed in any rolling hour; past it a person decides |
| `MAX_TTL_HOURS` / `ACTION_TTL_HOURS` | `24` / unset | core: longest any temporary action lasts; per-type hours such as `lock_user=1,block_ip=4` |
| `CHECK_AFTER_MIN` / `CACTAI_HEALTH_URL` | `10` / unset | core: minutes after an action to check it worked and did no harm; a page that must keep answering meanwhile |
| `UNDO_RETRY_S` / `UNDO_RETRIES` | `60` / `3` | core: how often and how many times a failed undo is retried before a person is asked |
| `CACTAI_BACKUP_PATHS` | (none) | core: folders to back up, separated by `:` (Linux) or `;` (Windows), when the system profile's `backup.paths` names none. SentrAI's own data is always backed up |
| `CACTAI_BACKUP_EVERY_HOURS` | `24` | core: hours between scheduled backups; `0` turns the schedule off (Back up now still works) |
| `CACTAI_BACKUP_KEEP` | `7` | core: how many backups to keep; the oldest go first |
| `CACTAI_BACKUP_DIR` | `backups` next to `CACTAI_DB` | core: where backups are stored |
| `CACTAI_BACKUP_COPY_TO` | (none) | core: a second folder (another drive or a network share) that gets a copy of each backup |
| `TYPESAFE_API_KEY` | unset | core: enables Jev (TypeSafe System One); otherwise rules + fallback heuristic |
| `JEV_TIMEOUT_S` / `JEV_BUDGET_S` | 3 / 2 | core: per-call timeout and per-request time budget for Jev |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | unset | notifier: console mode when unset |
| `SMTP_HOST`, `ALERT_EMAIL_TO` | unset | notifier: email alerts off when either is unset |
| `SMTP_PORT` / `SMTP_SECURITY` | 587 / `starttls` | notifier: `starttls`, `ssl` (port 465) or `none` |
| `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_FROM` | unset | notifier: SMTP login and sender (sender defaults to the login) |
| `CACTAI_EMAIL_MODE` | `backup` | notifier: `backup` emails only when Telegram fails; `always` emails every alert too |
| `CACTAI_DASHBOARD_URL` | `http://127.0.0.1:8501` | notifier: link in email alerts |
| `CACTAI_CORE_URL` | `http://127.0.0.1:8000` | lab, dashboard, notifier |
| `CACTAI_NODE_NAME` | `This computer` | dashboard: this machine's name in the Machines list on Review |
| `CACTAI_PEERS` | unset | dashboard: other SentrAI cores to show in the Machines list, as `Name=URL, Name=URL`; they must accept this console's API token |
| `CACTAI_LAB_LOGS` | `mvp\lab\logs` | lab: the collector tails JSON-lines logs here |
| `CACTAI_LOG_ACCESS`, `_AUTH`, `_DB`, `_OS` | `access.jsonl`, `auth.jsonl`, `db.jsonl`, `os.jsonl` | lab: log file names |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | 5 / 60 | core: failed logins that count as brute force |
| `EXPORT_ROWS_THRESHOLD` | 100 | core: rows in one export that count as exfiltration |
| `NEEDLE_MIN_CONFIDENCE` | 0.6 | core: AI confidence Countersign needs before approving an autonomous action |
| `CACTAI_PRESET` | `moderate` | wizard and dashboard: `strict`, `moderate`, `balanced` or `advanced` |
| `CACTAI_OPERATOR` | `operator` | notifier: name shown on approvals |
| `CACTAI_CONFIG` | `~\.cactai\config.json` | all: where the setup wizard saves settings |
| `CACTAI_API_TOKEN` | generated | all: the token the core API requires (`python cactai_config.py token` prints it) |
| `CACTAI_DASHBOARD_EMAIL` | `admin@sentrai.local` | dashboard: the sign-in email |
| `CACTAI_DASHBOARD_PASSWORD_HASH` | made on first run | dashboard: the sign-in password, saved only as a salted PBKDF2 hash |
| `CACTAI_DASHBOARD_LOGIN` | on | dashboard: `off` opens it without signing in (local testing only) |

### Access

The core API refuses every request without its token, except `/health` and `/blocklist` (so an
app or proxy can enforce blocks). The token is generated on first run, saved in the settings file,
and passed to the collector, dashboard and Telegram bot by `run.ps1` / `run.sh`. The report link in a Telegram alert is signed for that one report,
so it opens in a browser without the token. To call the API by hand:

```powershell
$t = python cactai_config.py token
Invoke-RestMethod http://127.0.0.1:8000/incidents -Headers @{ Authorization = "Bearer $t" }
```

The dashboard asks for an email and password. The first run makes them: the wizard asks for
both (Enter makes a random password), and `run.ps1` / `run.sh` print the sign-in at the end, with the
password shown only that once. Only a salted hash of the password is saved. After five wrong
tries from one address, that address waits five minutes.

```bash
python cactai_config.py admin                                  # show the sign-in email (makes one if missing)
python cactai_config.py admin --reset                          # new password, printed once
python cactai_config.py admin --email you@example.com --reset  # new email and password
```

You can also change the password on the dashboard: Configuration, section 6. For local testing
where you do not want to sign in, start SentrAI with `CACTAI_DASHBOARD_LOGIN=off`
(`$env:CACTAI_DASHBOARD_LOGIN = "off"` in PowerShell). Settings saved with the older plain
dashboard password keep working; the file then keeps only its hash.

### Telegram setup (optional)

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token.
2. Send any message to your new bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Enter both in `python cactai_config.py setup`, or before `run.ps1`: `$env:TELEGRAM_BOT_TOKEN = "<token>"; $env:TELEGRAM_CHAT_ID = "<chat id>"`.

Only the configured chat can press the buttons.

### Email alerts (optional backup)

Email carries the same alert content as Telegram, including SLA reminders and escalations,
and links to the dashboard for the buttons. Set the SMTP server and recipients in
`python cactai_config.py setup` (section 4) or on the dashboard's Configuration page.
With `CACTAI_EMAIL_MODE=backup` an alert is emailed only when Telegram cannot deliver it;
with `always` every alert is emailed too. In console mode (no Telegram) alerts are emailed as
well as printed. With no SMTP settings, nothing is emailed. For Gmail use `smtp.gmail.com`,
port 587, and an app password. The audit log records the channel used (`telegram`, `email`,
`telegram+email`, `console+email`).

## The three parts

SentrAI is a pipeline of three pluggable parts. Each part is one small base class with
one job; to add a new one, subclass it and add it to the list shown.

| Part | Base class | Implement | Built-in versions | Register in |
| --- | --- | --- | --- | --- |
| 1. Collector | `Source` in `lab/collector/collector.py` | `poll()` returns new events (build them with `make_event`) | `JsonLogSource`, `HeartbeatSource` | `default_sources()` |
| 2. Classifier | `Classifier` in `core/app/classifier.py` | `classify(event, now)` returns a `Classification`, or `None` to pass | `RulesClassifier` → `JevClassifier` → `FallbackClassifier` | `default_chain()` |
| 3. Responder | `Responder` in `core/app/responders.py` | `apply(action)` returns True when in force; `revert(action)` undoes it | `BlocklistResponder` (block_ip, lock_user), `SimulatedResponder` (the rest) | `Saguaro.__init__` |

Events travel from part 1 to part 2 over `POST /events` as plain dicts (`CONTRACT.md`).
Between parts 2 and 3 sit the risk engine and Countersign: an action only reaches a responder
after an operator approves it, or after Countersign approves it above the risk threshold. The
allowlist of action types is whatever the registered responders handle, and every action
goes back through its responder when it expires or is rolled back.

Example: a new classifier.

```python
class AttackToolClassifier(Classifier):
    name = "user_agent"

    def classify(self, event, now):
        if "sqlmap" in str(event.get("raw", "")).lower():
            return Classification("sql_injection", 0.9, 0.95, "known attack tool user agent")
        return None  # not mine: next classifier decides
```

## Tests

GitHub Actions (`.github/workflows/tests.yml`) runs the core, lab, dashboard and notifier suites on Windows and Linux for every pull request and every push to `main`. It needs no API keys.

| Suite | Command (from the component folder) | Result |
| --- | --- | --- |
| Core | `.venv\Scripts\python -m pytest -q` | 27 passed |
| Lab | `.venv\Scripts\python -m pytest -q` | 36 passed |
| Dashboard | `.venv\Scripts\python -m pytest -q` | 25 passed |
| Notifier | `.venv\Scripts\python -m pytest -q` | 8 passed |

## Safety

- Containment only changes SentrAI's own blocklist unless `CACTAI_FIREWALL` is on. Your own machine (127.0.0.1) and `PROTECTED_IPS` are never blocked.
- Admin and service accounts are never auto-locked, and private networks are never auto-blocked (`PROTECTED_NETS`).

## Known limits

- Incidents, blocks and notifications are saved in SQLite next to the audit chain and restored when the core restarts. Blocks keep their original TTL; any that expired while the core was down are rolled back and audited on start.
- Only IP blocks and account locks have a real effect. Rate limit, WAF rule, kill process and revoke ACL are recorded as simulated.
- Jev has not been called against the live TypeSafe API yet (no API key); without a key the fallback heuristic classifies what the rules cannot.
- Telegram mode has not been tested with a real bot.
