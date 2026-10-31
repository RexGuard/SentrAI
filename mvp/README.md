# SentrAI MVP

A working prototype of SentrAI that runs natively on one Windows laptop or Linux machine (no Docker).

| Component | Folder | What it does | URL |
| --- | --- | --- | --- |
| Core | `core/` | FastAPI risk engine, rules + Jev classifier, agents (Warden, Gatehouse, Vault, Garrison, Countersign, Watchdog, Scribe, HelpDesk), TTL hotpatches, hash-chained audit log, evidence reports (Markdown/JSON/PDF) | http://127.0.0.1:8000 |
| Collector | `lab/collector/` | Tails the logs you approve (nginx, sshd, journald, Windows Event Log, Suricata, MySQL/MariaDB, PostgreSQL, MongoDB, or JSON-lines app logs) and sends normalized events to core | |
| Scout | `lab/scout/` | Finds the security logs on a new system | |
| Dashboard (classic) | `dashboard/` | Streamlit console, kept as the demo fallback; the main console is the web dashboard in `web/` with a sidebar menu: Configuration (home), Approvals, Collector, Classifier, Action taker, Review (gauge, threshold, risk accumulated), Reports, Audit trail. Menu bubbles flag new malicious activity per part | http://127.0.0.1:8501 |
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
(`.\run.ps1 -CorePort 8100 -DashboardPort 8601` on Windows, or set `SENTRAI_CORE_PORT` /
`SENTRAI_DASHBOARD_PORT`).

The web dashboard (main console) starts next to it: `web/run-web.sh` (`web\run-web.ps1`), then open http://127.0.0.1:5173. See `web/README.md`.

### Point it at real logs

SentrAI only sees the logs you approve. On a Linux server, `cd lab && .venv/bin/python -m collector.collector --add-system-logs`
approves nginx and SSH logs; anywhere else, use Scout or the dashboard's **Collector** page
(process scan, Scout proposals). See [lab/README.md](lab/README.md).

Blocking an IP only takes effect outside SentrAI when `SENTRAI_FIREWALL` is on (or a responder
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

The answers are saved to `%USERPROFILE%\.sentrai\config.json` (or the path in `SENTRAI_CONFIG`)
and every component reads that file on start. A variable set in the environment still wins.
Everything else SentrAI keeps (the audit record, read positions, Scout's lists, backups) goes in
the same folder, one sub-folder per part: see [DATA.md](DATA.md), or run `python sentrai_paths.py`
for this machine's map.

```powershell
python sentrai_config.py            # show the current settings (runs the wizard on a new machine)
python sentrai_config.py setup      # change them
```

The file holds the TypeSafe key and Telegram token in plain text, so keep it in your own
user folder. `run.ps1` / `run.sh` never delete logs.

### Set up with Cyanide (no Configuration page)

The dashboard's **Chat** page can do the same setup as a conversation. Until a machine has
been set up, the dashboard opens on Chat with a **Set up with Cyanide** offer (the **Setup**
button on Chat, or **Set up with Cyanide** on Configuration, starts it any time). Cyanide asks
what SentrAI guards and suggests a preset, then the logs folder, IPs and accounts never to
touch, your name, how to alert you (Telegram and/or email), the AI key, and the dashboard:
who may open it (this computer, or named IP addresses) and its port. Opening the dashboard to other
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
settings file keeps the choice (`SENTRAI_PRESET`) and every value; values that no longer match
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
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | core: never auto-blocked (blocklist or firewall); add your admin IP here before enabling `SENTRAI_FIREWALL` |
| `PROTECTED_USERS` | empty | core: more accounts never auto-locked; admin and service accounts (root, admin, administrator, www-data, nginx, postgres, ...) are always protected |
| `PROTECTED_NETS` | private ranges | core: networks Countersign never blocks on its own (an operator still can); `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7` by default, `off` for a lab whose attackers sit on a private network |
| `INFRA_ALLOWLIST` | empty | core: gateways, DNS, monitoring and other infrastructure never blocked (addresses or networks). This machine's DNS servers and default gateway are added automatically (`INFRA_AUTODETECT=0` turns that off) |
| `ADMIN_SESSIONS` | `on` | core: keep track of who is signed in on each machine and whose root work (`sudo`, `su`, Windows admin events) is whose: a known administrator's is recorded, never an incident; `off` judges every line on its own |
| `ADMIN_IPS` | empty | core: addresses or networks the administrators sign in from (`deploy/install.sh` puts the `--protect` and dashboard-allowed addresses here); "This was me" on an incident teaches more |
| `ADMIN_SSH_KEYS` | empty | core: their SSH key fingerprints, `SHA256:...` as `ssh-keygen -lf ~/.ssh/id_ed25519.pub` prints them |
| `ADMIN_ACCOUNTS` | empty | core: their accounts, `deploy` on every machine or `erick@web-01` on one |
| `ADMIN_SESSION_HOURS` / `ADMIN_SIGNIN_HOURS` | `12` / `12` | core: hours a sign-in counts as open after its last line; hours a dashboard sign-in as Owner or Admin vouches for its address |
| `ADMIN_LEARN` | `on` | core: a known key from a new address makes the address known, a new key from a known address makes the key known |
| `BUSY_SERVER` | `off` | core: `on` groups many addresses doing the same attack to one machine into one wave (one alert, a summary every `WAVE_UPDATE_MIN`, a capped share of the risk index); for game servers and big networks |
| `WAVE_MIN_ADDRESSES` / `WAVE_WINDOW_MIN` / `WAVE_UPDATE_MIN` / `WAVE_CATEGORIES` | `10` with `BUSY_SERVER=on`, else `0` (off) / `15` / `15` / `port_scan,brute_force` | core: how many addresses within how many minutes make a wave, minutes between its summaries, which kinds can make one |
| `TRUSTED_IPS` | empty | core: addresses or networks (a players' relay, a CDN, monitoring) whose lines are never analysed; a decoy touch is still reported |
| `CONTAIN_MIN_SEVERITY` / `CONTAIN_MIN_POINTS` | `high` / `20` | core: an incident is only contained without a person when its own severity and points reach these, whatever the overall risk index |
| `SENTRAI_FIREWALL` | `off` | core: also block IPs in the host firewall (`auto`, `nftables`, `iptables`, `netsh`); `off` keeps blocks on SentrAI's own blocklist only |
| `SENTRAI_FIREWALL_ENFORCE` | `0` | core: `0` is a dry run that only logs the firewall command; `1` really runs it (needs admin/root) |
| `SENTRAI_RISK_SCOPE` | `fleet` | core: `host` scores and blocks each machine on its own, for a central panel (set `SENTRAI_FIREWALL=off` with it) |
| `SENTRAI_PANEL_PORT` / `SENTRAI_PANEL_URL` | unset | core and dashboard: the agents' HTTPS port and the address they use (`install.sh --panel` sets both, with `SENTRAI_PANEL_CERT` / `SENTRAI_PANEL_KEY`) |
| `SENTRAI_AGENT_OFFLINE_HOLD_H` | `24` | agent: hours blocks stay in place while the panel cannot be reached |
| `SENTRAI_HW_ALERTS` | `on` | core: alert the on-duty person when a machine's hardware passes a limit (`off`: only show it) |
| `SENTRAI_HW_CPU_PCT` / `SENTRAI_HW_MEM_PCT` / `SENTRAI_HW_DISK_PCT` / `SENTRAI_HW_TEMP_C` | `90` / `90` / `90` / `85` | core: those limits; CPU, memory and heat must stay over for `SENTRAI_HW_FOR_MIN` (`5`) minutes |
| `AUTO_ACTIONS` | `block_ip,rate_limit,waf_rule` | core: action types SentrAI may take on its own; any other type waits for a person |
| `MAX_AUTO_ACTIONS_PER_HOUR` | `10` | core: automatic actions allowed in any rolling hour; past it a person decides |
| `MAX_TTL_HOURS` / `ACTION_TTL_HOURS` | `24` / unset | core: longest any temporary action lasts; per-type hours such as `lock_user=1,block_ip=4` |
| `CHECK_AFTER_MIN` / `SENTRAI_HEALTH_URL` | `10` / unset | core: minutes after an action to check it worked and did no harm; a page that must keep answering meanwhile |
| `UNDO_RETRY_S` / `UNDO_RETRIES` | `60` / `3` | core: how often and how many times a failed undo is retried before a person is asked |
| `SENTRAI_BACKUP_PATHS` | (none) | core: folders to back up, separated by `:` (Linux) or `;` (Windows), when the system profile's `backup.paths` names none. SentrAI's own data is always backed up |
| `SENTRAI_BACKUP_EVERY_HOURS` | `24` | core: hours between scheduled backups; `0` turns the schedule off (Back up now still works) |
| `SENTRAI_BACKUP_KEEP` | `7` | core: how many backups to keep; the oldest go first |
| `SENTRAI_BACKUP_DIR` | `backups` next to `SENTRAI_DB` | core: where backups are stored |
| `SENTRAI_BACKUP_COPY_TO` | (none) | core: a second folder (another drive or a network share) that gets a copy of each backup |
| `TYPESAFE_API_KEY` | unset | TypeSafe extension: enables Jev (TypeSafe System One); otherwise rules + fallback heuristic |
| `JEV_TIMEOUT_S` / `JEV_BUDGET_S` | 3 / 2 | core: per-call timeout and per-request time budget for Jev |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | unset | notifier: console mode when unset |
| `TELEGRAM_GROUP_COPY` | `fallback` | notifier: when the team group also gets an alert that went to people's own chats: `fallback` (only for people who have not linked a chat), `always`, `off` |
| `SMTP_HOST`, `ALERT_EMAIL_TO` | unset | notifier: email alerts off when either is unset |
| `SMTP_PORT` / `SMTP_SECURITY` | 587 / `starttls` | notifier: `starttls`, `ssl` (port 465) or `none` |
| `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_FROM` | unset | notifier: SMTP login and sender (sender defaults to the login) |
| `SENTRAI_EMAIL_MODE` | `backup` | notifier: `backup` emails only when Telegram fails; `always` emails every alert too |
| `SENTRAI_DASHBOARD_URL` | `http://127.0.0.1:8501` | notifier: link in email alerts |
| `SENTRAI_CORE_URL` | `http://127.0.0.1:8000` | lab, dashboard, notifier |
| `SENTRAI_NODE_NAME` | `This computer` | dashboard: this machine's name in the Machines list on Review |
| `SENTRAI_PEERS` | unset | dashboard: other SentrAI cores to show in the Machines list, as `Name=URL, Name=URL`; they must accept this console's API token |
| `SENTRAI_LAB_LOGS` | `logs` in the data root (`~\.sentrai\logs`) | lab: the collector tails JSON-lines logs here. A machine that saved its settings keeps the folder it saved |
| `SENTRAI_LOG_ACCESS`, `_AUTH`, `_DB`, `_OS` | `access.jsonl`, `auth.jsonl`, `db.jsonl`, `os.jsonl` | lab: log file names |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | 5 / 60 | core: failed logins that count as brute force |
| `EXPORT_ROWS_THRESHOLD` | 100 | core: rows in one export that count as exfiltration |
| `NEEDLE_MIN_CONFIDENCE` | 0.6 | core: AI confidence Countersign needs before approving an autonomous action |
| `SENTRAI_PRESET` | `moderate` | wizard and dashboard: `strict`, `moderate`, `balanced` or `advanced` |
| `SENTRAI_OPERATOR` | `operator` | notifier: name shown on approvals |
| `SENTRAI_HOME` | `~\.sentrai` (or the folder of `SENTRAI_CONFIG`) | all: the data root; every file SentrAI keeps is under it unless its own variable moves it (see [DATA.md](DATA.md)) |
| `SENTRAI_CONFIG` | `~\.sentrai\config.json` | all: where the setup wizard saves settings |
| `SENTRAI_API_TOKEN` | generated | all: the token the core API requires (`python sentrai_config.py token` prints it) |
| `SENTRAI_ACCOUNTS` | `accounts.json` next to the settings | dashboard: who may sign in (see Access below) |
| `SENTRAI_DASHBOARD_LOGIN` | on | dashboard: `off` opens it without signing in (local testing only) |
| `SENTRAI_REPORT_PAGE` | on | dashboard: `off` turns off the open staff report page (`/?report`) |
| `SENTRAI_REPORT_CODE` | unset | dashboard: a shared code staff must type on the report page (put it on the noticeboard) |
| `TELEGRAM_REPORT_FROM` | `alert-chat` | notifier: who may send `/report`: the alert chat only, `any` chat that messages the bot, or a comma list of chat ids |
| `SENTRAI_STAFF_REPORTS` | `people/staff_reports.json` next to the core database | core: where staff reports are saved |

### Access

The core API refuses every request without its token, except `/health` and `/blocklist` (so an
app or proxy can enforce blocks). The token is generated on first run, saved in the settings file,
and passed to the collector, dashboard and Telegram bot by `run.ps1` / `run.sh`. The report link in a Telegram alert is signed for that one report,
so it opens in a browser without the token. To call the API by hand:

```powershell
$t = python sentrai_config.py token
Invoke-RestMethod http://127.0.0.1:8000/incidents -Headers @{ Authorization = "Bearer $t" }
```

Everyone signs in to the dashboard with their own account: email, password, then a 6-digit
code from an authenticator app. On a new machine `run.sh` / `run.ps1` (or `python sentrai_config.py admin`)
prints a one-time **setup code**; the dashboard opens on "Create your Owner account", which takes
that code (it works once, for 24 hours). The Owner then scans a QR code with any authenticator app
and saves 8 recovery codes. There is no open sign-up: Owners and Admins invite people from the
**Team** page, which makes a link (valid 72 hours) for a given email and role.

| Role | Can |
| --- | --- |
| Owner | everything, including adding or removing Owners |
| Admin | approve, block, scan, change settings, invite and remove Admins and Auditors |
| Auditor | see every page and export reports; changes nothing |

Accounts live in `accounts.json` next to the settings file, readable by its owner only, with
salted PBKDF2 password hashes; the setup, invite and recovery codes are kept only as hashes. After
five wrong passwords or codes from one address, that address waits five minutes. Each sign-in
shows the time and address of the one before, so you notice someone else using your account.

```bash
python sentrai_config.py admin                                   # who may sign in; a setup code on a new machine
python sentrai_config.py admin --reset                           # the first Owner: new password, authenticator again
python sentrai_config.py admin --reset --email you@example.com   # the same for another account
```

A forgotten password or lost phone is also reset by another Owner or Admin on the Team page. For a
recording where you do not want to sign in on camera, start SentrAI with `SENTRAI_DASHBOARD_LOGIN=off`
(`$env:SENTRAI_DASHBOARD_LOGIN = "off"` in PowerShell). A machine set up before accounts existed
keeps its sign-in: that email and password become the Owner, who adds an authenticator at the
next sign-in.

### Telegram setup (optional)

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token.
2. Send any message to your new bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Enter both in `python sentrai_config.py setup`, or before `run.ps1`: `$env:TELEGRAM_BOT_TOKEN = "<token>"; $env:TELEGRAM_CHAT_ID = "<chat id>"`.

Only the configured chat, and people's linked private chats, can press the buttons.

4. Optional, so each person gets their own alerts instead of the group: on the dashboard's Incidents page, press
   **Make link code** for a person; they send `/link CODE` to the bot in a private chat. See
   "Alerts in each person's own Telegram chat" in `core/README.md`.

### Staff reports

Anyone at the business can report something suspicious (a strange email, a pop-up, a login they
did not make, a stranger at the computers) without a dashboard account:

- **Web, signed in:** the web dashboard's *Report something suspicious* page (`/report`), for people with a dashboard account.
- **Web, no account:** the classic dashboard address plus `/?report`, for example `https://server:8501/?report`. No
  sign-in, and the page shows nothing from SentrAI. Set `SENTRAI_REPORT_CODE` to ask for a shared code.
  Staff must be able to reach the dashboard (on a server, add their network to `--protect`).
- **Telegram:** `/report I got an email asking for my password`. Only the alert chat by default; set
  `TELEGRAM_REPORT_FROM=any` so staff can message the bot directly.
- **Anything else** that holds the API token can `POST /staff-reports` (`CONTRACT.md`).

Each report is sorted at once (the AI model when one is set up, keyword rules otherwise): what kind
of problem it sounds like, how urgent, what the reporter should do now, and what technical staff
should check first. It opens a "Staff report" incident marked *needs review*, which alerts like any
other and is never acted on automatically. On the **Staff reports** page technical staff pick a
report up (that acknowledges the incident), add notes, and close it as *resolved* or *not a threat*
with a note; closing the last report on an incident closes the incident. Every step is in the audit
trail. One sender may send 5 reports every 10 minutes.

### Email alerts (optional backup)

Email carries the same alert content as Telegram, including SLA reminders and escalations,
and links to the dashboard for the buttons. Set the SMTP server and recipients in
`python sentrai_config.py setup` (section 4) or on the dashboard's Configuration page.
With `SENTRAI_EMAIL_MODE=backup` an alert is emailed only when Telegram cannot deliver it;
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

- Containment only changes SentrAI's own blocklist unless `SENTRAI_FIREWALL` is on. Your own machine (127.0.0.1) and `PROTECTED_IPS` are never blocked.
- Admin and service accounts are never auto-locked, and private networks are never auto-blocked (`PROTECTED_NETS`).
- Root work by a known administrator (a sign-in with a known SSH key, from a known address, or by a known account at the console) is recorded as admin activity, never an incident. Root work from a sign-in SentrAI does not recognise opens one "Root access from an unrecognised sign-in" incident per address, never contained on its own: a person answers **This was me** (SentrAI learns the sign-in and closes it) or **Not me** (the address is blocked). What it learns stays in `core/people/admins.json` on the server (`ADMIN_*` above, `core/README.md`).

## Known limits

- Incidents, blocks and notifications are saved in SQLite next to the audit chain and restored when the core restarts. Blocks keep their original TTL; any that expired while the core was down are rolled back and audited on start.
- Only IP blocks and account locks have a real effect. Rate limit, WAF rule, kill process and revoke ACL are recorded as simulated.
- Jev has not been called against the live TypeSafe API yet (no API key); without a key the fallback heuristic classifies what the rules cannot.
- Telegram mode has not been tested with a real bot.
