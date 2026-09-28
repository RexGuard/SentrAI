# CactAI MVP

A working prototype of CactAI that runs natively on one Windows laptop or Linux machine (no Docker).

| Component | Folder | What it does | URL |
| --- | --- | --- | --- |
| Core | `core/` | FastAPI risk engine, rules + Jev classifier, agents (Saguaro, Root, Reservoir, Areole, Needle, Watchdog, Scribe, HelpDesk), TTL hotpatches, hash-chained audit log, negligence reports | http://127.0.0.1:8000 |
| Target app | `lab/target_app/` | Fictional "Aegis Academy Student Portal" that writes logs and enforces CactAI's blocklist (HTTP 403) | http://127.0.0.1:5000 |
| Collector | `lab/collector/` | Tails the portal's web, DB and OS logs and sends normalized events to core | |
| Attacks / replay | `lab/attacks/`, `lab/replay/` | Localhost-only attack scripts and a scripted replay for backup recordings | |
| Dashboard | `dashboard/` | Streamlit console with a sidebar menu: Configuration (home), Approvals, Collector, Classifier, Action taker, Review (gauge, threshold, risk accumulated), Reports, Audit trail. Menu bubbles flag new malicious activity per part | http://127.0.0.1:8501 |
| Notifier | `notifier/` | Telegram bot with Approve / Reject buttons, or console mode without a token | |

The interface between components is defined in [`CONTRACT.md`](CONTRACT.md).

## Run the demo

Requirements (Windows): Windows 10/11, Python 3.12 on PATH. Each component gets its own `.venv`, created automatically on first run.

```powershell
cd mvp
powershell -ExecutionPolicy Bypass -File .\run_demo.ps1 -DemoSpeed 600
```

Then, in another terminal:

```powershell
cd mvp\lab
.\.venv\Scripts\python.exe scenario.py            # full narrated story
```

Or step by step:

```powershell
.\.venv\Scripts\python.exe -m attacks.benign
.\.venv\Scripts\python.exe -m attacks.brute_force --count 8 --delay 0.3
# wait ~40 s at DemoSpeed 600 while the inaction penalty climbs
.\.venv\Scripts\python.exe -m attacks.sqli --count 3
```

Stop everything with `.\stop_demo.ps1`.

### On Linux (or macOS)

Requirements: Python 3.11+ with the `venv` module (Debian/Ubuntu: `sudo apt install python3-venv`).
`run_demo.sh` does the same as `run_demo.ps1`, but runs each component in the background and
writes its output to `mvp/.demo_logs/<name>.log` instead of opening a window.

```bash
cd mvp
./run_demo.sh --demo-speed 600          # also: --mode replay, --no-dashboard, --no-browser
cd lab && .venv/bin/python scenario.py  # in another terminal
tail -f ../.demo_logs/core.log          # to watch a component
cd .. && ./stop_demo.sh
```

The attack commands above work the same with `.venv/bin/python` in place of `.\.venv\Scripts\python.exe`.

If port 8000 or 8501 is taken, pick others: `./run_demo.sh --core-port 8100 --dashboard-port 8601`
(`.\run_demo.ps1 -CorePort 8100 -DashboardPort 8601` on Windows, or set `CACTAI_CORE_PORT` /
`CACTAI_DASHBOARD_PORT`). The portal stays on 5000, the only port the attack scripts accept.

### On a server (systemd services)

To keep CactAI running on a Linux server, install it as services instead of running the demo:
`sudo ./deploy/install.sh --protect <your admin IP>`. See [deploy/README.md](deploy/README.md).

### What you should see

The dashboard opens on Configuration. Open **Review** for the gauge; the Collector, Classifier and Action taker buttons show a red bubble when new malicious activity reaches that part.

1. Benign traffic: no incidents, gauge green.
2. Brute force from `203.0.113.45`: incident `RSK-2026-081`, risk about 39 (amber), operator alert (Telegram or the notifier window).
3. Nobody acknowledges: +5 per demo hour, SLA reminders, escalation to the team lead at red.
4. SQL injection from `198.51.100.23`: risk crosses 80, Needle approves, both attackers are blocked and `admin` is locked for 2 demo hours. The portal returns "Blocked by CactAI" (403) to them. Your own machine (127.0.0.1) is never blocked.
5. The report (dashboard **Reports** page, or `http://127.0.0.1:8000/reports/RSK-2026-081.md`) shows the timeline of inaction, "Ack: none" and the audit chain hash.
6. Roll back or make the fix permanent from the dashboard **Approvals** page.

### Demo speed

`DEMO_SPEED` sets how many demo hours pass per real hour. The default 60 means 1 real minute = 1 demo hour, so the penalty takes about 6 minutes to max out. `-DemoSpeed 600` (1 real minute = 10 demo hours) fits a video; note that the 2-hour hotpatch TTL then lasts only 12 real seconds.

## Configuration

### First-run setup

On a new machine, `run_demo.ps1` (and the collector when started on its own) first runs a
short setup wizard. It starts with a **security preset** (Strict, Moderate or Balanced), which
sets the detection and response values, or **Advanced** to set each of them yourself. Then one section per part: **collector** (logs directory and log file names),
**classifier** (brute-force and bulk-export thresholds, TypeSafe key), **responder** (risk
threshold, block expiry, SLA, IPs and accounts never to touch) and **notifications**
(Telegram). Press Enter at every question to keep the demo defaults.

The answers are saved to `%USERPROFILE%\.cactai\config.json` (or the path in `CACTAI_CONFIG`)
and every component reads that file on start. A variable set in the environment still wins.

```powershell
python cactai_config.py            # show the current settings (runs the wizard on a new machine)
python cactai_config.py setup      # change them
```

The file holds the TypeSafe key and Telegram token in plain text, so keep it in your own
user folder. `run_demo.ps1` only clears old `.jsonl` logs when the logs directory is inside
`mvp\lab`, so pointing it at real logs never deletes them.

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
| `PROTECTED_IPS` | `127.0.0.1,::1,localhost` | core: never auto-blocked |
| `PROTECTED_USERS` | empty | core: never auto-locked |
| `TYPESAFE_API_KEY` | unset | core: enables Jev (TypeSafe System One); otherwise rules + fallback heuristic |
| `JEV_TIMEOUT_S` / `JEV_BUDGET_S` | 3 / 2 | core: per-call timeout and per-request time budget for Jev |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | unset | notifier: console mode when unset |
| `CACTAI_CORE_URL` | `http://127.0.0.1:8000` | lab, dashboard, notifier |
| `CACTAI_LAB_LOGS` | `mvp\lab\logs` | lab: portal writes and collector tails logs here |
| `CACTAI_LOG_ACCESS`, `_AUTH`, `_DB`, `_OS` | `access.jsonl`, `auth.jsonl`, `db.jsonl`, `os.jsonl` | lab: log file names |
| `BRUTE_FORCE_COUNT` / `BRUTE_FORCE_WINDOW_S` | 5 / 60 | core: failed logins that count as brute force |
| `EXPORT_ROWS_THRESHOLD` | 100 | core: rows in one export that count as exfiltration |
| `NEEDLE_MIN_CONFIDENCE` | 0.6 | core: AI confidence Needle needs before approving an autonomous action |
| `CACTAI_PRESET` | `moderate` | wizard and dashboard: `strict`, `moderate`, `balanced` or `advanced` |
| `CACTAI_OPERATOR` | `operator` | notifier: name shown on approvals |
| `CACTAI_CONFIG` | `~\.cactai\config.json` | all: where the setup wizard saves settings |

### Telegram setup (optional)

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token.
2. Send any message to your new bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Enter both in `python cactai_config.py setup`, or before `run_demo.ps1`: `$env:TELEGRAM_BOT_TOKEN = "<token>"; $env:TELEGRAM_CHAT_ID = "<chat id>"`.

Only the configured chat can press the buttons.

## The three parts

CactAI is a pipeline of three pluggable parts. Each part is one small base class with
one job; to add a new one, subclass it and add it to the list shown.

| Part | Base class | Implement | Built-in versions | Register in |
| --- | --- | --- | --- | --- |
| 1. Collector | `Source` in `lab/collector/collector.py` | `poll()` returns new events (build them with `make_event`) | `JsonLogSource`, `HeartbeatSource` | `default_sources()` |
| 2. Classifier | `Classifier` in `core/app/classifier.py` | `classify(event, now)` returns a `Classification`, or `None` to pass | `RulesClassifier` → `JevClassifier` → `FallbackClassifier` | `default_chain()` |
| 3. Responder | `Responder` in `core/app/responders.py` | `apply(action)` returns True when in force; `revert(action)` undoes it | `BlocklistResponder` (block_ip, lock_user), `SimulatedResponder` (the rest) | `Saguaro.__init__` |

Events travel from part 1 to part 2 over `POST /events` as plain dicts (`CONTRACT.md`).
Between parts 2 and 3 sit the risk engine and Needle: an action only reaches a responder
after an operator approves it, or after Needle approves it above the risk threshold. The
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

| Suite | Command (from the component folder) | Result |
| --- | --- | --- |
| Core | `.venv\Scripts\python -m pytest -q` | 27 passed |
| Lab | `.venv\Scripts\python -m pytest -q` | 36 passed |
| Dashboard | `.venv\Scripts\python -m pytest -q` | 25 passed |
| Notifier | `.venv\Scripts\python -m pytest -q` | 8 passed |
| End-to-end (real core + portal + collector + attacks) | from `integration`: `..\lab\.venv\Scripts\python -m pytest -q test_e2e.py` | 1 passed |

## Safety

- Attack scripts refuse any host other than localhost and any port other than 5000.
- `/admin/run` never executes anything; it only logs a simulated "shell spawned" event.
- Containment only changes CactAI's own blocklist, which the portal enforces. No firewall, OS or network settings are touched.
- All member data is synthetic.

## Known limits

- Incidents and notifications are kept in memory; only the audit chain persists across restarts.
- Only IP blocks and account locks have a real effect. Rate limit, WAF rule, kill process and revoke ACL are recorded as simulated.
- Jev has not been called against the live TypeSafe API yet (no API key); without a key the fallback heuristic classifies what the rules cannot.
- Telegram mode has not been tested with a real bot.
