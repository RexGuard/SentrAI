# CactAI MVP

A working prototype of CactAI that runs natively on one Windows laptop (no Docker).

| Component | Folder | What it does | URL |
| --- | --- | --- | --- |
| Core | `core/` | FastAPI risk engine, rules + Jev classifier, agents (Saguaro, Root, Reservoir, Areole, Needle, Watchdog, Scribe, HelpDesk), TTL hotpatches, hash-chained audit log, negligence reports | http://127.0.0.1:8000 |
| Target app | `lab/target_app/` | Fictional "Aegis Academy Student Portal" that writes logs and enforces CactAI's blocklist (HTTP 403) | http://127.0.0.1:5000 |
| Collector | `lab/collector/` | Tails the portal's web, DB and OS logs and sends normalized events to core | |
| Attacks / replay | `lab/attacks/`, `lab/replay/` | Localhost-only attack scripts and a scripted replay for backup recordings | |
| Dashboard | `dashboard/` | Streamlit risk console: gauge, risk over time, incident queue, Approve / Reject / Rollback / Make Permanent, audit feed, report viewer | http://127.0.0.1:8501 |
| Notifier | `notifier/` | Telegram bot with Approve / Reject buttons, or console mode without a token | |

The interface between components is defined in [`CONTRACT.md`](CONTRACT.md).

## Run the demo

Requirements: Windows 10/11, Python 3.12 on PATH. Each component gets its own `.venv`, created automatically on first run.

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

### What you should see

1. Benign traffic: no incidents, gauge green.
2. Brute force from `203.0.113.45`: incident `RSK-2026-081`, risk about 39 (amber), operator alert (Telegram or the notifier window).
3. Nobody acknowledges: +5 per demo hour, SLA reminders, escalation to the team lead at red.
4. SQL injection from `198.51.100.23`: risk crosses 80, Needle approves, both attackers are blocked and `admin` is locked for 2 demo hours. The portal returns "Blocked by CactAI" (403) to them. Your own machine (127.0.0.1) is never blocked.
5. The negligence report (dashboard, or `http://127.0.0.1:8000/reports/RSK-2026-081.md`) shows the timeline of inaction, "Ack: none" and the audit chain hash.
6. Roll back or make the fix permanent from the dashboard.

### Demo speed

`DEMO_SPEED` sets how many demo hours pass per real hour. The default 60 means 1 real minute = 1 demo hour, so the penalty takes about 6 minutes to max out. `-DemoSpeed 600` (1 real minute = 10 demo hours) fits a video; note that the 2-hour hotpatch TTL then lasts only 12 real seconds.

## Configuration

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

### Telegram setup (optional)

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token.
2. Send any message to your new bot, then open `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy `chat.id`.
3. Before `run_demo.ps1`: `$env:TELEGRAM_BOT_TOKEN = "<token>"; $env:TELEGRAM_CHAT_ID = "<chat id>"`.

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
| Lab | `.venv\Scripts\python -m pytest -q` | 31 passed |
| Dashboard | `.venv\Scripts\python -m pytest -q` | 12 passed |
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
