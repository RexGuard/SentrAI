# SentrAI Lab (target app · collector · attacks · replay)

The **lab** half of the SentrAI MVP: a fictional victim web app, a log
collector that feeds the core, scripted attacks for the demo, and a replay
fallback. Everything runs natively on Windows, on localhost, no Docker.

Owner: lab agent. Writes only inside `mvp/lab/`. Talks to the core
(`http://127.0.0.1:8000`) over the shared contract in `../CONTRACT.md`.

## Layout

```
lab/
  requirements.txt        flask, requests, psutil, pytest
  fake_core.py            tiny stand-in for the real core (dev/demo only)
  scenario.py             full live demo story (benign -> brute -> pause -> sqli)
  target_app/             Flask "Aegis Academy Student Portal" on :5000
    app.py  db.py  logger.py  blocklist.py  paths.py  templates/
  collector/collector.py  tails logs/*.jsonl + approved server logs -> POST core /events
  collector/parsers.py    nginx access/error, syslog (sshd), journald line parsers
  attacks/                brute_force, sqli, exfil, shell, benign (+ _common)
  replay/simulate.py      REPLAY MODE: post a scripted incident to core
  logs/                   JSON-lines logs written at runtime (access/auth/db/os)
  seed/admin_password.txt fake admin password
  tests/                  pytest suite
```

## Setup (once)

```powershell
cd mvp\lab
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

All commands below use the venv python. Run them **from `mvp\lab`**.

## Run the demo stack

Open separate terminals (order: core, target, collector).

```powershell
# 1. Core — the real one (core agent). For a self-contained lab, use the stand-in:
.\.venv\Scripts\python.exe fake_core.py                 # http://127.0.0.1:8000

# 2. Target app (student portal, polls core /blocklist every 2s, fail-open)
.\.venv\Scripts\python.exe -m target_app                # http://127.0.0.1:5000

# 3. Collector (tails logs, batches events to core every 1s, heartbeat every 10s)
.\.venv\Scripts\python.exe -m collector.collector
```

Point components at a different core with `--core` / the `CACTAI_CORE_URL`
env var (default `http://127.0.0.1:8000`).

## Attacks (localhost-only; remote hosts are hard-refused)

```powershell
.\.venv\Scripts\python.exe -m attacks.benign       --count 8  --delay 0.5
.\.venv\Scripts\python.exe -m attacks.brute_force  --count 12 --delay 0.3
.\.venv\Scripts\python.exe -m attacks.sqli         --count 6  --delay 0.4
.\.venv\Scripts\python.exe -m attacks.exfil        --count 4  --delay 0.6
.\.venv\Scripts\python.exe -m attacks.shell        --count 3  --delay 0.5
```

Every script takes `--count`, `--delay`, `--host`, `--port`, `--src-ip`.
The demo "attacker" IP is sent in the `X-Demo-Src-IP` header (brute
`203.0.113.45`, sqli `198.51.100.23`, shell `198.51.100.77`, exfil
`203.0.113.77`, benign `192.0.2.10`).

## Full scripted story (live)

```powershell
.\.venv\Scripts\python.exe scenario.py            # benign -> brute -> pause -> sqli
```

## Tripwires: honeypot, honeytokens, tarpit (off by default)

Design doc section 11. Everything stays inside the portal; nothing is ever sent to the
attacker. Turn on with `run_demo.ps1 -Tripwires` / `run_demo.sh --tripwires` (or set
`CACTAI_SPINES=1` before `python -m target_app`). The older `-Spines` / `--spines` flags still work.

| Tripwire | What it is | Touch becomes |
| --- | --- | --- |
| Honeypot page | `/admin-legacy`, listed only in `robots.txt` as Disallow | `port_scan` (reconnaissance) |
| Honeypot login | posting to that page; never signs anyone in | `brute_force` (IP only, no real account is locked) |
| Honeytoken credential | `svc_backup` planted in an HTML comment on the decoy page, used on the real `/login` | `brute_force` |
| Honeytoken rows | `STF-0007` and `STF-0012` in `members`; staff searches never match them, `/export` does | `data_exfiltration` |
| Tarpit | decoy pages, and every request from an IP after its first touch, wait `CACTAI_TARPIT_S` seconds (default 3, max 30) | slows the attack |

Each touch is written to `logs/deception.jsonl` (source `tripwire`) and the core
rules classify it with confidence 1.0.

```powershell
.\.venv\Scripts\python.exe -m attacks.spines        # intruder walks into every tripwire (prints each wait)
.\.venv\Scripts\python.exe scenario.py --tripwires  # the full story plus a phase 5 for the tripwires
```

In the full scenario the risk is already high by phase 5, so the first decoy touch gets
203.0.113.99 blocked within seconds and the later steps are refused with 403. Run
`attacks.spines` on its own (fresh start) to show every tripwire.

## Replay fallback (if the live attack is flaky on camera)

```powershell
.\.venv\Scripts\python.exe -m replay.simulate                 # post scripted incident to core
.\.venv\Scripts\python.exe -m replay.simulate --dump          # just print the events
```

Prints a `REPLAY MODE` banner — say on camera that it is a replay.

## Scout: find the security logs on a new system

On a real network nobody hands you a list of log files. Scout finds them for a novice technician, and it learns from how experienced people find them.

1. **An expert shows the way once** (optional). They browse with simple read-only commands (`ls`, `cd`, `peek`, `find`), then `pick` the files that matter and say why. Each step is saved as a trail in `scout/trails/`.
   `python -m scout record --root C:\ "find the IIS web logs"`
2. **A novice asks in plain words.** The AI model reads the trails and browses the same way, explaining each step. It asks the technician when only a person can know, then proposes log files.
   `python -m scout find --root C:\ "where are the login logs on this server?"`
3. **The technician confirms each file.** Confirmed files go into `scout/sources.json`, and the collector starts watching them within a few seconds. Every yes or no is saved as a new trail, so the next search starts smarter.

Each proposal is saved to `scout/pending.json` the moment Scout makes it, so stopping Scout part way keeps what it found. With no terminal attached (a service, cron, `ssh` without `-t`) or with `--no-input`, Scout never waits for keyboard answers: it decides on its own and leaves its proposals pending. Approve or dismiss them on the dashboard's Collector page ("Scout proposals"), or with `python -m scout pending`, `python -m scout approve <id>` and `python -m scout reject <id> --why "..."`.

Scout can only read files under the `--root` folders, never write. It masks `password=`, `token=` and similar values before the AI sees a line, and treats log text as data, never as instructions. Two example trails (a Linux web server and Windows IIS) ship in `scout/trails/`. `python -m scout list` shows what the collector will watch. Scout needs one AI key: Anthropic, OpenAI, DeepSeek or another OpenAI-compatible service (`python cactai_config.py setup`, section 5). `SCOUT_MODEL` overrides the model.

## Real server logs (nginx, SSH)

On a Linux server, approve its own logs once, then run the collector as a user that can read
them (root, or a member of the `adm` group on Debian/Ubuntu):

```bash
python -m collector.collector --add-system-logs   # nginx access/error + auth.log, secure or journald
python -m collector.collector
```

- nginx and sshd lines become events with the log's own time, the real host name and a `parsed`
  object (method, path, status, user agent; or ssh_event, user, port). Fields: `mvp/CONTRACT.md`,
  "Parsed fields".
- Read positions are saved in `~/.cactai/collector-state.json` (`CACTAI_COLLECTOR_STATE`) after core
  accepts each batch, so a restart resumes where it stopped. A rotated file's last lines are read
  from `<name>.1` first. The first time a file is seen, only its last 256 KB are read
  (`CACTAI_COLLECTOR_BACKFILL_KB`).
- Lines with no time zone (auth.log, nginx error.log) use this computer's zone, or `CACTAI_LOG_TZ`
  (`Asia/Singapore`, `+08:00`, `UTC`). `CACTAI_HOST` overrides the host name.
- Sample lines for tests are in `tests/samples/` (synthetic, documentation IP ranges only).

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Covers: login flow, blocklist (containment) 403 enforcement, collector
normalization to a valid contract Event, tailer creation/rotation handling,
and that every attack script refuses non-localhost targets. Tests write to a
temp dir and hit no network.

## Safety notes

- `/admin/run?cmd=` **never executes** anything — it only logs a simulated
  `web server spawned shell: <cmd>` OS-layer event.
- All member data is synthetic (`Member 0001`…, `@example.com`); the bait rows
  use `@aegis-academy.example` and are removed again when tripwires are off.
- Attack scripts refuse any host other than `127.0.0.1` / `localhost` / `::1`.
- If core is unreachable the target app **fails open** (allows traffic).
```
