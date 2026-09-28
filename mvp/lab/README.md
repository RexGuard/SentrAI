# CactAI Lab (target app · collector · attacks · replay)

The **lab** half of the CactAI MVP: a fictional victim web app, a log
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
  collector/collector.py  tails logs/*.jsonl -> POST core /events
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
- All member data is synthetic (`Member 0001`…, `@example.com`).
- Attack scripts refuse any host other than `127.0.0.1` / `localhost` / `::1`.
- If core is unreachable the target app **fails open** (allows traffic).
```
