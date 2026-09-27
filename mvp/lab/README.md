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
