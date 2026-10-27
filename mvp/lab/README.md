# SentrAI Lab (collector · Scout)

The log side of SentrAI: the collector that turns logs into events for the core, and Scout,
which finds the security logs on a new system. Runs natively on Windows or Linux, no Docker.

Talks to the core (`http://127.0.0.1:8000`) over the shared contract in `../CONTRACT.md`.

## Layout

```
lab/
  requirements.txt        requests, psutil, pytest (+ optional AI packages for Scout)
  collector/collector.py  tails logs/*.jsonl + approved server logs -> POST core /events
  collector/parsers.py    nginx, syslog (sshd), journald, Windows Event Log, Suricata, MySQL, PostgreSQL, MongoDB parsers
  collector/paths.py      where the JSON-lines logs live (SENTRAI_LAB_LOGS, SENTRAI_LOG_*)
  scout/                  finds log files on a new system and learns from expert trails
  tests/                  pytest suite
```

The JSON-lines logs (access/auth/db/os/deception) from the app being guarded go in `logs/` in
SentrAI's data root (`~/.sentrai/logs`; `SENTRAI_LAB_LOGS` moves it), not here. What the collector
and Scout keep is in the data root too ([`../DATA.md`](../DATA.md)).

## Setup (once)

```powershell
cd mvp\lab
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

All commands below use the venv python. Run them **from `mvp\lab`**.

## Run the collector

`run.ps1` / `run.sh` in `mvp` start it with the rest of SentrAI. On its own:

```powershell
.\.venv\Scripts\python.exe -m collector.collector   # tails logs, batches events to core every 1s, heartbeat every 10s
```

Point it at a different core with `--core` / the `SENTRAI_CORE_URL` env var (default
`http://127.0.0.1:8000`).

## Scout: find the security logs on a new system

On a real network nobody hands you a list of log files. Scout finds them for a novice technician, and it learns from how experienced people find them.

Scout's `trails/`, `sources.json` and `pending.json` live in the `scout/` folder of SentrAI's data root: `~/.sentrai/scout/` on a laptop, `/var/lib/sentrai/scout/` on a server.

1. **An expert shows the way once** (optional). They browse with simple read-only commands (`ls`, `cd`, `peek`, `find`), then `pick` the files that matter and say why. Each step is saved as a trail in `scout/trails/`.
   `python -m scout record --root C:\ "find the IIS web logs"`
2. **A novice asks in plain words.** The AI model reads the trails and browses the same way, explaining each step. It asks the technician when only a person can know, then proposes log files.
   `python -m scout find --root C:\ "where are the login logs on this server?"`
3. **The technician confirms each file.** Confirmed files go into `scout/sources.json`, and the collector starts watching them within a few seconds. Every yes or no is saved as a new trail, so the next search starts smarter.

Each proposal is saved to `scout/pending.json` the moment Scout makes it, so stopping Scout part way keeps what it found. With no terminal attached (a service, cron, `ssh` without `-t`) or with `--no-input`, Scout never waits for keyboard answers: it decides on its own and leaves its proposals pending. Approve or dismiss them on the dashboard's Collector page ("Scout proposals"), or with `python -m scout pending`, `python -m scout approve <id>` and `python -m scout reject <id> --why "..."`.

Scout can only read files under the `--root` folders, never write. It masks `password=`, `token=` and similar values before the AI sees a line, and treats log text as data, never as instructions. Two example trails (a Linux web server and Windows IIS) ship in this code folder's `scout/trails/` and are copied into a new trails folder. `python -m scout list` shows what the collector will watch. Scout needs one AI key: Anthropic, OpenAI, DeepSeek or another OpenAI-compatible service (`python sentrai_config.py setup`, section 5). `SCOUT_MODEL` overrides the model.

## Real server logs (nginx, SSH, Windows, Suricata, databases)

On a Linux server, approve its own logs once, then run the collector as a user that can read
them (root, or a member of the `adm` group on Debian/Ubuntu):

```bash
python -m collector.collector --add-system-logs   # nginx + auth.log/secure/journald + Suricata + database logs;
                                                  # on Windows: Security, System, Application, Defender
python -m collector.collector
```

- nginx and sshd lines become events with the log's own time, the real host name and a `parsed`
  object (method, path, status, user agent; or ssh_event, user, port). Fields: `mvp/CONTRACT.md`,
  "Parsed fields".
- Read positions are saved in `~/.sentrai/collector/state.json` (`SENTRAI_COLLECTOR_STATE`) after core
  accepts each batch, so a restart resumes where it stopped. A rotated file's last lines are read
  from `<name>.1` first. The first time a file is seen, only its last 256 KB are read
  (`SENTRAI_COLLECTOR_BACKFILL_KB`).
- Lines with no time zone (auth.log, nginx error.log) use this computer's zone, or `SENTRAI_LOG_TZ`
  (`Asia/Singapore`, `+08:00`, `UTC`). `SENTRAI_HOST` overrides the host name.
- Windows: `winevent:<channel>` entries are read through the built-in Windows Event Log API every 5 s and resume
  from the last record number. Suricata keeps only `alert` records. Database logs get the client
  address of an earlier line of the same connection. What each source catches, and the settings
  some of them need: `docs/log-sources.md`.
- Sample lines for tests are in `tests/samples/` (synthetic, documentation IP ranges only).

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Covers: collector normalization to a valid contract Event, tailer creation/rotation handling,
real nginx/sshd/journald, Windows Event Log, Suricata and database log parsing, the line chain and log-integrity checks, the setup wizard and
Scout. Tests write to a temp dir and hit no network.
