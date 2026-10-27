# Where SentrAI keeps its data

Every part of SentrAI keeps what it writes in one folder, the **data root**, with one folder per
part inside it. The code folder (`mvp/`) holds no data, so updating the code never touches your
records. [`sentrai_paths.py`](sentrai_paths.py) decides where each file goes, and every part asks it.

| Machine | Data root |
| --- | --- |
| A laptop (Linux, macOS) | `~/.sentrai` |
| A laptop (Windows) | `%USERPROFILE%\.sentrai` |
| A server (`deploy/install.sh`) | `/var/lib/sentrai` |
| A Linux machine with only the agent (`deploy/install-agent.sh`) | `/var/lib/sentrai/agent` |
| A Windows machine with only the agent (`deploy/install-agent.ps1`) | `C:\ProgramData\SentrAI\agent` |

The root is `SENTRAI_HOME` when it is set, else the folder of `SENTRAI_CONFIG` (every installer
puts the settings file at the root), else `~/.sentrai`. `INDEX.md` in the root lists every file on
that machine, with its full path.

## The tree

```text
<root>/             INDEX.md, config.json, accounts.json
  core/             sentrai.db, anchor.key, archive/, protection.json, summary.json, extensions.json, remote-copy.token
    people/         routing.json, telegram_links.json, staff_reports.json
    machines/       fleet.json, jobs.json
    threats/        threat_seen.json, quarantine/
    backups/        backup archives
    restores/       restored copies
  collector/        state.json
  scout/            sources.json, pending.json, trails/
  notifier/         last_witness.txt
  agent/            agent.json, backups/
  logs/             the logs the collector tails (lab-logs/ on a server)
```

A machine only has the folders of the parts that run on it. On a machine with only the agent, the
installer pins each file with a variable, so its files sit directly in the root.

## Each file

Paths are inside the root. The core service writes everything under `core/`; **Owner** is the agent
or part the file belongs to. **Set with** is the variable that puts it somewhere else.

| File | Owner | What it holds | Set with |
| --- | --- | --- | --- |
| `INDEX.md` | `sentrai_paths.py` | this map, for this machine | |
| `config.json` | every part | settings, read by every part when it starts | `SENTRAI_CONFIG` |
| `accounts.json` | Dashboard | who may sign in, with password hashes and authenticator secrets | `SENTRAI_ACCOUNTS` |
| `logs/` | Collector | JSON-lines logs the collector tails (an input, not SentrAI's own data). Older versions used `mvp/lab/logs`; a machine that saved its settings keeps the folder it saved | `SENTRAI_LAB_LOGS` |
| `core/sentrai.db` (+ `-wal`, `-shm`) | Scribe | the hash-chained audit record and the working state (incidents, actions) | `SENTRAI_DB` |
| `core/anchor.key` | Scribe | signs the audit fingerprints sent to the alert channels | |
| `core/archive/` | Scribe | audit chains set aside by a reset (never deleted) | |
| `core/protection.json` | Warden | the monitor-only switch, as an operator last set it | |
| `core/summary.json` | Scribe | when the client summary goes out (Reports page) | |
| `core/extensions.json` | Extensions | extensions added or removed on the dashboard (Extensions page) | |
| `core/remote-copy.token` | Scribe | the witness's append token (`install.sh --remote-copy`) | `SENTRAI_REMOTE_COPY_TOKEN_FILE` |
| `core/people/routing.json` | Warden | who gets what: contacts, routing rules, escalation | `SENTRAI_ROUTING` |
| `core/people/telegram_links.json` | Notifier | contacts linked to their Telegram chats | `SENTRAI_TELEGRAM_LINKS` |
| `core/people/staff_reports.json` | HelpDesk | what staff reported (`/report`, the report page) | `SENTRAI_STAFF_REPORTS` |
| `core/machines/fleet.json` | Fleet | machines that joined the panel: hashed keys and join codes | |
| `core/machines/jobs.json` | Fleet | scans and backups queued for those machines | |
| `core/threats/threat_seen.json` | ThreatWatch | findings already raised, so each one alerts once | `SENTRAI_THREAT_STATE` |
| `core/threats/quarantine/` | ThreatWatch | files moved out of reach, with what they were (restorable) | `SENTRAI_QUARANTINE` |
| `core/backups/` | BackupWatch | backup archives and their manifests | `SENTRAI_BACKUP_DIR` |
| `core/restores/` | BackupWatch | folders a backup was restored into | |
| `collector/state.json` | Collector | where each log was read up to, and the line chain | `SENTRAI_COLLECTOR_STATE` |
| `scout/sources.json` | Scout | log files a person approved; the collector tails them | `SENTRAI_SCOUT_SOURCES` |
| `scout/pending.json` | Scout | Scout's proposals waiting for a person | `SENTRAI_SCOUT_PENDING` |
| `scout/trails/` | Scout | expert trails recorded here; a new folder starts with the two examples in `lab/scout/trails/` | `SENTRAI_SCOUT_TRAILS` |
| `notifier/last_witness.txt` | Notifier | the last audit fingerprint delivered to the alert chat | `NOTIFIER_WITNESS_FILE` |
| `agent/agent.json` | Agent | machine key, panel address and pin, blocks in force, local rules | `SENTRAI_AGENT_FILE` |
| `agent/backups/` | Agent | backups the panel asked this machine to make | `SENTRAI_BACKUP_DIR` |

## Rules

- **A variable that is set always wins.** A server keeps every path `install.sh` pinned in
  `/etc/sentrai/sentrai.env`, and an agent the ones in `agent.env` or `SentrAIAgent.xml`.
- **Files that belong together stay together.** The core's files sit next to the database wherever
  `SENTRAI_DB` points, `pending.json` and `trails/` next to `sources.json`, `accounts.json` next to
  the settings file, and the agent's backups next to `agent.json`.
- **Old files move on first use.** A file an older version kept elsewhere (the checkout's
  `mvp/core/data`, `mvp/lab/scout` or `mvp/notifier/data`, or loose in `~/.sentrai`) is moved when
  SentrAI first starts, or when its part first looks for it: renamed, never copied, and only when
  nothing is at the new place yet. Each move is printed once, in the console that started SentrAI
  (`run.sh`, `run.ps1` or the installer) or in the part's own output.
- **A failed move keeps the old place.** When a file is held open or sits on another drive, it stays
  in use where it is if SentrAI can still write there, and one warning names it. Move it by hand
  while SentrAI is stopped, or set `SENTRAI_HOME` on that drive.
- **Nothing is deleted or overwritten.** A file already at both places stays at both; the new one
  is used, and one warning names the older copy so you can remove it or put it back by hand.

## Commands

Run these from `mvp/` with `python` or any part's Python (for example `lab/.venv/bin/python`, or
`lab\.venv\Scripts\python.exe` on Windows); the script needs only the standard library.

```bash
python sentrai_paths.py           # the map for this machine: each file, where it is, who writes it
python sentrai_paths.py index     # move files from older places, then write INDEX.md into the root
python sentrai_paths.py migrate   # only move files from older places
python sentrai_paths.py json      # the map as JSON
```

`run.sh`, `run.ps1` and the installers run `index` for you. On a server, simply read
`/var/lib/sentrai/INDEX.md` (`sudo less /var/lib/sentrai/INDEX.md`).

## Not data

- Service settings: `/etc/sentrai/sentrai.env`, `agent.env` and the dashboard certificate in
  `/etc/sentrai/tls/` on a server; the `<env>` lines in `SentrAIAgent.xml` on a Windows agent.
- The witness's copy of the audit record, on its own machine in `/var/lib/sentrai-witness`.
- The process ids and output of `run.sh` and `run.ps1`, in `mvp/.run_pids.json` and `mvp/.run_logs/`.

## Moving it

- **Everything:** stop SentrAI, move the root folder, then set `SENTRAI_HOME` to its new place in
  the environment (on Windows `setx SENTRAI_HOME D:\SentrAI`, then open a new PowerShell). It cannot
  go in `config.json`, which lives inside the root, and SentrAI does not move an old root by itself.
- **One file or folder:** set its variable from the table. The files that sit next to it follow it.
- **On a server** the paths are pinned in `sentrai.env` and in the service sandboxes below, so mount
  a bigger disk at `/var/lib/sentrai` rather than move it.

## On a server

Each service may write only its own folders (`ReadWritePaths=` in the `sentrai-*.service` files),
so a new file must go in the folder of the part that writes it. `core/`, `collector/` and
`notifier/` are open to the `sentrai` account only (mode 0700).

| Service | Writes | Cannot open |
| --- | --- | --- |
| `sentrai-core` | `core/`, and `scout/` (it approves log files) | `collector/` |
| `sentrai-collector` | `collector/` | `core/` |
| `sentrai-notifier` | `notifier/` | `core/`, `collector/` |
| `sentrai-dashboard` | the settings and sign-in files in the root | `core/`, `collector/` |
| `sentrai-agent` | `agent/` (`/var/lib/sentrai/agent`) | |
