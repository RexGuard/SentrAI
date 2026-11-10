---
title: Install the agent
nav: docs
description: Install the SentrAI agent ("wings") on a Linux or Windows machine and join it to your panel.
---

# Install the agent

The **agent** (we also call it *wings*) is the small part of SentrAI that runs on each machine your
panel watches. It sends that machine's logs to the panel and puts the panel's blocks for it into
the machine's own firewall. It only makes outgoing HTTPS calls, so no port is opened on the machine.

It has its own installer, separate from the panel's: `install-agent.sh` on Linux and
`install-agent.ps1` on Windows. It installs only the agent, with only the Python packages it needs
(`requests`, `psutil`, `tzdata`: about 20 MB, not the panel's 110 MB of dashboard, AI and test
packages). Nothing of the panel (dashboard, notifier, sign-in) is installed on the machine.

You need two things from the panel first:

1. A panel, installed as in [Install the panel](server.html).
2. A join code: on the panel's dashboard, **Machines** > **Add machine** > **Make join code**. It
   comes with the exact command to paste, for Linux and for Windows, including the panel's pin.


## On Linux

Linux with systemd, Python 3.10 or newer with `venv`, and `sudo`. Get the code and paste the
command from the dashboard:

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI
sudo ./mvp/deploy/install-agent.sh --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:... --name web-01
```

The installer joins the panel, approves the machine's nginx, SSH, Suricata and database logs if it
finds them, and starts the `sentrai-agent` service. Within a minute the machine shows on
**Machines** with the services running on it.

## On Windows

Windows 10, 11 or Server 2016 and newer, with Python 3.10 or newer from
[python.org](https://www.python.org/downloads/) installed **for all users** (the Microsoft Store
Python cannot run as a service). Get the code, open PowerShell **as Administrator** in the
`SentrAI` folder and paste the Windows command from the dashboard:

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Panel https://panel.example.com:8443 -Code ABCD-EFGH-JKLM -Pin sha256:... -Name pc-01
```

It installs the **SentrAI agent** Windows service, which starts with Windows and restarts itself
after a crash. Check it with `Get-Service SentrAIAgent`. Its output is in
`C:\ProgramData\SentrAI\agent\service\SentrAIAgent.out.log`.

## Antivirus on the machine

Between the scans you ask for, the agent watches the scan folders (`SENTRAI_THREAT_PATHS` in
`/etc/sentrai/agent.env`), important files such as SSH login keys and cron jobs, and the running
programs, every 30 seconds, and tells the panel about malware, disguised programs or signs of
ransomware. It also checks every file against the panel's shared list of known-bad fingerprints, and
uses ClamAV when that is installed. See [The agent's antivirus](antivirus.html).

## Blocks start as a dry run

On a new machine the agent only **logs** the firewall command it would run for each block. Watch
it for a while (`journalctl -u sentrai-agent -f` on Linux, the log file above on Windows). When the
commands look right, let it really change the firewall:

```bash
sudo ./mvp/deploy/install-agent.sh --enforce --protect 203.0.113.10
```

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Enforce -Protect 203.0.113.10
```

The panel's own address is never blocked on an added machine. Add `--protect` (`-Protect`) for
every address you manage that machine from, just as on the panel. A rerun keeps what earlier
runs set: `--protect` adds to the addresses already kept, and enforcing stays on until you pass
`--dry-run` (`-DryRun` on Windows) to go back to only logging.

You can also switch it from the panel, without the installer: open the machine and press **Turn
real blocking on**, or run `sudo sentrai machines blocking HOST on` (`off` goes back to a dry run and
lifts the blocks the agent had put in place). The Machines page says *Not blocking yet* for every
machine still on a dry run. A later `--enforce` or `--dry-run` from the installer wins over the panel.

## Installer options

| Linux | Windows | What it does |
| --- | --- | --- |
| `--panel URL` | `-Panel URL` | the panel's HTTPS address (needed the first time) |
| `--code CODE` | `-Code CODE` | the one-time join code (needed the first time) |
| `--pin sha256:...` | `-Pin sha256:...` | the panel's certificate pin, shown with the join code |
| `--name NAME` | `-Name NAME` | the machine's name on the panel (default: its host name) |
| `--enforce` / `--dry-run` | `-Enforce` / `-DryRun` | really change the firewall, or go back to only logging |
| `--protect IP` | `-Protect IP,IP` | never block these addresses on this machine |
| `--ca FILE` | `-Ca FILE` | the panel's certificate file, instead of a pin |
| `--allow-http` | `-AllowHttp` | accept a plain `http://` panel. Only on a private test network |
| `--no-start` | `-NoStart` | install the service without starting it |
| `--prefix DIR` / `--user NAME` | `-Prefix DIR` | install somewhere else, or run as another account |

On Linux the settings are in `/etc/sentrai/agent.env` and the machine's key in
`/var/lib/sentrai/agent/`, where `INDEX.md` lists every file the agent keeps
(`C:\ProgramData\SentrAI\agent\INDEX.md` on Windows). After editing `agent.env` by hand, run
`sudo systemctl restart sentrai-agent`. On Windows, rerun the installer with the option you want to
change; the others are kept.

## On a laptop, without a service

For a quick test, the agent can run from a checkout while a terminal is open. From `mvp/lab`, with
its Python environment from a first `run.sh` / `run.ps1`:

```bash
.venv/bin/python -m agent join --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:...
.venv/bin/python -m agent run
```

On Windows use `.\.venv\Scripts\python.exe` in place of `.venv/bin/python`.

## Where things go

| | Linux | Windows |
| --- | --- | --- |
| Code and Python packages | `/opt/sentrai/mvp/lab` and `/opt/sentrai/mvp/core/app` | `C:\Program Files\SentrAI` |
| Settings | `/etc/sentrai/agent.env` | `C:\Program Files\SentrAI\SentrAIAgent.xml` (rerun the installer to change) |
| Machine key and state | `/var/lib/sentrai/agent/` | `C:\ProgramData\SentrAI\agent\` |
| Service | `sentrai-agent` (systemd) | `SentrAIAgent` |

An agent installed before this version has the panel's larger set of packages. Its next update
(or a rerun of the installer) makes its Python environment again with only the agent's packages,
once. With a panel on the same machine, the two share that environment and nothing is removed.

To use Scout's AI help on an agent (`python -m scout find`), add the package yourself:
`sudo /opt/sentrai/mvp/lab/.venv/bin/pip install anthropic` (or `openai`).

## Update the agent

On each Linux machine, one command updates the agent to the newest code. It stays joined and
keeps `--enforce`/dry run, `--protect` and its approved logs:

```bash
sudo sentrai-update
```

On Windows, from an Administrator PowerShell:

```powershell
& "C:\Program Files\SentrAI\update-agent.ps1"
```

Both save the running version first, check the agent runs and keeps running, and put the saved
version back when it does not. `--check` (`-Check`) only says whether a newer version is out,
and `--rollback` (`-Rollback`) goes back to the version before the last update. Update the panel
first (also `sudo sentrai-update`, on the panel): a newer agent may need a newer panel.

Agents installed before the updater was added get it with one last update the old way:
`git pull`, then `sudo ./mvp/deploy/update.sh` (Linux) or the install command again without
`--code` (Windows).

## Uninstall

```bash
sudo ./mvp/deploy/uninstall-agent.sh            # keeps the machine key
sudo ./mvp/deploy/uninstall-agent.sh --purge    # also deletes it
```

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\uninstall-agent.ps1 -Purge
```

A panel on the same machine is left alone. To take the machine off the panel as well, revoke its key
on the panel (**Machines**, the machine's **Agent** tab).
