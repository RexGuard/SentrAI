---
title: One panel, many machines
nav: docs
description: Turn one SentrAI server into a central panel and add Linux and Windows machines to it with the agent.
---

# One panel, many machines

One SentrAI server can watch other machines too. That server becomes the **panel**: it scores
every machine on its own, decides on blocks and shows them all on its dashboard. Each other
machine runs only the small **agent**, which sends that machine's logs to the panel and puts the
panel's blocks for it into its own firewall.

The agent only makes outgoing HTTPS calls to the panel, so no port is opened on the machines you
add. Each machine gets its own key, so removing one never touches the others.

| | Panel | Each added machine |
| --- | --- | --- |
| Runs | the full SentrAI install (core, collector, dashboard, notifier) | the agent only |
| Installed with | `deploy/install.sh --panel` | `deploy/install-agent.sh` (Linux) or `deploy/install-agent.ps1` (Windows) |
| Needs open | port 8443 for the agents, plus the dashboard for you | nothing, outgoing HTTPS only |

The examples use `panel.example.com` for the panel's name and `203.0.113.10` for your own
computer's IP. Put your real ones in their place.

## 1. Install the panel

Install SentrAI on the server that will be the panel as in [Install on a server](server.html), and
add `--panel`:

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI/mvp
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com --panel
```

Already installed? Run `sudo ./deploy/install.sh --panel` on its own; your settings are kept.

`--panel` does three things:

- opens a second port, **8443**, for agents only. It uses HTTPS with a certificate the installer
  makes, and answers only what a machine key may do. Your API token and the dashboard never face
  the network through it.
- scores each machine on its own (`SENTRAI_RISK_SCOPE=host`), so an attack on one machine never
  blocks traffic on another.
- prints the address agents will use and the certificate's **pin** (`sha256:...`). You don't need
  to copy it: the dashboard shows it with every join code.

If the server's own name is not what other machines use to reach it, give the address yourself:

```bash
sudo ./deploy/install.sh --panel 8443 --panel-url https://panel.example.com:8443
```

When the panel only watches other machines, keep its own firewall out of it: add
`SENTRAI_FIREWALL=off` to `/etc/sentrai/sentrai.env` and run `sudo systemctl restart sentrai.target`.

The installer opens 8443 in `ufw` or `firewalld` when either is running. If your cloud provider has
its own firewall, allow 8443 there too, ideally only from the machines you add.
`sudo ./deploy/install.sh --panel off` closes the port again.

## 2. Make a join code

On the panel's dashboard, open **Machines**. In **Add machine**:

1. Type a name for the machine, like `web-01`, or leave it empty to use its own host name.
2. Check that **Panel address** is the `https://...:8443` address from step 1.
3. Press **Make join code**.

You get a one-time join code, valid for 24 hours, and the exact command to paste on the new
machine, for Linux and for Windows. The command carries the panel's pin, so the machine talks to
your panel and refuses anything pretending to be it.

## 3. Install the agent

### On Linux

Linux with systemd, Python 3.10 or newer with `venv`, and `sudo`. Get the code and paste the
command from the dashboard:

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI
sudo ./mvp/deploy/install-agent.sh --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:... --name web-01
```

The installer joins the panel, approves the machine's nginx, SSH, Suricata and database logs if it
finds them, and starts the `sentrai-agent` service. Within a minute the machine shows on
**Machines** with the services running on it.

### On Windows

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

### Blocks start as a dry run

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

### Agent installer options

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

### On a laptop, without a service

For a quick test, the agent can run from a checkout while a terminal is open. From `mvp/lab`, with
its Python environment from a first `run.sh` / `run.ps1`:

```bash
.venv/bin/python -m agent join --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:...
.venv/bin/python -m agent run
```

On Windows use `.\.venv\Scripts\python.exe` in place of `.venv/bin/python`.

## Look after your machines

| To | Do |
| --- | --- |
| See every machine, its risk and its services | dashboard, **Machines** |
| Open one machine's own page | **Machines**, click the machine. Its address (`?machine=<name>`) can be shared or bookmarked |
| See one machine's incidents, blocks or services | on its page, the **Incidents**, **Blocks** or **Services** tab |
| Scan a machine for threats, or back it up | on its page, press **Scan for threats** or **Back up now** |
| Remove a machine from the panel | on its page, **Agent** tab: tick **Yes, stop accepting its key**, press **Revoke key** |
| Remove the agent from a Linux machine | `sudo systemctl disable --now sentrai-agent && sudo rm /etc/systemd/system/sentrai-agent.service` |
| Remove the agent from a Windows machine | `powershell -ExecutionPolicy Bypass -File .\mvp\deploy\uninstall-agent.ps1` (add `-Purge` to delete its key too) |

A revoked machine stops at once: its key no longer works. To bring it back, make a new join code
and run the installer again with it.

**Scans and backups** run on the machine itself, on folders set there and never by the panel. List
them in that machine's `/etc/sentrai/agent.env` and restart the agent:

```bash
SENTRAI_THREAT_PATHS=/var/www:/srv/minecraft/plugins
SENTRAI_BACKUP_PATHS=/srv/app/data
```

The agent picks a job up within about 15 seconds. Serious scan findings open an incident on that
machine, and backups stay on the machine.

## Update the agents

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

## When the panel cannot be reached

- Blocks already in place stay for 24 hours (`SENTRAI_AGENT_OFFLINE_HOLD_H`) and are then removed,
  so a lost panel never leaves a block in force forever.
- Logs wait on the machine and reach the panel when it is back.
- After 30 seconds the agent's own rules take over and block clear attacks (password guessing, SQL
  injection, port scans and the like) for an hour at a time, at most 10 new blocks an hour. Private
  and protected addresses are never blocked. `SENTRAI_AGENT_LOCAL_RULES=off` turns this off.
- When the panel answers again, it gets a report of every block made alone. **Machines** shows it
  under **Last time offline**.

## Renewing the panel's certificate

The panel's certificate lasts five years. If you replace it, every machine needs the new pin. The
dashboard shows the new pin with every join code. On each machine, from the `SentrAI` folder:

```bash
sudo ./mvp/deploy/install-agent.sh --pin sha256:...
```

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Pin sha256:...
```

The installer keeps every other setting and restarts the agent.

A panel behind a publicly trusted certificate, for example nginx with Let's Encrypt, can leave the
pin out.

## Not tested yet

The Windows agent installer is tested on a real Windows machine for every change, including a real
Windows Firewall block. `install-agent.sh` has not yet been run on a real systemd machine, and the
Linux agent has not yet changed a real firewall with `--enforce`. Try it on a test machine first,
keep the dry run on for a while, and make sure your own IP is protected before you turn
enforcement on.
