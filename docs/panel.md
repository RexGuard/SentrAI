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
- scores each machine on its own (`CACTAI_RISK_SCOPE=host`), so an attack on one machine never
  blocks traffic on another.
- prints the address agents will use and the certificate's **pin** (`sha256:...`). You don't need
  to copy it: the dashboard shows it with every join code.

If the server's own name is not what other machines use to reach it, give the address yourself:

```bash
sudo ./deploy/install.sh --panel 8443 --panel-url https://panel.example.com:8443
```

When the panel only watches other machines, keep its own firewall out of it: add
`CACTAI_FIREWALL=off` to `/etc/cactai/cactai.env` and run `sudo systemctl restart cactai.target`.

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
finds them, and starts the `cactai-agent` service. Within a minute the machine shows on
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
it for a while (`journalctl -u cactai-agent -f` on Linux, the log file above on Windows). When the
commands look right, let it really change the firewall:

```bash
sudo ./mvp/deploy/install-agent.sh --enforce --protect 203.0.113.10
```

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Enforce -Protect 203.0.113.10
```

The panel's own address is never blocked on an added machine. Add `--protect` (`-Protect`) for
every address you manage that machine from, just as on the panel. On Linux, a rerun with
`--protect` or `--enforce` rewrites the machine's settings, so give both together whenever you
change either. `-DryRun` turns enforcement off again on Windows.

### Agent installer options

| Linux | Windows | What it does |
| --- | --- | --- |
| `--panel URL` | `-Panel URL` | the panel's HTTPS address (needed the first time) |
| `--code CODE` | `-Code CODE` | the one-time join code (needed the first time) |
| `--pin sha256:...` | `-Pin sha256:...` | the panel's certificate pin, shown with the join code |
| `--name NAME` | `-Name NAME` | the machine's name on the panel (default: its host name) |
| `--enforce` | `-Enforce` / `-DryRun` | really change the firewall, or go back to only logging |
| `--protect IP` | `-Protect IP,IP` | never block these addresses on this machine |
| `--ca FILE` | `-Ca FILE` | the panel's certificate file, instead of a pin |
| `--allow-http` | `-AllowHttp` | accept a plain `http://` panel. Only on a private test network |
| `--no-start` | `-NoStart` | install the service without starting it |
| `--prefix DIR` / `--user NAME` | `-Prefix DIR` | install somewhere else, or run as another account |

On Linux the settings are in `/etc/cactai/agent.env` and the machine's key in
`/var/lib/cactai/agent/`. After editing `agent.env` by hand, run
`sudo systemctl restart cactai-agent`. On Windows, rerun the installer with the option you want to
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
| See one machine's incidents | **Machines**, then **Look at one machine** |
| Scan a machine for threats, or back it up | **Machines**, pick it, press **Scan for threats** or **Back up now** |
| Remove a machine from the panel | **Machines**, **Joined machines**: pick it, tick **Yes, stop accepting its key**, press **Revoke** |
| Remove the agent from a Linux machine | `sudo systemctl disable --now cactai-agent && sudo rm /etc/systemd/system/cactai-agent.service` |
| Remove the agent from a Windows machine | `powershell -ExecutionPolicy Bypass -File .\mvp\deploy\uninstall-agent.ps1` (add `-Purge` to delete its key too) |

A revoked machine stops at once: its key no longer works. To bring it back, make a new join code
and run the installer again with it.

**Scans and backups** run on the machine itself, on folders set there and never by the panel. List
them in that machine's `/etc/cactai/agent.env` and restart the agent:

```bash
CACTAI_THREAT_PATHS=/var/www:/srv/minecraft/plugins
CACTAI_BACKUP_PATHS=/srv/app/data
```

The agent picks a job up within about 15 seconds. Serious scan findings open an incident on that
machine, and backups stay on the machine.

## When the panel cannot be reached

- Blocks already in place stay for 24 hours (`CACTAI_AGENT_OFFLINE_HOLD_H`) and are then removed,
  so a lost panel never leaves a block in force forever.
- Logs wait on the machine and reach the panel when it is back.
- After 30 seconds the agent's own rules take over and block clear attacks (password guessing, SQL
  injection, port scans and the like) for an hour at a time, at most 10 new blocks an hour. Private
  and protected addresses are never blocked. `CACTAI_AGENT_LOCAL_RULES=off` turns this off.
- When the panel answers again, it gets a report of every block made alone. **Machines** shows it
  under **Last time offline**.

## Renewing the panel's certificate

The panel's certificate lasts five years. If you replace it, every machine needs the new pin. On
each machine, `python -m agent pin` shows the kept pin and the panel's current one, and
`python -m agent pin sha256:...` sets the new one. Then restart the agent.

A panel behind a publicly trusted certificate, for example nginx with Let's Encrypt, can leave the
pin out.

## Not tested yet

The Windows agent installer is tested on a real Windows machine for every change, including a real
Windows Firewall block. `install-agent.sh` has not yet been run on a real systemd machine, and the
Linux agent has not yet changed a real firewall with `--enforce`. Try it on a test machine first,
keep the dry run on for a while, and make sure your own IP is protected before you turn
enforcement on.
