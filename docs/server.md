---
title: Install on a server
nav: docs
description: Install SentrAI as systemd services on a Linux server, open the dashboard to your own IP, update and uninstall.
---

# Install on a server

On a Linux server, SentrAI runs as four systemd services that start at boot and keep a real-time
clock. The installer sets up a service account, its settings, HTTPS for the dashboard, and a
firewall rule so only the computers you name can open it.

The examples use `203.0.113.10` as **your own computer's public IP** (the one you manage the
server from). Put your real one in its place. If you do not know it, search "what is my IP" from
that computer.

## Before you start

- A Linux server with systemd, and an account that can use `sudo`.
- Python 3.10 or newer with `venv` (`sudo apt install python3-venv git` on Debian and Ubuntu).
- `nft` or `iptables`, if the dashboard should be reachable from your computer. Without either,
  keep it [on the server only](#keep-the-dashboard-on-the-server).

## Install

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI/mvp
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com
```

`--protect` does three things: SentrAI will never block that address, the dashboard opens to it,
and root work (`sudo`) from it on this server counts as your own, recorded rather than raised as an
incident (`ADMIN_IPS`, see [Your own administrators](settings.html#your-own-administrators)). Add
it once for every address you manage the server from. Never skip your own address: it is what keeps
SentrAI from locking you out.

From a terminal, the installer then asks a few questions. Press **Enter** to keep the answer in
brackets:

```text
  Dashboard port [8501]:
  Allowed IPs [203.0.113.10]:
  Owner email:
  Owner password, at least 12 characters:
```

The Owner questions come only on a new machine. The password is asked twice. Press Enter at
*Owner email* to skip them: the installer then prints a one-time setup code, and you create the
Owner in the browser instead. The **Allowed IPs** go into `ADMIN_IPS` too, like `--protect`. When
it finishes, it prints the dashboard address, either the Owner's email or the setup code, and the
addresses whose `sudo` counts as your own.

## Open the dashboard to your computer

From the allowed computer, open:

```text
https://<your server's address>:8501
```

The dashboard uses a certificate the installer made itself, so the browser warns once. Accept it,
then create the Owner with the setup code, or sign in with the Owner email and password from the
install, and add an authenticator app. See [Signing in](sign-in.html) for inviting your team.

Only the addresses in **Allowed IPs** can reach the port. When your own IP changes, run the
installer again with the new one; `--dashboard-allow` replaces the list (the new address is added
to `ADMIN_IPS`; an old one stays there until you remove it from `/etc/sentrai/sentrai.env` and
restart `sentrai.target`):

```bash
sudo ./deploy/install.sh --dashboard-allow 203.0.113.25
```

### Keep the dashboard on the server

For the tightest setup, or when the server has no `nft` or `iptables`, keep the dashboard off the
network and reach it through an SSH tunnel:

```bash
sudo ./deploy/install.sh --dashboard-local
```

Then, from your own computer:

```bash
ssh -L 8501:127.0.0.1:8501 you@your-server
```

and open `http://127.0.0.1:8501` while that SSH session is open.

## Tell SentrAI which logs to watch

After the install, SentrAI is running but not yet reading your server's logs. On the dashboard,
open **Collector** and press **Scan running programs**: it lists the log files of the programs on
the server and lets you choose which to watch. The collector picks up an approved file within a
few seconds.

SentrAI can read nginx, SSH, Suricata, MySQL or MariaDB, PostgreSQL and MongoDB logs, and on
Windows the Windows Event Log. [Log sources](log-sources.html) lists what it catches in each one
and the setting some of them need.

With an AI key set (see [Settings](settings.html#ai-key)), SentrAI can also search for logs from a
plain request:

```bash
sudo sentrai-scout find --root /var/log "where are the login and web server logs?"
```

Its suggestions appear under **Collector**, then **Scout proposals**, where you press **Watch** or
**Dismiss**.

## Installer options

| Option | What it does |
| --- | --- |
| `--protect IP` | never block this IP, open the dashboard to it, and know root work from it as yours. Repeat for more addresses |
| `--dashboard-allow IP` | open the dashboard to this IP or network only. Repeat for more; replaces the list |
| `--dashboard-local` | keep the dashboard on the server, for an SSH tunnel only |
| `--admin-email EMAIL` | the dashboard Owner's email, on a first install |
| `--reset-password` | make a new password for that account and print it at the end |
| `--dashboard-port N` / `--core-port N` | when 8501 or 8000 is already taken |
| `--no-questions` (or `-y`) | never ask; use the options given and the defaults. Scripts get this anyway |
| `--no-notifier` | leave Telegram and email alerts off |
| `--no-start` | install and enable the services without starting them |
| `--seal-journal` | sign the system journal so old entries cannot be rewritten unnoticed. Prints a key once: keep it off the server |
| `--remote-copy URL` | send every record to a second machine that keeps a copy root on this server cannot change. See the [server README](https://github.com/RexGuard/SentrAI/blob/main/mvp/deploy/README.md#off-box-copy---remote-copy) |
| `--panel [PORT]` / `--panel-url URL` | make this server a [central panel](panel.html) that agents on other machines join (port 8443 by default); `--panel off` closes it |
| `--prefix DIR` / `--user NAME` | install somewhere other than `/opt/sentrai`, or run as another account |

A setup with no questions, for a script:

```bash
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com --no-questions
```

## Where things go

| What | Where |
| --- | --- |
| Program | `/opt/sentrai/mvp` |
| Service settings (ports, addresses, protected IPs) | `/etc/sentrai/sentrai.env` |
| Dashboard certificate | `/etc/sentrai/tls/` |
| Saved settings, watched logs, the audit record, one folder per part (`core/`, `collector/`, `scout/`, `notifier/`) | `/var/lib/sentrai/` |
| A list of every file SentrAI keeps there | `/var/lib/sentrai/INDEX.md` |
| Services | `sentrai-core`, `sentrai-collector`, `sentrai-dashboard`, `sentrai-notifier`, grouped as `sentrai.target` |

The services run as the `sentrai` account, each locked down to what its job needs. After editing
`sentrai.env` by hand, restart them with `sudo systemctl restart sentrai.target`.

## Everyday commands

```bash
systemctl status 'sentrai-*'                # are they running?
journalctl -u sentrai-core -f               # follow one service's output
sudo systemctl restart sentrai.target       # restart all four
sudo sentrai-admin                          # who may sign in; a setup code on a new machine
sudo sentrai-admin --reset                  # the first Owner: new password, printed once
sudo sentrai-update                         # newest version, same settings (see Update)
```

## Update

One command, from anywhere on the server:

```bash
sudo sentrai-update
```

It fetches the newest SentrAI from GitHub, installs it over the old one and restarts the
services. Everything you set at install time stays: ports, allowed IPs, `--dashboard-local`,
`--panel` and its address, the notifier choice, the sign-in and every record. It never asks
questions and never makes a new setup code. Python packages are reinstalled only when they
changed.

Before it changes anything it saves the running version (code, packages, `/etc/sentrai`, the
service files and the data, but not collected logs) to `/var/backups/sentrai/`. Afterwards it
checks the core answers, the dashboard and the agents' port answer, and that no service keeps
restarting. If any check fails, it puts the saved version back and starts that again, so a bad
update leaves you where you were. Every run is logged to `/var/log/sentrai-update.log`.

| Command | What it does |
| --- | --- |
| `sudo sentrai-update` | update to the newest `main` |
| `sudo sentrai-update --check` | only say whether a newer version is out |
| `sudo sentrai-update --ref v1.2` | follow a tag or another branch (remembered for next time) |
| `sudo sentrai-update --rollback` | go back to the version before the last update |
| `sudo sentrai-update --force` | reinstall the same version (repairs a damaged install) |
| `sudo sentrai-update --from ~/SentrAI` | install from a checkout on the server, without fetching |

An agent installed on the same server is updated with the panel. Agents on other machines are
updated on each machine with the same command (see [One panel, many machines](panel.html#update-the-agents)).

**Update available.** Once a day the server checks GitHub for a newer version (it only checks,
it never installs on its own). When one is out, the dashboard's sidebar shows **Update
available** with the command to run. The sidebar's foot shows the version running now.

**Servers installed before the updater.** `sentrai-update` arrives with the first install or
update after it was added. Do that one the old way, once:

```bash
cd SentrAI && git pull
sudo ./mvp/deploy/update.sh
```

From then on `sudo sentrai-update` is enough. Running `sudo ./deploy/install.sh` again still
works too: it is how you change options (only the options you pass change).

### Upgrading a server set up before the SentrAI name

Servers installed before October 2026 used the old name CactAI in their folders and services
(`/etc/cactai`, `/var/lib/cactai`, `cactai-core`, the `cactai` account). `sentrai-update` is not
there yet on such a server: pull the new code and run the install command again. It
moves all of it to the SentrAI names the first time it runs: settings, records, sign-in, the
API token, the machine key of an agent on the same server and any blocks already in the firewall
come along. An agent installed on the same server is upgraded with it. Settings written with the
old `CACTAI_` names still work, and SentrAI prints a reminder to rename them to `SENTRAI_`.

## Uninstall

```bash
sudo ./deploy/uninstall.sh            # removes the services, keeps settings and records
sudo ./deploy/uninstall.sh --purge    # also removes /etc/sentrai and /var/lib/sentrai
```

Both remove the dashboard's firewall rule. A sealed journal stays sealed.

## What a server install does not do yet

SentrAI's detection rules were first tuned on a demo app's logs, so on real logs they may catch
less at first. Blocks go on SentrAI's own blocklist by default. Blocking in the
server's own firewall is built but off: once turned on it starts as a dry run that only logs the
command it would run. Turn it on step by step in [Settings](settings.html#firewall-blocking),
after your own IP is protected.

## Next

To watch more machines from this server's dashboard, make it a
[central panel](panel.html) and add them with the agent.
