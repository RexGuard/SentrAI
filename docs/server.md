---
title: Install on a server
nav: docs
description: Install SentrAI as systemd services on a Linux server, open the dashboard to your own IP, upgrade and uninstall.
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

`--protect` does two things: SentrAI will never block that address, and the dashboard opens to
it. Add it once for every address you manage the server from. Never skip your own address: it is
what keeps SentrAI from locking you out.

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
Owner in the browser instead. When it finishes, it prints the dashboard address and either the
Owner's email or the setup code.

## Open the dashboard to your computer

From the allowed computer, open:

```text
https://<your server's address>:8501
```

The dashboard uses a certificate the installer made itself, so the browser warns once. Accept it,
then create the Owner with the setup code, or sign in with the Owner email and password from the
install, and add an authenticator app. See [Signing in](sign-in.html) for inviting your team.

Only the addresses in **Allowed IPs** can reach the port. When your own IP changes, run the
installer again with the new one; `--dashboard-allow` replaces the list:

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
sudo cactai-scout find --root /var/log "where are the login and web server logs?"
```

Its suggestions appear under **Collector**, then **Scout proposals**, where you press **Watch** or
**Dismiss**.

## Installer options

| Option | What it does |
| --- | --- |
| `--protect IP` | never block this IP, and open the dashboard to it. Repeat for more addresses |
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
| `--prefix DIR` / `--user NAME` | install somewhere other than `/opt/cactai`, or run as another account |

A setup with no questions, for a script:

```bash
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com --no-questions
```

## Where things go

| What | Where |
| --- | --- |
| Program | `/opt/cactai/mvp` |
| Service settings (ports, addresses, protected IPs) | `/etc/cactai/cactai.env` |
| Dashboard certificate | `/etc/cactai/tls/` |
| Saved settings, watched logs, the audit record | `/var/lib/cactai/` |
| Services | `cactai-core`, `cactai-collector`, `cactai-dashboard`, `cactai-notifier`, grouped as `cactai.target` |

The services run as the `cactai` account, each locked down to what its job needs. After editing
`cactai.env` by hand, restart them with `sudo systemctl restart cactai.target`.

## Everyday commands

```bash
systemctl status 'cactai-*'                # are they running?
journalctl -u cactai-core -f               # follow one service's output
sudo systemctl restart cactai.target       # restart all four
sudo cactai-admin                          # who may sign in; a setup code on a new machine
sudo cactai-admin --reset                  # the first Owner: new password, printed once
```

## Upgrade

Pull the new code and run the same install command again:

```bash
cd SentrAI && git pull && cd mvp
sudo ./deploy/install.sh
```

Your settings, sign-in and records are kept. Only the options you pass change, and Python
packages are reinstalled only when they changed.

## Uninstall

```bash
sudo ./deploy/uninstall.sh            # removes the services, keeps settings and records
sudo ./deploy/uninstall.sh --purge    # also removes /etc/cactai and /var/lib/cactai
```

Both remove the dashboard's firewall rule. A sealed journal stays sealed.

## What a server install does not do yet

SentrAI's detection rules were first tuned on a demo app's logs, so on real logs they may catch
less at first. Blocks go on SentrAI's own blocklist by default. Blocking in the
server's own firewall is built but off: once turned on it starts as a dry run that only logs the
command it would run. Turn it on step by step in [Settings](settings.html#firewall-blocking),
after your own IP is protected.
