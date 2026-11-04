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
| Installed with | `deploy/install-panel.sh` ([Install the panel](server.html)) | `deploy/install-agent.sh` (Linux) or `deploy/install-agent.ps1` (Windows) ([Install the agent](agent.html)) |
| Python packages | about 110 MB (dashboard, AI, tests) | about 20 MB (`lab/requirements-agent.txt`) |
| Needs open | port 8443 for the agents, plus the dashboard for you | nothing, outgoing HTTPS only |

The examples use `panel.example.com` for the panel's name and `203.0.113.10` for your own
computer's IP. Put your real ones in their place.

## 1. Install the panel

Install the panel on the server as in [Install the panel](server.html):

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI/mvp
sudo ./deploy/install-panel.sh --protect 203.0.113.10 --admin-email you@example.com
```

A first install opens the agents' port by itself. A panel installed before without it gets it with
`sudo ./deploy/install-panel.sh --panel`; your other settings are kept.

The agents' port (`--panel`) does three things:

- opens a second port, **8443**, for agents only. It uses HTTPS with a certificate the installer
  makes, and answers only what a machine key may do. Your API token and the dashboard never face
  the network through it.
- scores each machine on its own (`SENTRAI_RISK_SCOPE=host`), so an attack on one machine never
  blocks traffic on another.
- prints the address agents will use and the certificate's **pin** (`sha256:...`). You don't need
  to copy it: the dashboard shows it with every join code.

If the server's own name is not what other machines use to reach it, give the address yourself:

```bash
sudo ./deploy/install-panel.sh --panel 8443 --panel-url https://panel.example.com:8443
```

When the panel only watches other machines, keep its own firewall out of it: add
`SENTRAI_FIREWALL=off` to `/etc/sentrai/sentrai.env` and run `sudo systemctl restart sentrai.target`.

The installer opens 8443 in `ufw` or `firewalld` when either is running. If your cloud provider has
its own firewall, allow 8443 there too, ideally only from the machines you add.
`sudo ./deploy/install-panel.sh --panel off` closes the port again.

## 2. Make a join code

On the panel's dashboard, open **Machines**. In **Add machine**:

1. Type a name for the machine, like `web-01`, or leave it empty to use its own host name.
2. Check that **Panel address** is the `https://...:8443` address from step 1.
3. Press **Make join code**.

You get a one-time join code, valid for 24 hours, and the exact command to paste on the new
machine, for Linux and for Windows. The command carries the panel's pin, so the machine talks to
your panel and refuses anything pretending to be it.

## 3. Install the agent on each machine

The agent has its own installer, separate from the panel's. Follow
[Install the agent](agent.html) on each machine you add: paste the command from step 2, then turn
blocking on once its dry run looks right.

## Look after your machines

| To | Do |
| --- | --- |
| See every machine, its risk and its services | dashboard, **Machines** |
| Open one machine's own page | **Machines**, click the machine. Its address (`?machine=<name>`) can be shared or bookmarked |
| See one machine's CPU, memory, disks, network and temperatures | on its page, the **Hardware** tab (the list shows CPU, memory and fullest disk too) |
| See one machine's incidents, blocks or services | on its page, the **Incidents**, **Blocks** or **Services** tab |
| See who is signed in on a machine, what your administrators ran as root, and teach SentrAI who they are | on its page, the **Admins** tab |
| Scan a machine for threats, or back it up | on its page, press **Scan for threats** or **Back up now** |
| Remove a machine from the panel | on its page, **Agent** tab: tick **Yes, stop accepting its key**, press **Revoke key** |
| Remove the agent from a Linux machine | `sudo ./mvp/deploy/uninstall-agent.sh` (add `--purge` to delete its key too) |
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
machine. A backup stays on the machine and a locked copy is also kept on the panel and on two other
machines, so losing the machine does not lose it ([Copies on other machines](settings.md#copies-on-other-machines)).

**Admins** shows who is signed in on the machine right now (the account, how and from where, and
whether SentrAI trusts that sign-in and why), the root work your known administrators did lately,
and the administrators it knows: accounts, addresses and SSH keys, each with how it came to know
them (a setting, taught, or learned) and a **Forget** button, except for the ones from the
settings. A small form adds an address, key or account with a label. Root work from a sign-in
SentrAI does not know opens a **Root access from an unrecognised sign-in** incident, which never
blocks anything by itself and has two answers on the incident and in its Telegram alert:
**This was me** teaches SentrAI that sign-in and closes the alert, **Not me: block it** blocks the
address. The panel's installer puts your `--protect` and dashboard addresses in `ADMIN_IPS`, so your own work
from your computer counts as yours on every machine from the start. See
[Your own administrators](settings.html#your-own-administrators).

**Hardware** comes from the agent every 30 seconds: CPU, memory, each disk, network traffic, uptime,
and temperatures where the machine has sensors it can read (most Linux machines; usually none on
Windows or in a cloud VM). The panel keeps the last hour for the charts. It alerts the on-duty person
once when a disk passes 90% full, or CPU or memory stays over 90%, or a sensor stays over 85 °C, for
5 minutes. Change the limits with `SENTRAI_HW_*` in the panel's settings (see the
[API reference](api/fleet.html#post-fleethardware)), or set `SENTRAI_HW_ALERTS=off` to only show them.
Agents installed before this need an update (`sudo sentrai-update`) to start sending it.

## Update the agents

Each machine updates its own agent with `sudo sentrai-update` (Windows: `update-agent.ps1`); see
[Install the agent](agent.html#update-the-agent). Update the panel first: a newer agent may need a
newer panel.

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
