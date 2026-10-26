---
title: One panel, many machines
nav: docs
description: Turn one SentrAI server into a central panel and add other machines to it with the agent.
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
| Runs | the full SentrAI install (core, collector, dashboard, notifier) | the agent only (`cactai-agent`) |
| Installed with | `deploy/install.sh`, see [Install on a server](server.html) | `deploy/install-agent.sh` |
| Needs open | HTTPS for the agents, plus the dashboard for you | nothing, outgoing HTTPS only |

The examples use `panel.example.com` for the panel's name and `203.0.113.10` for your own
computer's IP. Put your real ones in their place.

## 1. Install the panel

Install SentrAI on the server that will be the panel, the normal way:

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI/mvp
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com
```

Then switch it to panel mode. Add these lines to `/etc/cactai/cactai.env`:

```bash
CACTAI_RISK_SCOPE=host
CACTAI_FIREWALL=off
CACTAI_PUBLIC_URL=https://panel.example.com:8443
```

| Line | Why |
| --- | --- |
| `CACTAI_RISK_SCOPE=host` | scores each machine on its own, so an attack on one machine never blocks traffic on another |
| `CACTAI_FIREWALL=off` | the panel decides blocks but does not apply them to its own firewall; each agent applies its own |
| `CACTAI_PUBLIC_URL` | the HTTPS address the agents will use (step 2). The **Add machine** box fills it in for you |

Restart it with `sudo systemctl restart cactai.target`. On the dashboard, **Machines** no longer
shows the "turn on central panel mode" note.

## 2. Let the agents reach the panel over HTTPS

The panel's core still listens on `127.0.0.1:8000` only. Agents refuse a plain `http://` panel, so
put HTTPS in front of the core. A simple way is nginx with a certificate for the panel's name, for
example from Let's Encrypt (`sudo apt install nginx certbot python3-certbot-nginx`, then
`sudo certbot certonly --nginx -d panel.example.com`):

```nginx
# /etc/nginx/sites-available/sentrai-panel  (then link it into sites-enabled and reload nginx)
server {
    listen 8443 ssl;
    server_name panel.example.com;
    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
```

Apart from a health check and the blocklist, every call to the core needs a machine key or the API
token. Still, open port 8443 only to the machines you add, both in the server's firewall and in your cloud provider's firewall if it has
one.

Using your own certificate instead of Let's Encrypt? Copy its certificate file to each machine and
pass it to the agent installer with `--ca`.

## 3. Add a machine

**On the panel's dashboard**, open **Machines**. In **Add machine**:

1. Type a name for the machine, like `web-01` (or leave it empty to use its own host name).
2. Check that **Panel address** is the HTTPS address from step 2.
3. Press **Make join code**.

You get a one-time join code, valid for 24 hours, and the exact command to paste on the new
machine.

**On the new machine** (Linux with systemd, Python 3.10 or newer with `venv`), get the code and run
the command it gave you:

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI
sudo ./mvp/deploy/install-agent.sh --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --name web-01
```

The installer joins the panel, approves the machine's nginx and SSH login logs if it finds them,
and starts the `cactai-agent` service. Within a minute the machine shows on **Machines** with the
services running on it. Approve more logs on the machine later with Scout, as on any SentrAI
install.

### Blocks start as a dry run

On a new machine, the agent only **logs** the firewall command it would run for each block. Watch
it for a while:

```bash
journalctl -u cactai-agent -f
```

When the commands look right, let it really change the firewall:

```bash
sudo ./mvp/deploy/install-agent.sh --enforce --protect 203.0.113.10
```

The panel's own address is never blocked on an added machine. Add `--protect` for every address
you manage that machine from, just as on the panel. A rerun with `--protect` or `--enforce` rewrites
the machine's settings, so give both together whenever you change either.

### Agent installer options

| Option | What it does |
| --- | --- |
| `--panel URL` | the panel's HTTPS address (needed the first time) |
| `--code CODE` | the one-time join code from **Add machine** (needed the first time) |
| `--name NAME` | the machine's name on the panel (default: its host name) |
| `--enforce` | really change the firewall. Without it, blocks are only logged |
| `--protect IP` | never block this IP or network on this machine. Repeat for more |
| `--ca FILE` | the panel's certificate, when it is your own and not from a public authority |
| `--allow-http` | accept a plain `http://` panel. Only on a private test network |
| `--no-start` | install and enable the service without starting it |
| `--prefix DIR` / `--user NAME` | install somewhere other than `/opt/cactai`, or run as another account |

Settings go in `/etc/cactai/agent.env` and the machine's key in `/var/lib/cactai/agent/`. After
editing `agent.env` by hand, run `sudo systemctl restart cactai-agent`.

### On Windows or a laptop

Without systemd, run the agent from a SentrAI checkout. In PowerShell, from the `mvp\lab` folder
(make its Python environment first if `run.ps1` has never run there):

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m agent join --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --name laptop-01
.\.venv\Scripts\python.exe -m agent run
```

It keeps running while that window is open, and blocks are a dry run. To block in the Windows
firewall, start it from an administrator PowerShell with `$env:CACTAI_FIREWALL="netsh"` and
`$env:CACTAI_FIREWALL_ENFORCE="1"` set first. On Linux or macOS the same commands work with
`.venv/bin/python`.

## Look after your machines

| To | Do |
| --- | --- |
| See every machine, its risk and its services | dashboard, **Machines** |
| See one machine's incidents | **Machines**, then **Look at one machine** |
| Remove a machine | **Machines**, **Joined machines**: pick it, tick **Yes, stop accepting its key**, press **Revoke** |
| Check what a machine joined as and whether blocks are a dry run | on that machine: `journalctl -u cactai-agent -n 20` (the start-up line reads `<name> -> <panel> (blocks: ...)`) |
| Stop the agent for good | on that machine: `sudo systemctl disable --now cactai-agent && sudo rm /etc/systemd/system/cactai-agent.service` |

A revoked machine stops at once: its key no longer works and the panel ignores it. To bring it
back, make a new join code and run the installer again with it.

If a machine loses touch with the panel, the blocks already in place stay for 24 hours
(`CACTAI_AGENT_OFFLINE_HOLD_H`) and are then removed, so a lost panel never leaves a block in
force forever.

## Not tested yet

The panel and the agent are tested in code, but `install-agent.sh` has not yet been run on a real
systemd machine, and the agent has not yet changed a real firewall with `--enforce`. Try it on a
test machine first, keep the dry run on for a while, and make sure your own IP is protected before
you turn enforcement on.
