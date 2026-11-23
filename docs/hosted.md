---
title: Hosted service
nav: docs
description: Run SentrAI for many companies on one server, each company kept apart in its own core.
---

# Hosted service: many companies, one server

A company's own panel ([Install the panel](server.html)) serves one company. The **hosted service** runs
SentrAI for many companies on SentrAI's own server, so a new customer needs no server of their own: they get
a web address, install the agent on their computers, and that is all.

```text
                      https://acme.sentrai.pro          https://beta.sentrai.pro
                      https://acme.sentrai.pro:8443     https://beta.sentrai.pro:8443
                                   \                          /
                                    gateway (web/gateway.py)            one front door, picks the company
                                   /                          \         by its name in the address
                 Acme's core (127.0.0.1:9100)          Beta's core (127.0.0.1:9101)
                 /var/lib/sentrai-hosted/companies/acme/   .../companies/beta/
```

## How companies are kept apart

- **Their own process and folder.** Each company has its own core, with its own data folder: machines,
  incidents, the audit record, Security Coach data, Company Rules, accounts and backups are files only that
  company's core opens. No request names a company: the core *is* the company.
- **Their own keys.** Each company has its own API token, its own sign-in cookies (on its own address) and its
  own machine keys. A key from one company sent to another company's address is checked by that other core,
  which does not know it.
- **One way in.** The cores listen on `127.0.0.1` only. The gateway sends a request to a core only when the
  address is an active company's; anything else gets "No SentrAI panel here". On the agents' port it passes
  only what a machine key may do (the same list a company's own panel applies), so a company's API token never
  works from outside.
- **Nothing runs on our server.** The cores run in hosted mode (`SENTRAI_HOSTED=1`): they never scan, back up,
  quarantine or restore on the server they run on, never change its firewall, and do not read its logs. Sentry's
  chat and the schedules cannot either. All of that happens on the company's own computers, through their agents.
- **No private addresses.** A company cannot point SentrAI at a private or local address (the AI service, the
  health page, the email server, Slack), so no company can use our server to reach another company's core.
- **Nothing shared by accident.** A company's core gets only a short list of this server's variables (the AI key,
  the monthly AI budget and the mail relay by default, `SENTRAI_HOSTED_SHARE`), never our Telegram bot, tokens or paths.

Still to come: each company under its own system user (today all cores run as one service account), a disk
quota per company, and a public sign-up page.

## Set it up

On a Linux server with the panel's code (any folder; `/opt/sentrai` below):

```bash
cd /opt/sentrai/mvp
python3 -m venv core/.venv && core/.venv/bin/pip install -r core/requirements.txt
python3 -m venv notifier/.venv && notifier/.venv/bin/pip install -r notifier/requirements.txt   # alerts
(cd web/app && npm ci && npm run build)                                                         # the console
sudo install -d -o sentrai -m 0700 /var/lib/sentrai-hosted
```

You need:

- **A wildcard name**: `*.sentrai.pro` pointing at the server (one DNS record).
- **A wildcard certificate** for `*.sentrai.pro` (Let's Encrypt with a DNS challenge works). Both listeners use
  it, and agents pin it: every join code carries its pin. After a renewal with a new key, each machine needs
  `python -m agent pin NEW`, exactly as on a company's own panel.
- **Two open ports**: 443 for the web panels and 8443 for the agents.

Start it (as a systemd service in production):

```ini
# /etc/systemd/system/sentrai-hosted.service
[Unit]
Description=SentrAI hosted service (every company's core and the gateway)
After=network-online.target

[Service]
User=sentrai
WorkingDirectory=/opt/sentrai/mvp
Environment=SENTRAI_HOSTED_HOME=/var/lib/sentrai-hosted
Environment=SENTRAI_HOSTED_DOMAIN=sentrai.pro
Environment=SENTRAI_HOSTED_WEB_PORT=443
Environment=SENTRAI_HOSTED_AGENT_PORT=8443
Environment=SENTRAI_HOSTED_TLS_CERT=/etc/sentrai-hosted/tls/fullchain.pem
Environment=SENTRAI_HOSTED_TLS_KEY=/etc/sentrai-hosted/tls/privkey.pem
EnvironmentFile=-/etc/sentrai-hosted/shared.env
AmbientCapabilities=CAP_NET_BIND_SERVICE
ExecStart=/opt/sentrai/mvp/core/.venv/bin/python sentrai_hosted.py run
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/sentrai-hosted/shared.env` holds what every company shares, for example `ANTHROPIC_API_KEY=...` and
`SENTRAI_AI_MONTHLY_BUDGET_USD=10` (each company's own cap on AI spend).

Alerts by email with no setup: put SentrAI's own mail relay there too (`SENTRAI_RELAY_SMTP_HOST`, `_PORT`,
`_SECURITY`, `_USER`, `_PASSWORD` and `SENTRAI_RELAY_FROM`, such as `alerts@sentrai.pro`). Each company's alerts
then go by email to the people routed to them, or to its Owner and Admin accounts, from the first day. The relay's
login has its own names, so a company that sets its own `SMTP_HOST` never has it sent to that server.

## Add a company

```bash
sudo -u sentrai python sentrai_hosted.py add "Acme Pte Ltd" --owner owner@acme.com
```

```text
Added Acme Pte Ltd.
  Web panel:  https://acme-pte-ltd.sentrai.pro
  Agents:     https://acme-pte-ltd.sentrai.pro:8443
  Owner's one-time setup code: 7KQ2-M9XA-PL4D
```

Send the owner the web address and the code. The panel's first screen creates their Owner account with it, and
from there they invite their own team and add their computers (**Machines** > **Add machine**: the join code
already names their own agents' address). The running service picks a new company up within a few seconds.

## Day to day

```bash
python sentrai_hosted.py list                         # every company, its port and status
python sentrai_hosted.py check                        # is each company's core answering?
python sentrai_hosted.py pause acme-pte-ltd           # stop it (its address shows "No SentrAI panel here")
python sentrai_hosted.py resume acme-pte-ltd
python sentrai_hosted.py remove acme-pte-ltd          # its folder is set aside in removed/, never deleted
python sentrai_hosted.py setup-code acme-pte-ltd      # a new code while no Owner exists yet
python sentrai_hosted.py sentrai acme-pte-ltd status  # the team command line (docs/cli.html), for one company
python sentrai_hosted.py sentrai acme-pte-ltd machines list
```

Each company's core writes its output to `companies/<name>/run/core.log`. A core that stops is started again,
waiting longer after each crash (up to five minutes).

| Setting | Default | What it does |
| --- | --- | --- |
| `SENTRAI_HOSTED_HOME` | `/var/lib/sentrai-hosted` | the companies' folders and `companies.json` |
| `SENTRAI_HOSTED_DOMAIN` | `sentrai.pro` | each company is `<name>.<domain>` |
| `SENTRAI_HOSTED_WEB_PORT` / `SENTRAI_HOSTED_AGENT_PORT` | 8080 / 8443 | the gateway's two listeners |
| `SENTRAI_HOSTED_BIND` | `0.0.0.0` | the address they listen on |
| `SENTRAI_HOSTED_TLS_CERT` / `SENTRAI_HOSTED_TLS_KEY` | none (plain http) | the wildcard certificate |
| `SENTRAI_HOSTED_BEHIND_TLS` | off | set when a proxy in front does TLS, so sign-in cookies are secure |
| `SENTRAI_HOSTED_PUBLIC_WEB_PORT` / `SENTRAI_HOSTED_PUBLIC_AGENT_PORT` | 443 / the agent port | the ports in the addresses companies are given |
| `SENTRAI_HOSTED_FIRST_PORT` | 9100 | the first local port for the cores |
| `SENTRAI_HOSTED_SHARE` | `ANTHROPIC_API_KEY`, `SENTRAI_AI_MONTHLY_BUDGET_USD` and the mail relay's `SENTRAI_RELAY_*` | variables every company's core gets |
| `SENTRAI_HOSTED_NOTIFIER` | on when `notifier/.venv` exists | one notifier per company, for its alerts |
| `SENTRAI_HOSTED_AGENT_MAX_MB` | 2048 | the largest request an agent may send (a sealed backup copy) |
