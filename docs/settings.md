---
title: Settings
nav: docs
description: Change SentrAI's security preset, protected IPs, alerts, AI key and firewall blocking.
---

# Settings

There are three ways to change SentrAI's settings. They all write the same settings file, and
every part reads it when it starts.

- **The dashboard:** **Configuration** has every setting, with a search box at the top.
- **A guided chat:** on a new machine the dashboard opens on **Chat** with a **Set up** offer. It
  asks plain questions (what SentrAI guards, which IPs never to touch, how to alert you) and
  saves nothing until you confirm the summary. Keys and passwords go in a hidden box.
- **The command line:** `python cactai_config.py setup` asks the same questions in the terminal.
  `python cactai_config.py` shows the current settings.

The file is `~/.cactai/config.json` (`%USERPROFILE%\.cactai\config.json` on Windows), or
`/var/lib/cactai` on a server. It holds your keys, so it is readable by you only. A variable set
in the environment always wins over the file. Restart SentrAI after a change, or on a server
`sudo systemctl restart cactai.target`.

## Security preset

One choice sets how quickly SentrAI acts and how long a block lasts.

| | Strict | Moderate (default) | Balanced |
| --- | --- | --- | --- |
| Failed logins that count as password guessing | 3 in 2 minutes | 5 in 1 minute | 8 in 1 minute |
| Rows in one export that count as data theft | 50 | 100 | 250 |
| Risk at which SentrAI blocks without waiting | 65 | 80 | 90 |
| Hours a block lasts | 4 | 2 | 1 |
| Hours a person has to respond | 1 | 2 | 4 |

Strict acts early and holds longer, with more false alarms. Balanced puts day-to-day work first.
**Advanced** lets you set each value yourself.

## Never block these

SentrAI never blocks or locks what is on these lists. Put your own admin IP here before anything
else.

| Setting | What it protects | Default |
| --- | --- | --- |
| `PROTECTED_IPS` | addresses never blocked | this machine (`127.0.0.1`, `::1`) plus each `--protect` IP |
| `PROTECTED_USERS` | extra accounts never locked | none; `root`, `admin`, `administrator` and service accounts are always protected |
| `PROTECTED_NETS` | networks only a person may block | the private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and more) |
| `INFRA_ALLOWLIST` | gateways, DNS, monitoring | your DNS servers and default gateway are added for you |

## Alerts

### Telegram

1. In Telegram, message **@BotFather**, send `/newbot`, and copy the token it gives you.
2. Send any message to your new bot. Then open
   `https://api.telegram.org/bot<TOKEN>/getUpdates` and copy the number after `"chat":{"id":`.
3. Enter both under **Configuration**, section **4. Notifications** (`TELEGRAM_BOT_TOKEN` and
   `TELEGRAM_CHAT_ID`).

Only that chat can press the Approve and Reject buttons.

### Staff reports

Staff can report something suspicious without an account. Share the dashboard address with
`/?report` on the end (the **Staff reports** page shows the exact link). To ask for a shared code
first, set `CACTAI_REPORT_CODE`. In Telegram they can send `/report` and what they saw; by default
only the alert chat can, and `TELEGRAM_REPORT_FROM=any` lets staff message the bot directly.

### Email

Set the mail server and who gets alerts in the same section. By default email is the backup and
is only sent when Telegram fails; choose **always** to get every alert by email too. For Gmail use
`smtp.gmail.com`, port 587 and an [app password](https://support.google.com/accounts/answer/185833).

## AI key

SentrAI works without an AI key: its rules decide on their own. A key adds the guided chat's
free-text answers and the log search on servers. Under **Configuration**, section
**5. AI model**, pick a provider (Anthropic, OpenAI, DeepSeek or another OpenAI-compatible
service) and paste its key.

## Firewall blocking

By default a block only goes on SentrAI's own blocklist (`/blocklist`, for your app or proxy to read). To block attackers in the machine's own firewall,
go step by step:

1. Make sure your own IP is in `PROTECTED_IPS`.
2. Set `CACTAI_FIREWALL=auto` (or `nftables`, `iptables`, or `netsh` on Windows). SentrAI now
   only **logs** the command it would run. Watch the log for a while.
3. When the commands look right, set `CACTAI_FIREWALL_ENFORCE=1`. This needs root or
   administrator rights.

On a server these go in `/etc/cactai/cactai.env`; restart `cactai.target` afterwards.

## Backups

SentrAI backs up its own settings and records every 24 hours from the start. To back up your own
folders too (a website, a game server), list them in `CACTAI_BACKUP_PATHS`, for example
`CACTAI_BACKUP_PATHS=/var/www:/srv/minecraft` (on Windows use `;` between folders).

| Setting | Default | What it does |
|---|---|---|
| `CACTAI_BACKUP_EVERY_HOURS` | `24` | hours between backups; `0` turns the schedule off |
| `CACTAI_BACKUP_KEEP` | `7` | how many backups to keep |
| `CACTAI_BACKUP_COPY_TO` | none | a second place for each backup, like a USB drive or network share |

The dashboard's **Backups** page shows the last and next backup, has **Back up now** and **Check**,
and restores a backup. A restore goes into a new folder unless you choose "back where they came
from" and type the backup's name to confirm; SentrAI then saves the current files first, so you can
undo it.

## All variables

The full list, with every default, is in the
[MVP README](https://github.com/RexGuard/SentrAI/blob/main/mvp/README.md#variables).
