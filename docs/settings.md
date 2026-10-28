---
title: Settings
nav: docs
description: Change SentrAI's security preset, protected IPs, alerts, AI key, firewall blocking, action limits and backups.
---

# Settings

There are three ways to change SentrAI's settings. They all write the same settings file, and
every part reads it when it starts.

- **The dashboard:** **Configuration** has every setting, with a search box at the top.
- **A guided chat:** on a new machine the dashboard opens on **Chat** with a **Set up** offer. It
  asks plain questions (what SentrAI guards, which IPs never to touch, how to alert you) and
  saves nothing until you confirm the summary. Keys and passwords go in a hidden box.
- **The command line:** `python sentrai_config.py setup` asks the same questions in the terminal.
  `python sentrai_config.py` shows the current settings.

The file is `~/.sentrai/config.json` (`%USERPROFILE%\.sentrai\config.json` on Windows), or
`/var/lib/sentrai` on a server. It holds your keys, so it is readable by you only. A variable set
in the environment always wins over the file. Restart SentrAI after a change, or on a server
`sudo systemctl restart sentrai.target`.

Every other file SentrAI keeps sits in the same folder as the settings file, one sub-folder per
part. `INDEX.md` in that folder lists them all; see
[where SentrAI keeps its data](https://github.com/RexGuard/SentrAI/blob/main/mvp/DATA.md).

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
3. Enter both under **Configuration**, section **Telegram extension** (`TELEGRAM_BOT_TOKEN` and
   `TELEGRAM_CHAT_ID`). Saving them turns the [Telegram extension](extensions.html#telegram) on.

Only that chat can press the Approve and Reject buttons.

### Staff reports

Staff can report something suspicious without an account. Share the dashboard address with
`/?report` on the end (the **Staff reports** page shows the exact link). To ask for a shared code
first, set `SENTRAI_REPORT_CODE`. In Telegram they can send `/report` and what they saw; by default
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
2. Set `SENTRAI_FIREWALL=auto` (or `nftables`, `iptables`, or `netsh` on Windows). SentrAI now
   only **logs** the command it would run. Watch the log for a while.
3. When the commands look right, set `SENTRAI_FIREWALL_ENFORCE=1`. This needs root or
   administrator rights.

On a server these go in `/etc/sentrai/sentrai.env`; restart `sentrai.target` afterwards. On a
[central panel](panel.html) keep `SENTRAI_FIREWALL=off`: each added machine applies its own blocks.

## Limits on automatic actions

SentrAI keeps every action it takes on its own small, temporary and recorded, so it can be undone.
These settings set the limits:

| Setting | Default | What it does |
|---|---|---|
| `AUTO_ACTIONS` | `block_ip,rate_limit,waf_rule` | what SentrAI may do without asking. Anything else, like locking an account, waits for a person |
| `MAX_AUTO_ACTIONS_PER_HOUR` | `10` | at most this many actions on its own in any hour; after that a person decides |
| `MAX_TTL_HOURS` | `24` | no temporary action lasts longer than this |
| `ACTION_TTL_HOURS` | none | hours per type, for example `lock_user=1,block_ip=4` |
| `SENTRAI_HEALTH_URL` | none | a page that must keep answering while SentrAI blocks things, like your site's home page |

About 10 minutes after each action, SentrAI checks that it worked and that it did not break the
page above. A failed undo is tried again a few times, then handed to a person.

## Busy servers

A public game server or a big network is scanned and password-guessed by hundreds of addresses a
day. On a normal setting each one is its own alert, and together they push the risk index to 100.
`BUSY_SERVER=on` groups them:

- When 10 or more addresses do the same kind of attack (a scan, password guessing) to one machine
  within 15 minutes, they become one **wave**. You get one alert when it starts, then one summary
  every 15 minutes ("40 new, 5 blocked automatically, 35 waiting for a person") instead of one
  alert per address.
- A wave counts on the risk index about as much as its worst address, at most twice that, so the
  index still jumps for anything new or serious, but not for the 300th scanner.
- Every address keeps its own incident, so each can still be blocked, approved and undone. On
  **Approvals**, group by type to approve a whole wave at once.

| Setting | Default | What it does |
|---|---|---|
| `BUSY_SERVER` | `off` | `on` turns waves on with the values below |
| `WAVE_MIN_ADDRESSES` | `10` with `BUSY_SERVER=on`, else `0` (off) | how many addresses make a wave |
| `WAVE_WINDOW_MIN` | `15` | ...within how many minutes; a wave ends after this long with no new address |
| `WAVE_UPDATE_MIN` | `15` | minutes between a wave's summaries |
| `WAVE_CATEGORIES` | `port_scan,brute_force` | which kinds of attack can make a wave |
| `TRUSTED_IPS` | none | addresses or networks whose lines are never looked at: your players' relay, a CDN, monitoring. Unlike `PROTECTED_IPS` (never blocked, still watched), nothing from these opens an incident |

Only put an address in `TRUSTED_IPS` if you control it or trust whoever does: an attacker behind it
would not be seen. A touched decoy is still always reported.

## Backups

SentrAI backs up its own settings and records every 24 hours from the start. To back up your own
folders too (a website, a game server), list them in `SENTRAI_BACKUP_PATHS`, for example
`SENTRAI_BACKUP_PATHS=/var/www:/srv/minecraft` (on Windows use `;` between folders).

| Setting | Default | What it does |
|---|---|---|
| `SENTRAI_BACKUP_EVERY_HOURS` | `24` | hours between backups; `0` turns the schedule off |
| `SENTRAI_BACKUP_KEEP` | `7` | how many backups to keep |
| `SENTRAI_BACKUP_COPY_TO` | none | a second place for each backup, like a USB drive or network share |

The dashboard's **Backups** page shows the last and next backup, has **Back up now** and **Check**,
and restores a backup. A restore goes into a new folder unless you choose "back where they came
from" and type the backup's name to confirm; SentrAI then saves the current files first, so you can
undo it.

## All variables

The full list, with every default, is in the
[MVP README](https://github.com/RexGuard/SentrAI/blob/main/mvp/README.md#variables).

Every variable starts with `SENTRAI_`. Names from before the rename (`CACTAI_FIREWALL` and the
like) still work when the new name is not set; SentrAI prints a reminder to rename them.
