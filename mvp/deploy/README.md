# Running SentrAI as server services

`run_demo.sh` is for recording the demo: everything stops when you run `stop_demo.sh`, and the
clock runs fast. On a real Linux server, install SentrAI as systemd services instead.

```bash
git clone https://github.com/RexGuard/cactai && cd cactai/mvp
sudo ./deploy/install.sh --protect 203.0.113.10       # your own admin IP, so SentrAI never blocks it
```

Needs systemd and Python 3.10+ with the `venv` module (Debian/Ubuntu: `sudo apt install python3-venv`).
Run the same command again from a newer checkout to upgrade: settings and state are kept, and
packages are reinstalled only when a `requirements.txt` changed.

## What it installs

| Service | What it does | Default address |
| --- | --- | --- |
| `cactai-core` | risk engine, agents, API | `127.0.0.1:8000` |
| `cactai-collector` | tails the approved log files, sends events to the core | |
| `cactai-dashboard` | Streamlit dashboard | `127.0.0.1:8501` |
| `cactai-notifier` | Telegram alerts (to the journal when no bot is set) | |

`cactai.target` groups them: `systemctl restart cactai.target` restarts all four.
The demo portal and attack scripts are not installed as services.

- Code: `/opt/cactai/mvp` (owned by root; `--prefix` moves it).
- Service settings: `/etc/cactai/cactai.env` (ports, addresses, paths, `PROTECTED_IPS`; readable
  by root and the `cactai` group only). Restart `cactai.target` after editing it.
- State: `/var/lib/cactai` (the settings you save on the dashboard, the audit database, the list
  of watched log files, Scout's pending proposals and trails).
- The services run as the `cactai` system user, which joins `adm` and `systemd-journal` so it can
  read `/var/log/auth.log`, nginx logs and the journal. They can write only to `/var/lib/cactai`.
- The clock runs in real time (`DEMO_SPEED=1`): a 2-hour block lasts 2 real hours.

## Options

```text
--core-port N / --dashboard-port N     when 8000 or 8501 is taken
--core-bind ADDR / --dashboard-bind ADDR
--protect IP                           add to PROTECTED_IPS (repeatable)
--no-notifier                          leave the Telegram notifier off
--no-start                             install and enable without starting
--prefix DIR / --user NAME
```

On an upgrade only the options you pass change `cactai.env`; everything else stays as it was.

## Reaching the dashboard

Both the core and the dashboard listen on `127.0.0.1` only. From your own computer:

```bash
ssh -L 8501:127.0.0.1:8501 you@your-server     # then open http://127.0.0.1:8501
```

`--dashboard-bind 0.0.0.0` makes it reachable from outside. Only do that with a dashboard login
set up and the port limited to your own IP in the firewall.

## Finding the logs to watch

Scout needs an AI key (Configuration page, section 5). It runs as the service user and never
waits for keyboard answers when no terminal is attached:

```bash
sudo cactai-scout find --root /var/log "where are the login and web server logs?"
```

Its proposals appear on the dashboard's Collector page under "Scout proposals" (Watch or
Dismiss), or from the shell: `sudo cactai-scout pending`, `sudo cactai-scout approve <id>`.
The collector starts watching an approved file within a few seconds. The "Scan running programs"
button on the same page finds log files without an AI key.

## Everyday commands

```bash
systemctl status 'cactai-*'
journalctl -u cactai-core -f          # or -u cactai-collector, -u cactai-dashboard
sudo systemctl restart cactai.target
sudo ./deploy/uninstall.sh            # keeps /etc/cactai and /var/lib/cactai; --purge removes them
```

## Not covered yet

This makes SentrAI run properly as services. It does not yet make it understand or stop real
attacks: the rules still expect the demo portal's log format, and a block only reaches the demo
portal's blocklist, not nginx, sshd or the firewall.
