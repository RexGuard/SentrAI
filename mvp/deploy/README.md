# Running SentrAI as server services

`run_demo.sh` is for recording the demo: everything stops when you run `stop_demo.sh`, and the
clock runs fast. On a real Linux server, install SentrAI as systemd services instead.

```bash
git clone https://github.com/RexGuard/SentrAI && cd SentrAI/mvp
sudo ./deploy/install.sh --protect 203.0.113.10 --admin-email you@example.com
```

Run from a terminal, the installer then asks about the web dashboard, with the answer in
[brackets] kept when you press Enter:

```text
  Dashboard port [8501]:
  Allowed IPs [203.0.113.10]:            the IPs that may open it (defaults to --protect, or the
                                          address your SSH session comes from); "local" = tunnel only
  Dashboard sign-in email [admin@sentrai.local]:
  Dashboard password (Enter to make one for you):   typed twice, at least 8 characters
```

It skips any question the command line already answers (`--dashboard-port`, `--dashboard-allow`,
`--dashboard-local`, `--admin-email`), and all of them with `--no-questions` or without a terminal.
On an upgrade the brackets hold the current values. At the end it prints the dashboard address and
the sign-in; a password it made is shown only then. `sudo cactai-admin --reset` makes a new one.

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
--protect IP                           add to PROTECTED_IPS (repeatable); the dashboard opens to it too
--dashboard-allow IP                   open the dashboard to this IP or network only (repeatable)
--dashboard-local                      keep the dashboard on the server (SSH tunnel only)
--admin-email EMAIL                    dashboard sign-in email (asked on a first install)
--reset-password                       new dashboard password, printed at the end
--no-questions (-y)                    never ask (what a script or CI run gets anyway)
--no-notifier                          leave the Telegram notifier off
--no-start                             install and enable without starting
--prefix DIR / --user NAME
```

On an upgrade only the options you pass change `cactai.env`; everything else stays as it was.

## Reaching the dashboard

With `--protect` or `--dashboard-allow`, the installer sets up access by itself:

- The dashboard listens on all addresses (`CACTAI_DASHBOARD_HOST=0.0.0.0`), and a firewall rule
  drops every address on its port except the allowed ones (`CACTAI_DASHBOARD_ALLOW` in
  `cactai.env`). The rule lives in its own nftables table `inet cactai_dashboard` (or iptables
  chain `CACTAI-DASH`); the dashboard service puts it back each time it starts, and refuses to
  start without nft or iptables rather than run open. When ufw or firewalld is active, the
  installer also allows the port there for those addresses.
- It serves HTTPS with a self-signed certificate made in `/etc/cactai/tls/`. The browser warns
  about it once.
- It asks for the email and password on every new browser session.

Open `https://<server address>:8501` from the allowed IP and sign in. When your IP changes, run
the installer again with the new one (`--dashboard-allow` replaces the list).

The core API always stays on `127.0.0.1`. `--dashboard-local` keeps the dashboard there too, and
removes the firewall rule; reach it through a tunnel from your own computer:

```bash
ssh -L 8501:127.0.0.1:8501 you@your-server     # then open http://127.0.0.1:8501
```

```bash
sudo cactai-admin                                  # show the sign-in email
sudo cactai-admin --reset                          # new password, printed once
sudo cactai-admin --email you@example.com --reset  # new email and password
```

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
                                      # (also removes the dashboard firewall rule)
```

## Not covered yet

This makes SentrAI run properly as services. It does not yet make it understand or stop real
attacks: the rules still expect the demo portal's log format, and a block only reaches the demo
portal's blocklist, not nginx, sshd or the firewall.
