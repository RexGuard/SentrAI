---
title: Troubleshooting
nav: docs
description: Fixes for the most common SentrAI install problems.
---

# Troubleshooting

## A port is already taken

Another program is using 8000 or 8501. Pick other ports:

```bash
./run.sh --core-port 8100 --dashboard-port 8601                  # Linux, macOS
sudo ./deploy/install.sh --core-port 8100 --dashboard-port 8601       # server
```

```powershell
.\run.ps1 -CorePort 8100 -DashboardPort 8601
```

## "No module named venv" or "ensurepip is not available"

Python is missing its `venv` module. On Debian and Ubuntu:

```bash
sudo apt install python3-venv
```

Then delete the half-made `.venv` folders and start again:

```bash
rm -rf core/.venv lab/.venv dashboard/.venv notifier/.venv
```

## "Could not download the Python packages"

The installer fetches its Python packages from pypi.org, so the machine needs outgoing HTTPS. Check
with `curl -sI https://pypi.org/simple/ | head -1` (it should print a `200` line). Behind a proxy, set
`HTTPS_PROXY` when you run the installer, for example `sudo HTTPS_PROXY=http://proxy:3128 ./mvp/deploy/install.sh`.
On Windows, run `$env:HTTPS_PROXY = "http://proxy:3128"` in the same PowerShell first.
Then run the same install command again: it carries on where it stopped.

## PowerShell says running scripts is disabled

Start SentrAI with the policy switch shown in [Run on a laptop](laptop.html#on-windows):
`powershell -ExecutionPolicy Bypass -File .\run.ps1`. It applies to that run only.

## "python" is not found on Windows

Install Python 3.12 from [python.org](https://www.python.org/downloads/) and tick **Add python.exe
to PATH** on the first screen of the installer. Close and reopen PowerShell afterwards.

## The dashboard does not open from my computer

Work through these in order:

1. **Is it running?** On the server: `systemctl status sentrai-dashboard`.
2. **Is your IP allowed?** Your public IP may have changed. Check it, then
   `sudo ./deploy/install.sh --dashboard-allow <your IP>`.
3. **Are you using https?** A server dashboard opened to other computers only answers on
   `https://`, not `http://`.
4. **Does the cloud provider block the port?** Some hosts have their own firewall in their web
   console (security groups, firewall rules). Allow port 8501 from your IP there too.
5. **The service will not start without a firewall tool.** When it is open to other computers,
   the dashboard refuses to run without `nft` or `iptables` rather than run open. Install one, or
   use `--dashboard-local` and an [SSH tunnel](server.html#keep-the-dashboard-on-the-server).

## I forgot the dashboard password, or lost my phone

Ask an Owner or Admin to press **Reset sign-in** for you on the **Team** page. A recovery code
also lets you in once without your phone. If no one else can sign in, reset from the machine;
the new password is printed once:

```bash
python sentrai_config.py admin --reset     # laptop
sudo sentrai-admin --reset                  # server
```

Add `--email you@example.com` for an account other than the first Owner.

## "Too many tries"

After five wrong passwords or codes from one address, that address waits five minutes. Wait, then
try again, or reset the sign-in as above.

## No alerts arrive in Telegram

Without a bot token, alerts go to the notifier's window (Windows) or `.run_logs/notifier.log`
(Linux, macOS), or `journalctl -u sentrai-notifier` on a server. Check the token and chat ID under
**Configuration**, section **4. Notifications**, and make sure you sent your bot a message first.

## Nothing shows up on the dashboard

- Check that the collector is watching something: **Collector** on the dashboard lists the logs
  it reads. Approve some first (see [Run on a laptop](laptop.html#give-it-logs-to-watch)).
- Make sure SentrAI is still running. Each part writes its output to `.run_logs/` on Linux and
  macOS, or to its own window on Windows.
- The timers run in real time. Use `--speed 60` (`-Speed 60`) to see escalations within minutes.

## My own commands show up as incidents

Your `sudo` commands on a server are raised as **Root access from an unrecognised sign-in** (on a
version before this one, as log tampering or privilege escalation): SentrAI does not yet know your
sign-in as an administrator's. Any one of these fixes it:

1. **Press This was me** on the incident, once per sign-in. SentrAI learns that sign-in's address,
   SSH key and account, closes the incident and stops asking for it.
2. **Tell it in the settings**, so it never asks: your addresses in `ADMIN_IPS` (the server installer
   puts your `--protect` and dashboard addresses there), your SSH key fingerprints in `ADMIN_SSH_KEYS`
   (`ssh-keygen -lf ~/.ssh/id_ed25519.pub` prints yours) or your accounts in `ADMIN_ACCOUNTS`. See
   [Your own administrators](settings.html#your-own-administrators).
3. **Sign in to the dashboard** as Owner or Admin from the computer you work from: for the next 12
   hours, root work from its address is yours.

If it keeps asking even so, SentrAI is not seeing your sign-ins. The collector on that machine must
send the sign-in and `sudo` lines, from `/var/log/auth.log` (or `/var/log/secure`) or the system
journal (`cd lab && .venv/bin/python -m collector.collector --add-system-logs` approves them on
Linux), and its own poll of who is signed in, which runs by itself on an up-to-date collector
(`sudo sentrai-update`). The machine's **Admins** tab shows who SentrAI sees signed in right now; an
empty list while you are signed in means the lines are not arriving. A sign-in made right after
password guessing from the same address is treated as unknown on purpose; **This was me** clears that too.

## A machine will not join the panel

The agent installer prints why. The usual causes:

- **"the panel must be reached over https://"**: use the agents' address, `https://…:8443`, not
  `http://…:8000`. The panel needs `install.sh --panel` first; see
  [Install the panel](panel.html#1-install-the-panel).
- **"could not reach the panel"**: from the new machine, try
  `curl -k https://panel.example.com:8443/health`. If it fails, allow port 8443 from that machine in
  the panel's firewall and in your cloud provider's.
- **"could not reach the panel … SSLError"**: the certificate does not match the pin. Copy the
  command again from **Add machine**, with its `--pin`. After the panel's certificate changed, give
  an installed machine the new pin with `sudo ./mvp/deploy/install-agent.sh --pin sha256:...`
  (`-Pin sha256:...` on Windows); the dashboard shows it with every join code.
- **"the panel refused to join this machine"**: the join code was already used or is more than 24
  hours old. Make a new one under **Machines**, **Add machine**.
- **"the panel no longer accepts this machine's key"**: the machine was revoked. Join it again with
  a new code.

## An update says it rolled back

`sudo sentrai-update` checks the new version before it keeps it. When a check fails it puts the
version you had back, so SentrAI keeps running as before, and it names the check that failed.
The whole run, with each service's last lines, is in `/var/log/sentrai-update.log`; open an issue
with that part. To try again later, run `sudo sentrai-update` again. `sudo sentrai-update --rollback`
goes back one version by hand, after an update that passed its checks but does not behave.

An update that cannot fetch the code changes nothing: the server must reach github.com over HTTPS.

## Where are SentrAI's files?

Everything SentrAI keeps is in one folder, with one sub-folder per part: `~/.sentrai` on a laptop
(`%USERPROFILE%\.sentrai` on Windows), `/var/lib/sentrai` on a server, and
`/var/lib/sentrai/agent` (`C:\ProgramData\SentrAI\agent` on Windows) on a machine with only the
agent. `INDEX.md` in that folder lists every file, what writes it and what it holds. On a laptop,
`python sentrai_paths.py` in the `mvp` folder prints the same list.

Files from an older version are moved there the first time SentrAI starts. A file it could not
move, because it was open or on another drive, stays in use where it is, and a warning names it
when SentrAI starts. Nothing is deleted. See
[where SentrAI keeps its data](https://github.com/RexGuard/SentrAI/blob/main/mvp/DATA.md).

## Still stuck?

Open an [issue on GitHub](https://github.com/RexGuard/SentrAI/issues) with what you ran and what it
printed. Remove your IP addresses, passwords and keys before you paste anything.
