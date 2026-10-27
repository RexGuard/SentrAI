# Running SentrAI as server services

`run.sh` is for trying SentrAI on a laptop: everything stops when you run `stop.sh`. On a real
Linux server, install SentrAI as systemd services instead.

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
  Owner email:                            only on a new machine; Enter skips it, and you create the
  Owner password, at least 12 characters:  Owner in the browser with a setup code instead
```

It skips any question the command line already answers (`--dashboard-port`, `--dashboard-allow`,
`--dashboard-local`, `--admin-email`), and all of them with `--no-questions` or without a terminal.
On an upgrade the brackets hold the current values. At the end it prints the dashboard address and
either the Owner's email or a one-time setup code for creating the Owner on the dashboard. Everyone
else joins by invite from the dashboard's Team page.

Needs systemd and Python 3.10+ with the `venv` module (Debian/Ubuntu: `sudo apt install python3-venv`).
Run the same command again from a newer checkout to upgrade: settings and state are kept, and
packages are reinstalled only when a `requirements.txt` changed.

## What it installs

| Service | What it does | Default address |
| --- | --- | --- |
| `sentrai-core` | risk engine, agents, API | `127.0.0.1:8000` |
| `sentrai-collector` | tails the approved log files, sends events to the core | |
| `sentrai-dashboard` | Streamlit dashboard | `127.0.0.1:8501` |
| `sentrai-notifier` | Telegram alerts (to the journal when no bot is set) | |

`sentrai.target` groups them: `systemctl restart sentrai.target` restarts all four.
The demo portal and attack scripts are not installed as services.

- Code: `/opt/sentrai/mvp` (owned by root; `--prefix` moves it).
- Service settings: `/etc/sentrai/sentrai.env` (ports, addresses, paths, `PROTECTED_IPS`; readable
  by root and the `sentrai` group only). Restart `sentrai.target` after editing it.
- State: `/var/lib/sentrai`, one folder per part. The settings you save on the dashboard and the
  sign-in accounts sit at the top; `core/` holds the audit record and its `people/`, `machines/`,
  `threats/` and `backups/` folders; `collector/` the collector's read positions; `scout/` the list
  of watched log files, Scout's pending proposals and trails; `notifier/` the last fingerprint it
  delivered; `lab-logs/` the JSON-lines logs to tail. `/var/lib/sentrai/INDEX.md` lists every file
  ([`../DATA.md`](../DATA.md) explains them). An upgrade moves the audit record and the read
  positions from their old place in `/var/lib/sentrai` (it stops the services for that, even with
  `--no-start`).
- The services run as the `sentrai` system user, which has no extra groups. See "Least privilege".
- The clock runs in real time (`DEMO_SPEED=1`): a 2-hour block lasts 2 real hours.

## Options

```text
--core-port N / --dashboard-port N     when 8000 or 8501 is taken
--core-bind ADDR / --dashboard-bind ADDR
--protect IP                           add to PROTECTED_IPS (repeatable); the dashboard opens to it too
--dashboard-allow IP                   open the dashboard to this IP or network only (repeatable)
--dashboard-local                      keep the dashboard on the server (SSH tunnel only)
--admin-email EMAIL                    the dashboard Owner's email (asked on a first install)
--reset-password                       new password for that account, printed at the end
--no-questions (-y)                    never ask (what a script or CI run gets anyway)
--no-notifier                          leave the Telegram notifier off
--no-start                             install and enable without starting
--seal-journal                         keep the journal on disk and seal it (see below)
--remote-copy URL                      send everything to a witness on another machine (see below)
--prefix DIR / --user NAME
```

On an upgrade only the options you pass change `sentrai.env`; everything else stays as it was.

## Least privilege

Each service gets only what its job needs, so a flaw in one part cannot be used to rewrite the
record or switch SentrAI off. The limits are in the `sentrai-*.service` files:

| Service | Reads logs | Writes | Can change the firewall | Can see the audit record |
|---|---|---|---|---|
| `sentrai-core` | yes | `core/`, `scout/` | yes (only with `SENTRAI_FIREWALL` on) | yes |
| `sentrai-collector` | yes | `collector/` | no | no |
| `sentrai-dashboard` | no | the settings and sign-in files | no | no |
| `sentrai-notifier` | no | `notifier/` | no | no |

The log groups (`adm`, `systemd-journal`) are given to the core and collector services only, not
to the `sentrai` account; `sentrai-scout` gets them for its own run. Every service also runs with
no new privileges, a read-only system, no devices, no kernel tunables or modules, and the
`@system-service` system calls only (`systemd-analyze security sentrai-core` scores each one;
they are all "OK", down from "EXPOSED" before).

The services share one account, so these walls are the service sandboxes, not file ownership: a
person with root on the server can still lift them. That is why the core also watches for it:
adding an account to the log groups, making a log or SentrAI file writable by everyone, granting
file access with `setfacl`, `setcap` on a SentrAI program, `systemctl edit` or `set-property` on a
SentrAI service, and switching journal sealing or storage off are all reported as log tampering,
like a wiped log. Root's own changes are why the fingerprints in alerts (core README, "Record
fingerprints") go off the box.

### Sealed journal (`--seal-journal`)

Turns on journald's Forward Secure Sealing: the journal is kept on disk and signed every 15
minutes with a key that moves forward and forgets the old one, so entries already sealed cannot
be rewritten unnoticed, even by root. The installer prints a verification key once. Keep it away
from the server (a password manager), and check the journal with:

```bash
journalctl --verify --verify-key=<the key>
```

Uninstalling leaves sealing on.

## Off-box copy (`--remote-copy`)

Someone with root on this server can delete or rebuild SentrAI's audit record. A witness on a
second machine keeps a copy they cannot reach: the core sends it every audit record and every log
line the collector reads, within milliseconds. The witness only adds; the token this server holds
cannot change, delete or read anything there.

On the second machine (one this server's admins cannot log in to):

```bash
sudo ./deploy/install-witness.sh --name 198.51.100.20 --allow 203.0.113.10   # this server's address
```

It prints what to copy over. Then, here:

```bash
sudo ./deploy/install.sh --remote-copy https://198.51.100.20:8600 \
     --remote-copy-token-file ./append.token --remote-copy-ca ./cert.pem
```

The token is kept in `/var/lib/sentrai/core`, which only the core service can open. If this
server's record is ever changed, the core's next send is refused and a **Log tampering** incident
opens. To list what changed, run from anywhere holding the witness's read token (keep that one
off this server):

```bash
python -m app.remote_copy compare --url https://198.51.100.20:8600 --read-token-file read.token
```

`--remote-copy off` stops sending. A witness can also be any machine with Python 3.10; it needs
no packages.

## Reaching the dashboard

With `--protect` or `--dashboard-allow`, the installer sets up access by itself:

- The dashboard listens on all addresses (`SENTRAI_DASHBOARD_HOST=0.0.0.0`), and a firewall rule
  drops every address on its port except the allowed ones (`SENTRAI_DASHBOARD_ALLOW` in
  `sentrai.env`). The rule lives in its own nftables table `inet sentrai_dashboard` (or iptables
  chain `SENTRAI-DASH`); the dashboard service puts it back each time it starts, and refuses to
  start without nft or iptables rather than run open. When ufw or firewalld is active, the
  installer also allows the port there for those addresses.
- It serves HTTPS with a self-signed certificate made in `/etc/sentrai/tls/`. The browser warns
  about it once.
- It asks for the email, password and authenticator code on every new browser session.

Open `https://<server address>:8501` from the allowed IP and sign in. When your IP changes, run
the installer again with the new one (`--dashboard-allow` replaces the list).

The core API always stays on `127.0.0.1`. `--dashboard-local` keeps the dashboard there too, and
removes the firewall rule; reach it through a tunnel from your own computer:

```bash
ssh -L 8501:127.0.0.1:8501 you@your-server     # then open http://127.0.0.1:8501
```

```bash
sudo sentrai-admin                                  # who may sign in; a setup code on a new machine
sudo sentrai-admin --reset                          # the first Owner: new password, authenticator again
sudo sentrai-admin --reset --email you@example.com  # the same for another account
```

## Finding the logs to watch

Scout needs an AI key (Configuration page, section 5). It runs as the service user and never
waits for keyboard answers when no terminal is attached:

```bash
sudo sentrai-scout find --root /var/log "where are the login and web server logs?"
```

Its proposals appear on the dashboard's Collector page under "Scout proposals" (Watch or
Dismiss), or from the shell: `sudo sentrai-scout pending`, `sudo sentrai-scout approve <id>`.
The collector starts watching an approved file within a few seconds. The "Scan running programs"
button on the same page finds log files without an AI key.

## Everyday commands

```bash
systemctl status 'sentrai-*'
journalctl -u sentrai-core -f          # or -u sentrai-collector, -u sentrai-dashboard
sudo systemctl restart sentrai.target
sudo ./deploy/uninstall.sh            # keeps /etc/sentrai and /var/lib/sentrai; --purge removes them
                                      # (also removes the dashboard firewall rule)
```

## Updating (`sentrai-update`)

`install.sh` and `install-agent.sh` install `deploy/update.sh` as `/usr/local/sbin/sentrai-update`:

```bash
sudo sentrai-update                 # newest main (or the --ref saved earlier), same settings
sudo sentrai-update --check         # exit 10 when a newer version is out; writes update-check.json
sudo sentrai-update --rollback      # back to the version before the last update
sudo sentrai-update --from DIR      # from a local checkout (no network)
```

It finds what is installed here (panel, agent or both, `--prefix`, `--user`) from the service
files, fetches the code into `/opt/sentrai/source` (git, or GitHub's download when git is
missing), stops SentrAI, saves the code with its venvs, `/etc/sentrai`, the service files and
`/var/lib/sentrai` (without collected logs) to `/var/backups/sentrai/<time>/` (newest 2 kept),
then runs the new `install.sh --update` and/or `install-agent.sh`. `--update` means no questions,
the notifier stays as it was and the sign-in is left alone (no new setup code). Then it checks the
core's `/health`, the dashboard's `/_stcore/health` and the agents' port, and that no service that
was running before restarts within 20 seconds. On a failure it restores the backup and starts it.

Which code is installed is in `/opt/sentrai/mvp/VERSION` (commit, branch, repository, time); where
updates come from is in `/etc/sentrai/update.env` (`--repo` and `--ref` change it). The
`sentrai-update-check.timer` runs `sentrai-update --check` once a day on the panel; the dashboard
reads `/var/lib/sentrai/update-check.json` for its **Update available** notice. The log of every run
is `/var/log/sentrai-update.log`. Windows agents have the same in `update-agent.ps1`, which
`install-agent.ps1` copies next to the service.

## Upgrading from the CactAI names

`migrate-from-cactai.sh` (run by every install and uninstall script) moves an install made before
the rename: it stops and removes the `cactai-*` units, moves `/etc/cactai` and `/var/lib/cactai`
(renaming `cactai.env`, `cactai.db` and the `CACTAI_*` settings), renames the `cactai` account to
`sentrai` with the same uid, copies the blocks in `inet cactai` and the `cactai` iptables rules to
the new names, and deletes `/opt/cactai` and the old commands. When both the panel and an agent
were on the machine, the installer that ran upgrades the other one as well. Rules added to ufw or
firewalld keep their old `cactai-` comment; they still allow the same ports.

## One panel, many machines (`install-agent.sh`)

One SentrAI install can be the central panel for other machines. Each other machine runs only
the agent: it sends that machine's logs to the panel and puts the panel's blocks for that machine
into its own firewall. The panel does the scoring; the agent only makes outgoing HTTPS calls.

On the panel, install (or upgrade) with `--panel`. It opens a second core port for agents only
(8443, HTTPS with a self-signed certificate), scores each machine on its own
(`SENTRAI_RISK_SCOPE=host`) and prints the certificate's pin. Keep the panel's own firewall out of it
with `SENTRAI_FIREWALL=off` in `/etc/sentrai/sentrai.env` when the panel is not itself a guarded server.

```bash
sudo ./deploy/install.sh --panel                                  # port 8443
sudo ./deploy/install.sh --panel 9443 --panel-url https://panel.example.com:9443
sudo ./deploy/install.sh --panel off                              # close it again
```

The agents' port answers only what a machine key may do (send its events, read its blocks, report
its services and offline work) plus `/fleet/enrol`; the operator's API and token never face the
network through it. The local API on `127.0.0.1:8000` is unchanged.

Make a one-time join code (valid 24 h) on the dashboard's Machines page, Add machine: it shows the
command to paste, with the panel's address and pin. Or with the API, then on the new machine:

```bash
# on the panel (TOKEN is the core's API token: python sentrai_config.py token, with the service settings)
curl -s -X POST http://127.0.0.1:8000/fleet/join-codes \
     -H "Authorization: Bearer TOKEN" \
     -H 'content-type: application/json' -d '{"operator": "erick"}'
# -> {"code": "ABCD-EFGH-JKLM", "panel_url": "https://panel.example.com:8443", "pin": "sha256:...", ...}
# on the new machine
sudo ./deploy/install-agent.sh --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:... --name web-01
sudo ./deploy/install-agent.sh --enforce          # later: really change the firewall (default is a dry run)
sudo ./deploy/install-agent.sh --dry-run          # back to only logging the commands
sudo ./deploy/uninstall-agent.sh                  # remove it and its blocks (--purge also deletes the key)
```

Running `install-agent.sh` again from a newer checkout upgrades the agent and keeps the machine
joined, its `--protect` addresses, enforcing or dry run, and anything added to
`/etc/sentrai/agent.env` by hand. The agent keeps its machine key, read positions and backups in
`/var/lib/sentrai/agent`, where `INDEX.md` lists every file. The CI job "Linux install" runs this
whole path (panel with `--panel`, agent with the pin, a real attack, nftables and iptables blocks,
uninstall) on Ubuntu 22.04 and 24.04 for every pull request.

### Windows machines (`install-agent.ps1`)

On Windows 10, 11 or Server 2016 and newer, `install-agent.ps1` does the same as a Windows
service. It needs Python 3.10+ installed for all users (the python.org installer; the Microsoft
Store Python cannot run as a service). From a SentrAI checkout, in an Administrator PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Panel https://panel.example.com:8443 -Code ABCD-EFGH-JKLM -Pin sha256:... -Name web-01
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\install-agent.ps1 -Enforce   # later: really block in Windows Firewall
powershell -ExecutionPolicy Bypass -File .\mvp\deploy\uninstall-agent.ps1          # remove it (-Purge also deletes the key)
```

- The service is **SentrAI agent** (`SentrAIAgent`): starts with Windows, restarts itself after a
  crash, runs as LocalSystem because Windows Firewall rules need it. `Get-Service SentrAIAgent`,
  `Restart-Service SentrAIAgent`.
- Code and venv: `C:\Program Files\SentrAI` (`-Prefix` moves it). The service wrapper is
  [WinSW](https://github.com/winsw/winsw) 2.12.0, downloaded from its GitHub release and checked
  by SHA-256 (`-WinSW <file>` uses a copy you downloaded yourself).
- Settings: the `<env>` lines in `C:\Program Files\SentrAI\SentrAIAgent.xml`. Run the installer
  again with `-Enforce`, `-DryRun` or `-Protect IP` to change them; other options are kept.
- Machine key, read positions and service output: `C:\ProgramData\SentrAI\agent` (SYSTEM and
  Administrators only); the output is in `service\SentrAIAgent.out.log`, and `INDEX.md` there lists
  every file the agent keeps.
- Blocks are one inbound Windows Firewall rule per address, named `SentrAI-block-<ip>`. They are a
  dry run (only logged) until `-Enforce`. Uninstalling takes them all out (`-KeepBlocks` leaves them).
- Options: `-Panel`, `-Code`, `-Name`, `-Pin sha256:...` (the panel's certificate pin), `-Ca FILE`, `-AllowHttp` (test networks
  only), `-Enforce` / `-DryRun`, `-Protect IP,IP`, `-Prefix DIR`, `-WinSW FILE`, `-NoStart`.
  `Get-Help .\mvp\deploy\install-agent.ps1 -Full` explains each.

The CI job "Windows agent installer" runs all of this on a real Windows machine for every pull
request: install, join, report in, upgrade to `-Enforce`, one real Windows Firewall block,
uninstall.

On a laptop, without installing a service, the agent can also run from a checkout:

```bash
cd mvp/lab
python -m agent join --panel https://panel.example.com:8443 --code ABCD-EFGH-JKLM --pin sha256:...
python -m agent run         # SENTRAI_FIREWALL=netsh SENTRAI_FIREWALL_ENFORCE=1 to block on Windows
```

### The certificate pin

With `--pin`, every call the agent makes checks that the panel shows exactly that
certificate, so a self-signed panel needs no certificate file, and a look-alike server or an
intercepting proxy is refused even if some authority signed its certificate. A panel behind a
publicly trusted certificate (for example nginx with Let's Encrypt) can skip the pin; `--ca FILE`
still works for a private authority. After the panel's certificate is renewed, set the new pin on
each machine: `sudo ./deploy/install-agent.sh --pin sha256:...` (it keeps every other setting and
restarts the agent). From a checkout without the service, `python -m agent pin` shows the kept and
the current one, and `python -m agent pin sha256:...` sets it.

### When the panel cannot be reached

Each machine's key only sends that machine's events and reads
its own block list; revoke one with `POST /fleet/agents/<id>/revoke`. If the panel goes quiet:

- blocks already in place stay for 24 h (`SENTRAI_AGENT_OFFLINE_HOLD_H`) and are then removed
- the logs wait in the collector and reach the panel when it is back, where they are scored as usual
- after 30 s the agent's local rules take over: the core's own rules (no AI) score each line, and an
  outside address that reaches the panel's autonomous line (`RISK_THRESHOLD`, 80) in 10 minutes is
  blocked for an hour (`SENTRAI_AGENT_LOCAL_TTL_MIN`), at most 10 new blocks an hour
  (`SENTRAI_AGENT_LOCAL_MAX_PER_HOUR`). Only address blocks, only clear attacks (brute force, SQL
  injection, XSS, port scans, privilege escalation, data theft, prompt injection), never private or
  protected addresses. `SENTRAI_AGENT_LOCAL_RULES=off` turns this off.
- when the panel answers again the agent reports every local block (`POST /fleet/offline-report`):
  it is written to the audit record, raises an alert, and the Machines page and the machine's
  Agent tab show it under "Last time offline"

### Threat scans and backups from the panel

On the Machines page, click a machine and press **Scan for threats** or **Back up now**. The panel
only queues the job; the machine's agent picks it up on its next call out (within about 15 s), runs
it there and sends back a short result. Critical and high scan findings open a malware incident on
that machine. Backups stay on the machine (restoring one is done there, by a person); the panel gets
the backup's id, size and checksum. A job nobody picks up in 24 h expires.

What is read is set on each machine, never by the panel. Add these to `/etc/sentrai/agent.env`
(folders separated by `:`, or `;` on Windows) and restart the agent:

```bash
SENTRAI_THREAT_PATHS=/var/www:/srv/minecraft/plugins
SENTRAI_BACKUP_PATHS=/srv/app/data
SENTRAI_BACKUP_KEEP=7                 # optional; backups go to /var/lib/sentrai/agent/backups
```

The agent runs as its own user, so it can only scan and back up folders that user can read.
API: `POST /fleet/jobs {host, kind: threat_scan|backup}`, `GET /fleet/jobs?host=`,
`POST /fleet/jobs/<id>/cancel`.

## Not covered yet

This makes SentrAI run properly as services. It does not yet make it understand or stop real
attacks: the rules still expect the demo portal's log format, and a block only reaches the demo
portal's blocklist, not nginx, sshd or the firewall.
