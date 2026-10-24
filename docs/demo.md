---
title: Try the demo
nav: docs
description: Run the SentrAI demo on Windows, Linux or macOS and watch it stop a staged attack.
---

# Try the demo

The demo starts every part of SentrAI next to a made-up student portal, then runs a scripted
attack against it. You watch the risk climb, get an alert, and see SentrAI block the attackers.
Nothing leaves your computer: the attack scripts only accept `127.0.0.1`.

If you have not yet, [get the code](./#get-the-code) and open the `mvp` folder.

## On Windows

Open PowerShell in the `mvp` folder and start everything:

```powershell
powershell -ExecutionPolicy Bypass -File .\run_demo.ps1 -DemoSpeed 600
```

The first run asks a few setup questions. Press **Enter** at each one to keep the demo values.
When it finishes, a window opens for each part, the dashboard opens in your browser, and the
console prints your **dashboard sign-in**. The password is shown only this once, so copy it now.

Then, in a second PowerShell window, run the attack story:

```powershell
cd mvp\lab
.\.venv\Scripts\python.exe scenario.py
```

Stop everything with:

```powershell
.\stop_demo.ps1
```

## On Linux or macOS

```bash
./run_demo.sh --demo-speed 600
```

Each part runs in the background and writes to `mvp/.demo_logs/<part>.log` instead of opening a
window. Then, in a second terminal:

```bash
cd lab && .venv/bin/python scenario.py
```

Watch a part as it works with `tail -f .demo_logs/core.log`, and stop everything with
`./stop_demo.sh`.

## What you should see

Open **Review** on the dashboard to follow the gauge.

1. Normal traffic comes first. The gauge stays green.
2. A password-guessing attack starts. An incident opens at a risk of about 39 (amber) and you get
   an alert, in Telegram if you set it up, otherwise in the notifier's window or log.
3. Nobody answers. The risk climbs every demo hour, reminders go out, and it escalates to the
   team lead at red.
4. A database attack follows. The risk crosses 80, both attackers are blocked, and the portal
   shows them **Blocked by SentrAI**. Your own machine is never blocked.
5. **Reports** shows the evidence report: the timeline, who was told and when, and the record's
   fingerprint.
6. On **Approvals** you can undo a block or make it permanent.

## Options

| Windows | Linux and macOS | What it does |
| --- | --- | --- |
| `-DemoSpeed 600` | `--demo-speed 600` | demo hours per real hour. The default 60 makes 1 real minute one demo hour; 600 fits a short video |
| `-Mode replay` | `--mode replay` | plays a recorded attack instead of a live one, as a backup for recordings |
| `-NoDashboard` | `--no-dashboard` | starts everything but the dashboard |
| `-NoBrowser` | `--no-browser` | does not open the browser for you |
| `-Tripwires` | `--tripwires` | adds decoy traps to the portal (a fake page and fake credentials); run `scenario.py --tripwires` to trip them |
| `-CorePort 8100` | `--core-port 8100` | when port 8000 is taken |
| `-DashboardPort 8601` | `--dashboard-port 8601` | when port 8501 is taken |

The demo portal always stays on port 5000, the only port the attack scripts accept.

## Recording without signing in

For a screen recording where you do not want to type a password on camera, turn the sign-in off
for that run only:

```powershell
$env:CACTAI_DASHBOARD_LOGIN = "off"     # PowerShell
```

```bash
CACTAI_DASHBOARD_LOGIN=off ./run_demo.sh --demo-speed 600
```

Use this on your own computer only, never on a server.

## Next

The demo stops when you close it, and its clock runs fast. To keep SentrAI watching a real
machine, [install it on a server](server.html).
