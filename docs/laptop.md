---
title: Run on a laptop
nav: docs
description: Run SentrAI on Windows, Linux or macOS and point it at your own logs.
---

# Run on a laptop

`run.ps1` (Windows) and `run.sh` (Linux, macOS) start every part of SentrAI on your own computer
and keep it watching the logs you approve until you stop it.

If you have not yet, [get the code](./#get-the-code) and open the `mvp` folder.

## On Windows

Open PowerShell in the `mvp` folder and start everything:

```powershell
powershell -ExecutionPolicy Bypass -File .\run.ps1
```

The first run asks a few setup questions. Press **Enter** at each one to keep the defaults.
When it finishes, a window opens for each part, the dashboard opens in your browser, and the
console prints a one-time **setup code**. The dashboard opens on *Create your Owner account*:
type the code there, then add an authenticator app. See [Signing in](sign-in.html).

Stop everything with:

```powershell
.\stop.ps1
```

## On Linux or macOS

```bash
./run.sh
```

Each part runs in the background and writes to `mvp/.run_logs/<part>.log` instead of opening a
window. Watch a part as it works with `tail -f .run_logs/core.log`, and stop everything with
`./stop.sh`.

## Give it logs to watch

SentrAI only reads the logs you approve. On the dashboard, open **Collector** and run a process
scan, or ask Scout to find them. You can also approve the usual logs in one step: nginx, SSH,
Suricata and database logs on Linux, or the Windows Event Log on Windows (run it as an
administrator there; see [Log sources](log-sources.html)):

```bash
cd lab && .venv/bin/python -m collector.collector --add-system-logs
```

Before you turn on firewall blocking, add your own IP address to the protected IPs under
[Settings](settings.html).

## Options

| Windows | Linux and macOS | What it does |
| --- | --- | --- |
| `-Speed 60` | `--speed 60` | makes the timers run faster for a test: 60 turns 1 real minute into 1 hour. The default 1 is real time |
| `-NoDashboard` | `--no-dashboard` | starts everything but the dashboard |
| `-NoBrowser` | `--no-browser` | does not open the browser for you |
| `-CorePort 8100` | `--core-port 8100` | when port 8000 is taken |
| `-DashboardPort 8601` | `--dashboard-port 8601` | when port 8501 is taken |

## Next

To keep SentrAI watching a machine around the clock, [install it on a server](server.html).
