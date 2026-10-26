---
title: Install guide
nav: docs
description: How to install and run SentrAI on Windows, macOS or a Linux server.
---

# Install SentrAI

SentrAI watches your logs, scores the risk of what it sees, and blocks attackers inside your own
network. It never strikes back. This guide gets it running, from a laptop to
a server that keeps watch around the clock.

## Pick your path

| You want to | Go to | Time |
| --- | --- | --- |
| Run SentrAI on your own computer | [Run on a laptop](laptop.html) | about 5 minutes |
| Keep SentrAI running on a Linux server | [Install on a server](server.html) | about 10 minutes |
| Sign in, invite your team, or reset a sign-in | [Signing in](sign-in.html) | |
| Change thresholds, alerts or protected IPs | [Settings](settings.html) | |
| Fix a port clash, a missing package or a blocked dashboard | [Troubleshooting](troubleshooting.html) | |

## What you need

| | Laptop (Windows) | Laptop (Linux or macOS) | Server |
| --- | --- | --- | --- |
| System | Windows 10 or 11 | any recent Linux, or macOS | Linux with systemd |
| Python | 3.12, on your PATH | 3.11 or newer, with `venv` | 3.10 or newer, with `venv` |
| Rights | your normal account | your normal account | `sudo` |
| Also | Git, or the ZIP from GitHub | Git | Git, and `nft` or `iptables` to open the dashboard to other computers |

On Debian and Ubuntu, add the `venv` module with:

```bash
sudo apt install python3-venv git
```

No Docker is needed. Each part of SentrAI makes its own Python environment the first time it runs,
so the first start takes a minute or two longer than the next ones.

## Get the code

```bash
git clone https://github.com/RexGuard/SentrAI
cd SentrAI/mvp
```

No Git? On the [GitHub page](https://github.com/RexGuard/SentrAI) choose **Code**, then
**Download ZIP**, unzip it and open the `mvp` folder inside.

Every command in this guide is run from that `mvp` folder unless it says otherwise.

## What runs where

| Part | What it does | Address on your machine |
| --- | --- | --- |
| Core | scores risk, decides on blocks, keeps the tamper-evident record | `127.0.0.1:8000` |
| Collector | reads the log files you approve and passes new lines to the core | |
| Dashboard | the web console where you review, approve and change settings | `127.0.0.1:8501` |
| Notifier | sends alerts to Telegram or email, with Approve and Reject buttons | |

The core only ever listens on your own machine. The dashboard does too, unless you open it to
named IP addresses during a [server install](server.html#open-the-dashboard-to-your-computer).
