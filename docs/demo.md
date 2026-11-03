---
title: Try the demo
nav: docs
description: See SentrAI stop an attack in two minutes in your browser, or run the live attack lab on your own computer.
---

# Try the demo

There are two ways to watch SentrAI work. The browser demo needs nothing installed and takes two
minutes. The live attack lab runs the real SentrAI on your computer against a fake website.

## In your browser, nothing to install

A copy of the real panel runs in your browser with made-up data, and a second page plays the
attacker. Nothing is really attacked: the attacker page replays a scripted password-guessing attack
from a documentation-only address (203.0.113.x).

1. Open the **panel**:
   [rexguard.github.io/SentrAI/demo-copy](https://rexguard.github.io/SentrAI/demo-copy/#/command).
2. Open the **attacker page** in another tab, or on a second device such as your phone:
   [rexguard.github.io/SentrAI-demo/demo-site/attack.html](https://rexguard.github.io/SentrAI-demo/demo-site/attack.html).
   Wait until it says **Connected to the SentrAI panel**. Across two devices this takes up to 5
   seconds.
3. Press **Launch simulated attack**. A few seconds later a Critical **Brute Force** risk appears in
   the panel's **Command Center**.
4. Open the risk. It says what happened and what it means, in plain words. Press **Do the suggested
   fix**, as a manager would. The attacker's screen shows it being blocked and giving up.
   **Not a threat** closes the risk without blocking.
5. Press **Talk to Sentry about this** to ask the chat assistant about the attack.

### Two devices

In one browser the two pages talk to each other directly. Across devices they pass a few small
messages through the free public relay ntfy.sh, in a "room". The room is `solid10` unless you type
another one on the attacker page, which then shows the panel link to open on the other device. Both
devices need internet. Anyone who knows the room can press Launch too, so use your own room for a
talk.

## Run the live attack lab

The [SentrAI demo lab](https://github.com/RexGuard/SentrAI-demo) starts the real SentrAI next to a
fake school portal and gives you buttons that send harmless attacks at it. The attacks only ever hit
`127.0.0.1`, use documentation-only addresses and change no real data.

You need Python 3.10 or newer and Git. Stop any SentrAI you started with `run.sh` first, because the
lab starts its own.

```bash
git clone https://github.com/RexGuard/SentrAI-demo
cd SentrAI-demo
./demo.sh            # Windows: .\demo.ps1
```

The first run takes a few minutes and prints a **dashboard setup code**. Open the dashboard at
`http://127.0.0.1:8501`, create the Owner account with the code and add an authenticator app. Then
open `http://127.0.0.1:5000/lab` next to it and press **Full story**: normal traffic, password
guessing nobody acts on, SQL injection, then a web shell from the same attacker. The machine passes
its threshold and both attackers are blocked; the portal shows them a "Blocked by SentrAI" page.

To see it in the web dashboard too, run `./run-web.sh` in `.demo/SentrAI/mvp/web` and open
`http://127.0.0.1:5173` with the same account.

Use `./demo.sh --fresh` between rehearsals to start over, and `./stop.sh` (Windows: `.\stop.ps1`) to
stop. The lab's own guide covers the other buttons, an AI-played intruder on three machines, and a
lab that joins a panel on another computer.
