---
title: How Sentry talks
nav: docs
description: Sentry's default voice, where its instructions live, and how to tune it for your team.
---

# How Sentry talks

Sentry is the chat assistant in the dashboard. It is written for **business owners and managers with
no IT team**. SentrAI's own team does the setup and anything technical, so Sentry never walks people
through settings, keys or log files. It says "SentrAI's team can set that up for you" instead.

## The default voice

Sentry follows these rules unless your team says otherwise:

- **Answer first.** The first sentence says whether you are safe and whether you need to do anything.
- **Short.** About 120 words and at most 3 bullets. It goes into detail only when you ask.
- **Everyday words.** "Someone tried to guess passwords", not "brute force". "Blocked", not
  "contained". It explains any technical word it can't avoid.
- **No internal names.** It never names the parts inside SentrAI (agents, engines, the record keeper).
  It just says "SentrAI".
- **Calm.** It says first what SentrAI already did, then what is left for you.
- **Only what it looked up.** Every fact comes from SentrAI's own records. When the records don't show
  something (for example exactly which data a download held), it says so and offers SentrAI's team to
  check, instead of guessing. An open incident's fix is described as a suggestion until you approve it.
- **No raw details.** Internet addresses, server and account names stay out unless you ask.
- **It only suggests.** Approve, undo, back up and quarantine are always buttons you press, shown below the
  answer. Chat never changes anything by itself.

## How it is tested

`app/eval/sentry_sim.py` has Claude play business owners and managers with no IT team (a bakery owner,
a clinic manager, a cafe owner who wants to "hack them back", ...) chatting with Sentry about realistic
situations, each on a throw-away copy of the core, and grades every answer on seven points: answer first,
plain words, length, accuracy, safety, next step and tone. It runs on the panel with the panel's own AI
key and touches no real data:

```
sudo /opt/sentrai/app/core/.venv/bin/python /opt/sentrai/app/eval/sentry_sim.py --convos 24 --budget 15
```

`--prompt FILE` tries new instructions before they go into `chat.py`. Results (report.md, summary.json,
transcripts) go to `/var/lib/sentrai/sentry-sim/`.

Without an AI key, Sentry still answers with SentrAI's own facts, written in the same plain style, and
adds a short note that a fuller answer needs the AI helper.

## Where it lives

| What | Where | Who changes it |
| --- | --- | --- |
| Default instructions for the chat | `SYSTEM` in [`app/core/app/chat.py`](https://github.com/RexGuard/SentrAI/blob/main/app/core/app/chat.py) | SentrAI's team, in code |
| Default instructions for the setup chat | `SETUP_SYSTEM` in the same file | SentrAI's team, in code |
| Answers without an AI key | `_fallback*` and `_plain_why` in the same file | SentrAI's team, in code |
| Standing instructions for one organisation | **What Sentry remembers** panel in the Manager view, or `POST /chat/memory` | Owner or Admin |
| Facts Sentry should remember ("rexguard is our game server") | Say "Remember that ..." in chat | Anyone who can act |
| The name people see | `SENTRAI_ASSISTANT_NAME` (default `Sentry`) | SentrAI's team |

Standing instructions are added on top of the defaults before every answer, and they can be up to
2000 characters. Use them for things that only apply to one client, for example "Our managers read
this on their phones; keep it to two sentences" or "Call the website the shop".
Every change goes on the audit trail. See the [chat API](api/chat.html#memory).

## When Sentry can't do it yet

When someone asks Sentry for something SentrAI can't do yet ("Email me a report every Monday", "Export the
incidents to Excel"), Sentry says so plainly, helps with what it can do now, and passes the request
to SentrAI's team as a **feature idea**. Questions it can answer, and decisions it already offers buttons for, are
not noted.

The same idea asked again is grouped and counted, so the most wanted ones rise to the top. Only the person's own
words are kept, cleaned of addresses, emails, links, file paths and anything that looks like a password or key;
attached files and log lines never go in. Ideas live on the panel in `feature-ideas.json`.

SentrAI's team reviews them from the command line:

    sudo sentrai ideas list            # most asked first
    sudo sentrai ideas planned FI-1a2b3c --note "next release"
    sudo sentrai ideas done FI-1a2b3c  # or: dismiss, open
