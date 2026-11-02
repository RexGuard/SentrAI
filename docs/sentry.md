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
- **It only suggests.** Approve, undo, back up and quarantine are always buttons you press. Chat never
  changes anything by itself.

Without an AI key, Sentry still answers with SentrAI's own facts, written in the same plain style, and
adds a short note that a fuller answer needs the AI helper.

## Where it lives

| What | Where | Who changes it |
| --- | --- | --- |
| Default instructions for the chat | `SYSTEM` in [`mvp/core/app/chat.py`](https://github.com/RexGuard/SentrAI/blob/main/mvp/core/app/chat.py) | SentrAI's team, in code |
| Default instructions for the setup chat | `SETUP_SYSTEM` in the same file | SentrAI's team, in code |
| Answers without an AI key | `_fallback*` and `_plain_why` in the same file | SentrAI's team, in code |
| Standing instructions for one organisation | **What Sentry remembers** panel in the Manager view, or `POST /chat/memory` | Owner or Admin |
| Facts Sentry should remember ("rexguard is our game server") | Say "Remember that ..." in chat | Anyone who can act |
| The name people see | `SENTRAI_ASSISTANT_NAME` (default `Sentry`) | SentrAI's team |

Standing instructions are added on top of the defaults before every answer, and they can be up to
2000 characters. Use them for things that only apply to one client, for example "Our managers read
this on their phones; keep it to two sentences" or "Call the website the shop".
Every change goes on the audit trail. See the [chat API](api/chat.html#memory).
