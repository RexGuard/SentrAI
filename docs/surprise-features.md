---
title: Surprise features
nav: docs
description: The hackathon surprise features SentrAI implemented, what existed before the reveal, and what changed after it.
---

# Surprise features implemented

Team **SOLID** (#10). The surprise features were revealed on 2 Nov 2026 at 10:00 and 15:00 SGT. We implemented
**feature 2 (human must decide)** and **feature 5 (make it act)**. Everything listed under "after the
reveal" was built and merged between 2 Nov 10:00 and the 3 Nov 09:30 feature freeze. The pull request
numbers link each change to its commits in this repository and in
[SentrAI-demo](https://github.com/RexGuard/SentrAI-demo).

## Feature 2: Human must decide

**Before the reveal.** Incidents below the owner's limit waited on an Approvals page with Approve and Reject
buttons (also in Telegram and email). The page was built for a technical operator: tables, internal names
and many settings.

**After the reveal.**
- The Command Center shows each risk as a **Critical, High or Medium card in plain words**: what happened, why
  it matters and the suggested fix, with one press to decide: **Do the suggested fix** or **Not a threat**
  (#174, #175, #176, #197, #201).
- **Talk to Sentry about this** on every card opens the assistant about that risk, so the owner can ask before
  deciding (#198, #200). Sentry was rewritten to answer like a helper for an owner with no IT team, and it
  describes open fixes as proposals, never as done (#195, #206).
- Every decision, and who made it, goes into the Activity Log, now one table with Select all and Export to PDF
  (#190). Each handled risk can still be undone.
- The owner chooses how much SentrAI may do alone with one setting: **Strict, Moderate or Minimum** (#188, #189).
- The AI cannot decide by itself: it may only propose a fix from a fixed list for targets in the incident. How
  long a block lasts comes from settings, never from the AI.

## Feature 5: Make it act

**Before the reveal.** SentrAI could already block an address in the host firewall and lock an account, and an
"Auto mode" switch let it do so above the limit.

**After the reveal.**
- The Auto mode switch was removed: **SentrAI always acts on its own within the owner's limits**, and asks a
  person below them (#199).
- **The fix visibly works end to end.** In the live demo, pressing *Do the suggested fix* blocks the attacker:
  the attacker's own window shows its sign-ins refused for 2 hours and the attack giving up (SentrAI #202,
  #203, #205; SentrAI-demo #3 to #10).
- The attacker page can run on **another device** (for example a phone) and attack the panel through a small
  relay, so judges can launch the attack themselves (SentrAI-demo #9).
- Handled risks leave the active lists and move to *Already handled by SentrAI*, where each block can be
  undone (#201).

## Third-party parts

Claude (Anthropic) powers Sentry and was used through Claude Code to write most of the code. The cross-device
demo uses the public ntfy.sh relay. See the [Responsible AI and risk statement](responsible-ai.html) for every
model, tool and asset.

## What works and what is incomplete

- **Works:** one-press decisions, plain-language risk cards, Sentry chat on each risk, real blocking of an
  address (host firewall through the agents) and locking of an account, undo, Activity Log with PDF export,
  and the two-device live demo.
- **Incomplete:** other fix types (rate limit, web firewall rule, stop a process) are recorded or passed to
  the owner's own gateway by webhook, not applied by SentrAI itself. SentrAI does not yet learn from an
  owner's past decisions.
