---
title: Responsible AI and risk statement
nav: docs
description: Which AI SentrAI uses, what data it sees, what it can and cannot do, the risks we know about, and every AI tool, model and asset used to build the project.
---

# Responsible AI and risk statement

## 1. Where AI is used in the product

| Part | AI used | What it decides | What it can never do |
| --- | --- | --- | --- |
| **Sentry** (chat assistant and fix planner) | Claude by Anthropic (default `claude-opus-5`). OpenAI, DeepSeek or any OpenAI-compatible model can be set instead | Explains incidents in plain words and picks a fix from a fixed list (block an address, lock an account, and others) | Choose a target that is not in the incident, choose how long a block lasts, touch a protected address or account, or act outside the machines it was given |
| **Jev** (threat labeller) | TypeSafe System One | Puts a label on log lines the rules did not recognise | Act on its own: its label only feeds the risk score |

**SentrAI works with no AI at all.** Detection rules, the risk score and blocking all run without a key. AI adds
plain-language answers and labels for lines the rules miss. Jev is off until a TypeSafe key is set; without
it the rules and keyword fallback do the labelling.

## 2. People stay in control

- **Below the owner's limit, a person decides** with one press (Approve or Not a threat).
- **Above the limit**, SentrAI applies only a temporary fix inside the owner's own network: 2 hours by default,
  24 hours at most, set in settings and never by the AI.
- **Every fix can be undone** with one press, and protected addresses and accounts are never blocked.
- **Agents start in dry-run mode**: they record what they would block until the team turns on `--enforce`.
- Only *block an address* and *lock an account* change anything for real. Other fix types (rate limit, web
  firewall rule, stop a process) are recorded, or passed to the owner's own gateway through a webhook.
- **No hack-back.** SentrAI never attacks, scans or touches anyone else's machine. Striking back is an offence
  under Singapore's Computer Misuse Act and often hits an innocent, hijacked computer.
- **Accountability.** Every decision by the AI, a person or the `sentrai` command line goes into a hash-chained
  Activity Log that cannot be edited quietly, and each incident gets an evidence report.

## 3. Data and privacy

- SentrAI reads **only the log files the owner approves**.
- When an AI key is set, a short excerpt of the incident goes to the AI provider: up to 12 log lines of 300
  characters for Sentry, up to 2,000 characters for Jev. **Log lines can contain personal data** (addresses,
  user names, page addresses). Nothing removes it automatically yet, so the owner should know this before
  adding a key. Without a key nothing leaves the server.
- The Privacy and Staff Data page and the evidence reports are written with Singapore's PDPA in mind.
  SentrAI helps an owner show what they did. It does not make them compliant by itself.
- Accounts use a password and an authenticator app. Backups are locked with a key before they are copied
  to other machines.

## 4. Known risks and limits

| Risk | What we do about it |
| --- | --- |
| A false alarm blocks a real customer | Blocks are short and reversible, protected addresses are never blocked, and a busy-server mode raises the bar |
| The AI explains something wrongly or makes up a detail | Sentry is told to state only facts it looked up and to say when it does not know. Its fix choice is limited to an allowlist checked by code |
| Rules tuned on demo logs miss real attacks | Expect tuning per client. The detection test set is in `app/eval` |
| An attacker uses a trusted address | A learned admin address only quiets alerts about root work. It never stops blocking |
| Personal data in log lines reaches the AI provider | Optional AI, short excerpts, disclosed here. Masking is on the roadmap |
| The live browser demo uses a public relay (ntfy.sh) | It only carries the scripted demo's made-up events, never real data |

## 5. AI and tools used to build the project

| What | Used for |
| --- | --- |
| **Claude Code** (Anthropic, Claude models) | Most of the code, tests, docs, plan edits, the deck build script and the animated videos' HTML. A person on the team reviewed and tested each change |
| **Claude** (Anthropic) in the product | Sentry, and `app/eval/sentry_sim.py`, where Claude plays non-technical managers and grades Sentry's answers |
| **TypeSafe System One** | Jev, the optional threat labeller |
| **ElevenLabs** | AI voices. The "Erick voice" videos use a voice clone of team member Erick Sientaro, made by him with his consent. "Stand-in" videos use a stock AI voice |
| **HyperFrames + GSAP** | Animated explainer, teaser and story videos (all AI-assisted, made by code, no real footage) |
| **Higgsfield** | *Only if used:* AI-generated intro or B-roll clips in the demo video |

**Prompts.** The product's prompts are in the repository: Sentry's chat and setup prompts in
`app/core/app/chat.py` (guide: [Sentry](sentry.html)) and the simulation prompts in `app/eval/sentry_sim.py`.

**Labelling.** Every video and voice made with AI is labelled "AI-generated" where it is shown or submitted.
Screens of the panel are real screenshots of the prototype with made-up demo data.

## 6. Third-party assets and licences

- **Fonts:** Inter, JetBrains Mono, IBM Plex Sans, Rubik (SIL Open Font License).
- **Icons:** Lucide (ISC licence).
- **Web dashboard:** React, Vite, Tailwind CSS, shadcn/ui and other open-source packages, each under its own
  licence (MIT or similar), listed in the web dashboard's package files.
- **Videos:** GSAP (GreenSock standard no-charge licence).
- **Back end:** FastAPI, Streamlit and other Python packages listed in each part's `requirements.txt`.
- **Demo data:** made up. Attacker addresses come from documentation-only ranges such as 203.0.113.x. No real
  people's data is used.
- **Sources** for the facts we quote are in [app/research/SOURCES.md](https://github.com/RexGuard/SentrAI/blob/main/app/research/SOURCES.md).
