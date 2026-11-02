---
title: Team command line
nav: docs
description: The sentrai command for the SentrAI team - settings, presets, safety limits, routing, integrations, machines, jobs, incidents and people.
---

# Team command line

The web panel is for the business owner: what needs them, their computers, reports and backups.
Setup and fine-tuning are left to the SentrAI team, which uses the `sentrai` command on the
panel server. It can do everything the panel no longer shows, including the values a preset sets.

Every command goes through the core's API with the API token, so the core checks it and records it in the
activity log under `cli:<your login>`. You don't need to know the token or the address: the command
finds both itself.

```bash
sudo sentrai status          # protection, machines, what waits for a person
sudo sentrai --help          # every command
sudo sentrai settings --help # one command's options
```

Add `--json` to any command for the core's raw answer, for scripts.

## Settings and presets

```bash
sudo sentrai settings show                 # every saved setting, by section
sudo sentrai settings show --all           # also the empty ones and each section's notes
sudo sentrai settings get RISK_THRESHOLD
sudo sentrai settings set RISK_THRESHOLD=70 MAX_AUTO_ACTIONS_PER_HOUR=6
sudo sentrai settings preset               # the presets side by side, and which one is in use
sudo sentrai settings preset strict        # strict, moderate or minimum
```

Changing a value that a preset sets (marked `[preset]` in `settings show`) turns the preset into
*Advanced*: the business owner's panel then says "Your values were set by hand". Pick a preset again to go
back. Most settings need a restart: `sudo systemctl restart sentrai.target`.

## Fewer false alarms and safety limits

```bash
sudo sentrai tuning                        # the noisiest sources this week, with a suggestion for each
sudo sentrai settings set TRUSTED_IPS=203.0.113.0/24 BUSY_SERVER=1   # act on a suggestion
sudo sentrai limits show
sudo sentrai limits set MAX_AUTO_ACTIONS_PER_HOUR=5 PROTECTED_IPS=10.0.0.5,10.0.0.6
```

## Alert routing

```bash
sudo sentrai routing export > routing.json
# edit routing.json: contacts, rules, follow_up
sudo sentrai routing import - < routing.json --summary "night shift goes to the team lead"
```

## Integrations

```bash
sudo sentrai integrations list
sudo sentrai integrations on telegram      # its key must be saved first: sentrai settings set TELEGRAM_BOT_TOKEN=...
sudo sentrai integrations test telegram
sudo sentrai integrations off slack
```

AI Threat Detection (Jev) is built in: it turns on when `TYPESAFE_API_KEY` is set.

## Machines and remote jobs

```bash
sudo sentrai machines list
sudo sentrai machines join-code --name shop-pc      # prints the command to run on the new machine
sudo sentrai machines rename shop-pc "Front desk"
sudo sentrai machines delete old-laptop              # revokes its key, keeps its history
sudo sentrai machines agents                         # agent ids and keys; revoke AGENT_ID

sudo sentrai jobs scan shop-pc        # threat scan
sudo sentrai jobs backup shop-pc
sudo sentrai jobs deps shop-pc        # package check
sudo sentrai jobs packages shop-pc    # what the last package check found
sudo sentrai jobs update shop-pc 1a2b3c4d5e6f7a8b    # update one package (id from `packages`)
sudo sentrai jobs undo shop-pc u-1a2b3c4d             # undo that update
sudo sentrai jobs list --host shop-pc
sudo sentrai deps scan                # the panel server's own packages
```

## Incidents

```bash
sudo sentrai incidents list            # open ones; --all for every one
sudo sentrai incidents show RSK-2026-081
sudo sentrai incidents approve RSK-2026-081 RSK-2026-082
sudo sentrai incidents reject RSK-2026-083 --why "our own load test"
sudo sentrai incidents rollback RSK-2026-081
sudo sentrai incidents keep RSK-2026-081
sudo sentrai incidents resolve RSK-2026-081 --note "password changed, address blocked at the router"
sudo sentrai auto-mode off --reason "maintenance window"
sudo sentrai protection off --reason "migration tonight"     # watch only
```

## Contact Us messages

What the business sends with the panel's Contact Us form (name, email or company, and the question, feedback or bug
report). They stay on the panel until you mark them handled.

```bash
sudo sentrai feedback list             # open ones; --all for handled ones too
sudo sentrai feedback done FB-1a2b3c4d
sudo sentrai feedback open FB-1a2b3c4d # back to open
```

## People who may sign in

The core lets only signed-in people manage accounts, so this one works on the panel server itself, on
the accounts file (as the first Owner, or `--by EMAIL`):

```bash
sudo sentrai team list
sudo sentrai team invite owner@shop.example --role owner   # prints the invite link's path
sudo sentrai team role it@shop.example auditor
sudo sentrai team reset it@shop.example
sudo sentrai team remove it@shop.example
sudo sentrai team withdraw new@shop.example
```

A lost Owner sign-in is still `sudo sentrai-admin --reset`.

## Anything else

Every other core endpoint (see the [API reference](api/index.html)) is one call away:

```bash
sudo sentrai api GET /summary/week
sudo sentrai api POST /backups '{"operator": "cli:me"}'
```

From another computer, run `python mvp/sentrai_cli.py` with `SENTRAI_CORE_URL` and `SENTRAI_API_TOKEN`
set. Keep the token secret: it can change anything. `team` only works on the panel server.
