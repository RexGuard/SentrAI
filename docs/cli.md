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
sudo sentrai status          # protection, machines, what waits for a person, what is still to set up, AI spend
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

## AI helper: the first provider and a second one in reserve

```bash
sudo sentrai ai status      # which provider answers now, the second one, and any rest with its last error
sudo sentrai ai test        # one real request to each provider
sudo sentrai ai reset       # forget the rests after a key was replaced or credit added
```

Set the second provider with `sudo sentrai settings set SENTRAI_LLM_SECOND_PROVIDER=deepseek
SENTRAI_LLM_SECOND_API_KEY=...` (see [settings](settings.md)).

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
sudo sentrai machines blocking shop-pc on            # the agent really changes the firewall (off = dry run)
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

## Antivirus: lock a file away, the shared fingerprint list

See [The agent's antivirus](antivirus.html) for what each machine watches on its own.

```bash
sudo sentrai jobs threats shop-pc                       # what its file watch found lately, with ids
sudo sentrai jobs quarantine shop-pc 3f9c0a7d1e2b4c5a   # lock that file away (id from `threats` or a scan)
sudo sentrai jobs list --host shop-pc                   # the quarantine id (q-...) is in the result
sudo sentrai jobs restore shop-pc q-1a2b3c4d            # put it back (a false alarm)

sudo sentrai signatures list                            # how many known-bad fingerprints, and from where
sudo sentrai signatures add 9f86d0...0a08 --name "miner seen at a customer"
sudo sentrai signatures import recent.csv               # a MalwareBazaar export, a ClamAV .hdb/.hsb, or one hash per line
sudo sentrai signatures remove --source import:recent.csv
sudo sentrai signatures remove 9f86d0...0a08            # a false alarm
```

A file locked away on any machine joins the fingerprint list by itself, so the same file is flagged
on every other machine within about 30 minutes.

## Website check: the company's own websites, from the outside

Sentry can look at the company's website the way a stranger online would (certificate, security settings,
cookies, keys left in public code, `.env` and `.git` left public, SPF and DMARC) and explain what it found in
plain words, with a ready-made note for whoever builds the site. It only checks websites on this list, and only
once the company has proven it owns them. The proof is read again before every check, so leave it in place.

```bash
sudo sentrai websites add shop.example.com     # prints the TXT record (or file) that proves ownership
sudo sentrai websites verify shop.example.com  # after the record is published (DNS can take a few minutes)
sudo sentrai websites check shop.example.com   # at most 12 requests to the site, about 20 seconds
sudo sentrai websites show shop.example.com    # the latest result, with what was fixed since the last one
sudo sentrai websites proof shop.example.com w2    # what the site sent that proves problem w2, as it was saved
sudo sentrai websites recheck shop.example.com w2  # check that one again: still there, fixed, or can't tell yet
sudo sentrai websites list
sudo sentrai websites remove shop.example.com
```

Each problem keeps its proof: the address, the answer's status, the headers that matter, and a short slice of what
the site sent around the quote (never a slice of a settings file, and secret keys cut short). Code, not the AI, checks
that the quote really is in the saved answer (or that a missing setting really is missing): such problems are
**confirmed**, the rest only **likely**. A problem that is gone from the list counts as fixed only when the new check
looked at that thing again and it passed; when the site was busy or the check stopped early it is "can't tell yet".
Every proven website is checked again on its own once its last check is a week old (`SENTRAI_WEBSITE_RECHECK_DAYS`,
0 turns it off).

A sub-domain of a proven domain (blog.example.com under example.com) counts as proven. The owner can then just
ask Sentry "is my website safe?".

## Security Coach connections

The coach reads the company's Google Workspace or Microsoft 365 activity log every 15 minutes, read-only, once it
is set up ([Security Coach connections](coach-connectors.html) has the steps for each).

```bash
sudo sentrai settings set COACH_GOOGLE_CLIENT_ID=... COACH_GOOGLE_CLIENT_SECRET=... COACH_GOOGLE_REFRESH_TOKEN=... COACH_GOOGLE_DOMAIN=example.com
sudo sentrai settings set COACH_MS_TENANT_ID=... COACH_MS_CLIENT_ID=... COACH_MS_CLIENT_SECRET=...
sudo sentrai coach apps on google microsoft
sudo sentrai coach connectors        # connected or not, switched on, the last read and its error
sudo sentrai coach read [google|microsoft]   # read now instead of waiting
sudo sentrai coach setup --email-notes on      # email each note to staff reached by email (no links)
sudo sentrai coach send                      # email the notes that are ready now
```

## Backups

```bash
sudo sentrai backups list                  # this panel's backups, and which machines keep a copy
sudo sentrai backups now                   # take one now
sudo sentrai backups copies                # every machine's copies and where they are kept
sudo sentrai backups key                   # the panel's recovery code: write it down, keep it off the panel
sudo sentrai backups unlock HOST b-...     # a machine was lost: unlock its copy into the restores folder
```

If the panel itself is lost, take the newest `.sbk` file from `/var/lib/sentrai/agent/backups/copies/_panel/`
on any machine and run, in `mvp/core`: `python -m app.sealed open COPY.sbk backup.tar.gz --code CODE`.

## Incidents

```bash
sudo sentrai incidents list            # open ones; --all for every one
sudo sentrai incidents show RSK-2026-081
sudo sentrai incidents waiting --why-risk   # what waits on a person, safest to approve first, and why
sudo sentrai incidents approve-low          # approve every one tagged low risk (never "was this you?")
sudo sentrai lessons list                   # what SentrAI learned from how staff closed alerts, with the incidents
sudo sentrai lessons yes 'xss|198.51.100.0/24'   # normal for us (alerts still come, marked seen before); no: keep alerting
sudo sentrai incidents approve RSK-2026-081 RSK-2026-082
sudo sentrai incidents approve RSK-2026-084 --hours 4   # the fix lasts 4 hours (within MAX_TTL_HOURS)
sudo sentrai incidents reject RSK-2026-083 --why "our own load test"
sudo sentrai incidents rollback RSK-2026-081
sudo sentrai incidents keep RSK-2026-081
sudo sentrai incidents resolve RSK-2026-081 --note "password changed, address blocked at the router"
sudo sentrai protection off --reason "migration tonight"     # watch only
```

## Contact Us messages

What the business sends with the panel's Contact Us form (name, email or company, and the question, feedback or bug
report). They stay on the panel until you mark them handled. To have each one emailed as well (through the SMTP
server in Notifications; Reply goes to the sender when they gave an email):

```bash
sudo sentrai settings set SENTRAI_FEEDBACK_EMAIL=support@example.com
```

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

To let your own Claude list blocks and keep or undo them, see [Keep or undo blocks from Claude](claude.html)
(`sudo sentrai mcp`).

From another computer, run `python mvp/sentrai_cli.py` with `SENTRAI_CORE_URL` and `SENTRAI_API_TOKEN`
set. Keep the token secret: it can change anything. `team` only works on the panel server.
