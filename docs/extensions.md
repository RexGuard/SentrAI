---
title: Extensions
nav: docs
description: Add or remove Cloudflare, TypeSafe, Telegram, Slack and AbuseIPDB while SentrAI runs, or write your own.
---

# Extensions

SentrAI works on its own. Outside services are **extensions**: each one lives in its own folder and
can be added or removed while SentrAI runs. Five come with SentrAI:

| Extension | What it does | Its key |
| --- | --- | --- |
| Cloudflare | Blocks an attacker at Cloudflare's edge, before it reaches your site | `CLOUDFLARE_API_TOKEN` |
| TypeSafe | An AI classifier, asked when the rules are unsure | `TYPESAFE_API_KEY` |
| Telegram | Alerts with Approve, Reject and Take buttons in Telegram (This was me and Not me: block it when SentrAI asks about a sign-in) | `TELEGRAM_BOT_TOKEN` |
| Slack | Posts a copy of every alert in a channel | `SLACK_WEBHOOK_URL` |
| AbuseIPDB | Shows how often others have reported the attacking address | `ABUSEIPDB_API_KEY` |

## Add or remove one

Open the dashboard's **Extensions** page. It lists what is **Added**, what is **Available**, and
what is **Built in** (the webhook and email are part of SentrAI itself). Each card has:

- **Add** turns the extension on now. It uses the settings saved for it.
- **Remove** turns it off now, after you confirm. Its settings are kept, so adding it back restores
  it. Cloudflare also takes the blocks it made out of Cloudflare.
- **Test** makes one harmless call to the service with the saved key.
- **Settings** opens its settings on the Configuration page. Saving them takes effect at once.

Settings saved before extensions existed keep working. An extension whose key is saved counts as
added until someone removes it on this page. The choice is recorded in the audit trail with who
made it.

Auditors see the page but cannot change it.

## Decide on the server instead

Set `SENTRAI_EXTENSIONS` where SentrAI starts to fix which extensions are on: names separated by
commas (`cloudflare,telegram`), `all`, or `none`. It wins over the dashboard, whose Add and Remove
buttons are then greyed out.

## Install or uninstall one

An extension is a folder. The ones that ship with SentrAI are in `mvp/extensions/`. To install
another, put its folder there, or in a folder named in `SENTRAI_EXTENSIONS_DIR` (several folders are
separated by `:` on Linux and `;` on Windows). To uninstall one, delete its folder. Either way,
restart SentrAI. Its saved settings stay in the settings file, in case it comes back.

An extension's code runs inside SentrAI. So a folder in `SENTRAI_EXTENSIONS_DIR` that other users
can change (`chmod go-w` fixes that), or that belongs to someone other than you or root, is skipped.
An extra folder can never replace one that ships with SentrAI. The core's log says what was skipped
and why, and so does `python sentrai_extensions.py`.

## Cloudflare

When SentrAI blocks an address, it also blocks it in Cloudflare. When SentrAI's block ends (the
timer runs out, or a person rolls it back), the Cloudflare entry is removed too. The same limits
apply as for every other block: which actions SentrAI may take on its own, how long a block lasts,
and how many it may take in an hour.

1. In the Cloudflare dashboard, open **My Profile** > **API Tokens** > **Create Token** >
   **Create Custom Token**.
2. Give it one permission: **Zone** > **Firewall Services** > **Edit**, for the site you protect.
   (To block on every site in the account, use **Account** > **Account Firewall Access Rules** >
   **Edit** instead.)
3. Copy the token into **Cloudflare API token**.
4. Copy the site's **Zone ID** (on the site's **Overview** page) into **Cloudflare zone id**. For
   every site, copy the **Account ID** into **Cloudflare account id** and leave the zone blank.
5. Press **Save settings**, then open **Extensions** and press **Test**. No restart is needed.

**What an entry does.** `CLOUDFLARE_MODE` is `block` by default. `managed_challenge` is gentler:
a real person behind a shared address can still get through after a check.

**IP list instead of rules.** Cloudflare recommends custom rules over IP Access rules. To use them,
create an IP list (for example `sentrai_blocklist`) and a WAF custom rule `ip.src in
$sentrai_blocklist` with the action **Block**. Then set `CLOUDFLARE_METHOD=list`,
`CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_LIST_ID`, and give the token **Account** > **Account
Filter Lists** > **Edit**.

**Safe by design.**

- Protected and private addresses are never sent to Cloudflare.
- SentrAI only removes entries it made itself (their note starts with "SentrAI"). Something you
  blocked by hand stays.
- If Cloudflare cannot be reached, the block still works on your own machine, and the failure
  shows on the Extensions page.
- If removing an entry fails, SentrAI retries and tells the person on duty, so no forgotten block
  is left behind.
- Removing the Cloudflare extension takes every entry it made out of Cloudflare again. Your own
  machine's blocks stay. An entry that cannot be removed is named on its incident's timeline, so
  you can remove it by hand.

## AbuseIPDB

When an incident opens with a public source address, SentrAI asks AbuseIPDB how often others have
reported it and writes the answer on the incident: "reported 312 times, 100% abuse confidence".
It is context for the person deciding. It never opens, closes or scores an incident.

Create a free account at abuseipdb.com, open **Account** > **API**, create a key and paste it into
**AbuseIPDB API key**. The free plan allows 1,000 lookups a day; SentrAI keeps each answer for a
day (`ABUSEIPDB_CACHE_HOURS`), so one busy attacker costs one lookup.

## Slack

In Slack, open **Apps** > **Incoming Webhooks**, add one to the channel that should get alerts,
and paste its URL into **Slack incoming webhook URL**. Each alert is posted there as well as to
Telegram, email or the console, with a link to its report. Decisions stay in Telegram and the
dashboard.

## TypeSafe

TypeSafe's System One (Jev) is an AI classifier. SentrAI asks it about an event only when its own
rules are unsure, and falls back to keywords when it does not answer in time. Paste a TypeSafe API
key into **TypeSafe (Jev) API key**. The Classifier page then shows the AI classifier as On.
Without the extension, events are classified by the rules and the keyword fallback.

## Telegram

Alerts arrive in a Telegram group with Approve, Reject and Take buttons, and in each person's own
chat once they link it. A **Root access from an unrecognised sign-in** alert shows **This was me**,
**Not me: block it** and **Take it** instead. **This was me** teaches SentrAI that sign-in (its
address, SSH key and account become a known administrator's), closes the alert and undoes any
block; the bot replies with what SentrAI now knows. **Not me: block it** blocks the address (see
[Your own administrators](settings.html#your-own-administrators)). Make a bot with **@BotFather**, then paste its token and the group's chat id
into the Telegram extension's settings. [Settings](settings.html#telegram) has the steps. While
Telegram is removed, alerts go to email and the console, and the link codes on the Incidents page
are hidden.

## Any other system (built in)

`SENTRAI_RESPONDER_WEBHOOK_URL` sends every block and its removal as signed JSON to a URL you
choose. Use it to reach a service SentrAI does not connect to yet, through n8n, Zapier or Make.
`SENTRAI_RESPONDER_WEBHOOK_SECRET` signs each request so the receiver can check it came from SentrAI.

## Write your own

Copy one of the folders in `mvp/extensions/` and change it. An extension needs:

- **`extension.json`**: `name` (the folder's name), `title`, `kind` (Blocking, Lookups, Alerts,
  Classifier or Other), `what` (one sentence), `about`, `docs` (where to get a key), `order`, and
  `settings`. Each setting has `env`, `prompt`, and optionally `default`, `kind` (str, int or
  float), `secret`, `choices` and `advanced`. `on_when` names the settings that make it count as
  added once saved. `requires` lists the pip packages each part needs.
- **`core.py`**, to plug into the core: `setup(ctx)` returns an `Extension` (from
  `app.extensions`). Override what it needs: `responders(below)` to block somewhere else too,
  `classifiers()` to help classify events, `incident_opened(inc)`, `contacts(rows)`,
  `addresses(rows)`, `agent()`, `status()`, `test()` and `close()`. `close()` runs when it is
  removed and must undo what it put outside SentrAI. `routes(router, live)` may add API routes;
  they answer 404 while the extension is not added.
- **`notifier.py`**, to deliver alerts: `main_channel(ctx)` returns a function that runs the alert
  channel until `ctx.changed()` is true, or `None`. `copy_channel(ctx)` returns a function that
  posts a copy of each alert, or `None`.
- **`tests/`**: files named `test_<name>_core.py` run with the core's packages and
  `test_<name>_notifier.py` with the notifier's. Run them from `mvp/extensions`:

```bash
../core/.venv/bin/python -m pytest -q --ignore-glob='*_notifier.py'
../notifier/.venv/bin/python -m pytest -q --ignore-glob='*_core.py'
```

`setup()` must not call outside services; `test()` is for that. A setting that cannot work raises
`ValueError`, and the Extensions page shows its message. An extension that fails to start never
stops SentrAI.
