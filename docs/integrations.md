---
title: Integrations
nav: docs
description: Connect SentrAI to Cloudflare, AbuseIPDB and Slack, and test each one from the dashboard.
---

# Integrations

SentrAI can work with outside services. Each one stays off until you save its key, and the
dashboard's **Integrations** page shows which are connected, when each last worked, and a
**Test** button that makes one harmless call with the saved key.

Keys are saved in your settings file (never in the code) under **Configuration** >
**7. Integrations**, or as environment variables. Restart SentrAI after saving one.

| Service | What it does | Setting |
| --- | --- | --- |
| Cloudflare | Blocks an attacker at Cloudflare's edge, before it reaches your site | `CLOUDFLARE_API_TOKEN` |
| AbuseIPDB | Shows how often others have reported the attacking address | `ABUSEIPDB_API_KEY` |
| Slack | Posts a copy of every alert in a channel | `SLACK_WEBHOOK_URL` |
| Any other system | Sends each block and its removal to a URL (n8n, Zapier, a router) | `CACTAI_RESPONDER_WEBHOOK_URL` |

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
3. Copy the token into **Cloudflare: API token**.
4. Copy the site's **Zone ID** (on the site's **Overview** page) into **Cloudflare: zone id**. For
   every site, copy the **Account ID** into **Cloudflare: account id** and leave the zone blank.
5. Restart SentrAI, open **Integrations** and press **Test**.

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
  shows on the Integrations page.
- If removing an entry fails, SentrAI retries and tells the person on duty, so no forgotten block
  is left behind.

## AbuseIPDB

When an incident opens with a public source address, SentrAI asks AbuseIPDB how often others have
reported it and writes the answer on the incident: "reported 312 times, 100% abuse confidence".
It is context for the person deciding. It never opens, closes or scores an incident.

Create a free account at abuseipdb.com, open **Account** > **API**, create a key and paste it into
**AbuseIPDB: API key**. The free plan allows 1,000 lookups a day; SentrAI keeps each answer for a
day (`ABUSEIPDB_CACHE_HOURS`), so one busy attacker costs one lookup.

## Slack

In Slack, open **Apps** > **Incoming Webhooks**, add one to the channel that should get alerts,
and paste its URL into **Slack: incoming webhook URL**. Each alert is posted there as well as to
Telegram, email or the console, with a link to its report. Decisions stay in Telegram and the
dashboard.

## Any other system

`CACTAI_RESPONDER_WEBHOOK_URL` sends every block and its removal as signed JSON to a URL you
choose. Use it to reach a service SentrAI does not connect to yet, through n8n, Zapier or Make.
`CACTAI_RESPONDER_WEBHOOK_SECRET` signs each request so the receiver can check it came from SentrAI.
