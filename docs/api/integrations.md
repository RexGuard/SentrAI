---
title: Integrations
nav: api
description: See which outside services SentrAI is connected to and how each last went, and test one with a single harmless call.
---

# Integrations

SentrAI works with a few outside services: Cloudflare, and any other system you choose, for
blocking; AbuseIPDB for lookups; and Slack, Telegram and email for alerts. These two endpoints say
which ones are set up and how each last went, and test one with a single harmless call. The
dashboard's **Integrations** page is built on them. You set a service up in the settings, not
through the API: see [Integrations](../integrations.html) in the install guide.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

Keys are never returned, only whether they are set.

## See what is connected

### `GET /integrations`

Every integration, always in the same order: `cloudflare`, `abuseipdb`, `slack`, `webhook`,
`telegram`, `email`. It shows the settings the core started with, so a key saved since then shows up
after the next restart.

**Returns**, trimmed to two of the six:

```json
[
  {
    "name": "cloudflare",
    "title": "Cloudflare",
    "kind": "Blocking",
    "what": "Blocks attacking addresses at Cloudflare's edge, so they never reach your site. Removed again when SentrAI's block ends.",
    "settings": [
      "CLOUDFLARE_API_TOKEN",
      "CLOUDFLARE_ZONE_ID",
      "CLOUDFLARE_ACCOUNT_ID",
      "CLOUDFLARE_METHOD",
      "CLOUDFLARE_LIST_ID",
      "CLOUDFLARE_MODE"
    ],
    "docs": "https://developers.cloudflare.com/fundamentals/api/get-started/create-token/",
    "configured": true,
    "detail": "IP Access rules, block on zone 023e105f4ecef8ad9ca31a8372d0c353 · 1 address blocked now",
    "last_ok": "2026-10-27 10:41:07",
    "last_error": null,
    "testable": true,
    "error": null
  },
  {
    "name": "slack",
    "title": "Slack",
    "kind": "Alerts",
    "what": "Posts a copy of every alert to a Slack channel, next to Telegram and email.",
    "settings": [
      "SLACK_WEBHOOK_URL"
    ],
    "docs": "https://api.slack.com/messaging/webhooks",
    "configured": false,
    "detail": "Create an incoming webhook in Slack and paste its URL.",
    "testable": false
  }
]
```

| Field | Meaning |
| --- | --- |
| `name` | its id, for [`POST /integrations/{name}/test`](#post-integrationsnametest) |
| `title`, `what` | its name and what it does, in plain words |
| `kind` | `Blocking`, `Lookups` or `Alerts` |
| `settings` | the settings it reads, as environment variables or keys in the settings file |
| `docs` | where to get a key, or `""` |
| `configured` | `true` when its settings are filled in; for Cloudflare, also when they fit together |
| `detail` | one line: what it does now when it is set up, or what it still needs |
| `last_ok` | Cloudflare and AbuseIPDB only: the last time a call to them worked since the core started, or `null`. The machine's local time, written `YYYY-MM-DD HH:MM:SS`, without an offset |
| `last_error` | Cloudflare, AbuseIPDB and the webhook only: what went wrong the last time, or `null` |
| `testable` | `true` when [`POST /integrations/{name}/test`](#post-integrationsnametest) can test it now: Cloudflare, AbuseIPDB and Slack, once they are set up |
| `error` | Cloudflare only: why its settings could not be used, or `null`. Cloudflare then stays off, and `configured` is `false` |

A Cloudflare token without a zone or an account, for example, leaves it off with:

```json
{
  "name": "cloudflare",
  "configured": false,
  "detail": "Paste an API token and a zone or account id to turn it on.",
  "testable": false,
  "error": "set CLOUDFLARE_ZONE_ID (one site) or CLOUDFLARE_ACCOUNT_ID (every site)"
}
```

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/integrations
```

## Test a connection

### `POST /integrations/{name}/test`

Make one harmless call with the saved settings, and say whether it worked:

- `cloudflare` reads the place SentrAI would write to (the zone's or the account's IP Access rules,
  or the IP list) and never changes it.
- `abuseipdb` looks up 1.1.1.1, a public resolver that is never reported as abusive. It counts as one
  lookup on your AbuseIPDB plan, unless the answer is still kept from an earlier lookup
  (`ABUSEIPDB_CACHE_HOURS`, 24 by default).
- `slack` posts one test message to the channel, which reads
  `:shield: SentrAI test message: alerts will arrive in this channel.`
- `webhook`, `telegram` and `email` have no test yet, and answer with `ok` set to `false`.

Nothing is written to the audit trail. A Cloudflare or AbuseIPDB test also updates their `last_ok`
or `last_error` in `GET /integrations`. The answer can take a few seconds: the core waits up to 5
seconds for Cloudflare (`CLOUDFLARE_TIMEOUT_S`) and for Slack, and 4 for AbuseIPDB.

There is no body. `name` is one of the six names above.

**Returns** `ok`, with `detail` when the test worked or `error` when it did not. The status is 200
either way.

```json
{"ok": true, "detail": "Test message posted. Check the channel."}
```

```json
{"ok": false, "error": "No Slack webhook URL set."}
```

| `name` | `detail` when it works | `error` when it does not |
| --- | --- | --- |
| `cloudflare` | `Token works. SentrAI will block through IP Access rules on zone 023e105f4ecef8ad9ca31a8372d0c353.`, or `through IP list sentrai_blocklist (12 items).` with an IP list | Cloudflare's own message about the token or the zone; `Cloudflare is not set up (no API token).`; or the settings problem shown as `error` in `GET /integrations` |
| `abuseipdb` | `Key works. Each new attacking address will be looked up once a day at most.` | AbuseIPDB's own message about the key, `HTTP 429` and the like, or a network error; `No AbuseIPDB API key set.` |
| `slack` | `Test message posted. Check the channel.` | `the Slack webhook URL must start with https://`; `Slack answered HTTP 404` and the like; a network error; `No Slack webhook URL set.` |
| `webhook`, `telegram`, `email` | | `Any other system (webhook) has no test here yet.`, `Telegram has no test here yet.` or `Email has no test here yet.` |

**Errors**

- 404 `no integration called nope`: `name` is not one of the six.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/integrations/slack/test
```

## The six integrations

What makes each one `configured`, and what its `detail` says once it is:

| `name` | `kind` | `configured` when | `detail` once set up |
| --- | --- | --- | --- |
| `cloudflare` | Blocking | `CLOUDFLARE_API_TOKEN` is set, with `CLOUDFLARE_ZONE_ID` (one site) or `CLOUDFLARE_ACCOUNT_ID` (every site). With `CLOUDFLARE_METHOD=list`, `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_LIST_ID` instead | `IP Access rules, block on zone 023e105f4ecef8ad9ca31a8372d0c353 · 1 address blocked now`, or `IP list on account · 0 addresses blocked now` |
| `abuseipdb` | Lookups | `ABUSEIPDB_API_KEY` is set | `12 lookups since start, answers kept 24 h` |
| `slack` | Alerts | `SLACK_WEBHOOK_URL` is set | `The notifier posts each alert there.` |
| `webhook` | Blocking | `SENTRAI_RESPONDER_WEBHOOK_URL` is set | `Sends block_ip, lock_user to hooks.example.com`: the action types it hands over (`SENTRAI_RESPONDER_WEBHOOK_ACTIONS`) and the host it sends them to |
| `telegram` | Alerts | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are both set | `Handled by the notifier.` |
| `email` | Alerts | `SMTP_HOST` and `ALERT_EMAIL_TO` are both set | `Handled by the notifier.` |

- `CLOUDFLARE_METHOD` is `access_rule` (the default) or `list`. `CLOUDFLARE_MODE` is `block` (the
  default), `managed_challenge`, `challenge` or `js_challenge`. Any other value keeps Cloudflare off,
  with the reason in `error`.
- The address count in Cloudflare's `detail` is the blocks SentrAI put there itself and has not
  removed yet. Protected and private addresses are never sent.
- Slack, Telegram and email alerts are sent by the notifier, not by the core. The core only reports
  whether they are set, and tests Slack.
- What the webhook sends for each block and its removal, and how the receiver checks that it came
  from SentrAI, is on [What SentrAI sends out](outgoing.html).
