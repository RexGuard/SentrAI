---
title: Extensions
nav: api
description: See which extensions are installed, added and set up, add or remove one while SentrAI runs, and test one with a single harmless call.
---

# Extensions

SentrAI's outside services are extensions: TypeSafe (the Jev classifier), Telegram, Slack,
Cloudflare and AbuseIPDB. Each one lives in its own folder under `mvp/extensions/`, and SentrAI runs
fine with none of them. These endpoints say which ones are installed, added and set up, add or remove
one while SentrAI runs, and test one with a single harmless call. Two channels are part of SentrAI
itself and always on: the webhook for any other system, and email. They are listed too, marked
`built_in`.

The dashboard's **Extensions** page is built on these endpoints. You fill in an extension's settings
in the settings file or on the dashboard, not through the API: see [Extensions](../extensions.html)
in the install guide.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

Keys are never returned, only whether they are set.

## Added, installed and set up

- **Installed** means its folder is there. Installing or uninstalling one is adding or deleting the
  folder, then restarting the core and the notifier.
- **Added** means it is on. Adding and removing take effect while SentrAI runs.
- **Set up** (`configured`) means its settings are filled in and fit together.

Whether an installed extension is added is decided in this order:

1. `SENTRAI_EXTENSIONS` on the server, when it is set: a comma list of the extensions that are on
   (`none` for none). It is the final word, and add and remove answer 409.
2. Otherwise the last Add or Remove made on the dashboard or through this API, kept in
   `core/extensions.json` in SentrAI's data folder.
3. Otherwise it counts as added once its main key is saved (`on_when`), so settings files from before
   extensions keep working.

## See what is installed

### `GET /extensions`

Every installed extension in page order, then the two built-in channels: `typesafe`, `telegram`,
`slack`, `cloudflare`, `abuseipdb`, `webhook`, `email` when all five are installed.

**Returns**, trimmed to one extension and one built-in channel:

```json
[
  {
    "name": "slack",
    "title": "Slack",
    "kind": "Alerts",
    "what": "Posts a copy of every alert to a Slack channel. Decisions stay in Telegram and the dashboard.",
    "docs": "https://api.slack.com/messaging/webhooks",
    "about": "A copy of every alert in a Slack channel, through an incoming webhook.",
    "settings": ["SLACK_WEBHOOK_URL"],
    "on_when": ["SLACK_WEBHOOK_URL"],
    "parts": ["core", "notifier"],
    "source": "bundled",
    "requires": {"core": ["httpx"], "notifier": ["requests"]},
    "built_in": false,
    "added": true,
    "added_by": "dashboard",
    "running": true,
    "configured": true,
    "detail": "The notifier posts a copy of each alert there.",
    "last_ok": null,
    "last_error": null,
    "testable": true,
    "error": null,
    "changed_by": "erick",
    "changed_at": "2026-10-27T12:21:07+00:00"
  },
  {
    "name": "email",
    "title": "Email",
    "kind": "Alerts",
    "what": "Emails alerts, as a backup to the other alert channels or always.",
    "settings": ["SMTP_HOST", "ALERT_EMAIL_TO"],
    "docs": "",
    "about": "Part of SentrAI: set an SMTP server and the recipients.",
    "built_in": true,
    "added": true,
    "added_by": "built_in",
    "running": true,
    "configured": false,
    "detail": "Handled by the notifier.",
    "testable": false,
    "last_ok": null,
    "last_error": null,
    "error": null,
    "source": "built_in",
    "on_when": [],
    "parts": [],
    "requires": {}
  }
]
```

| Field | Meaning |
| --- | --- |
| `name` | its id, for the endpoints below |
| `title`, `what`, `about` | its name, what it does and a longer line about it, in plain words |
| `kind` | `Classifier`, `Alerts`, `Blocking` or `Lookups` |
| `settings` | the settings it reads, as environment variables or keys in the settings file |
| `on_when` | the settings that count it as added when nothing else decided (step 3 above) |
| `parts` | where it runs: `core`, `notifier` or both |
| `source` | `bundled` (shipped with SentrAI), `extra` (a folder in `SENTRAI_EXTENSIONS_DIR`) or `built_in` |
| `requires` | the Python packages each part needs |
| `docs` | where to get a key, or `""` |
| `built_in` | `true` for the webhook and email, which cannot be added or removed |
| `added` | `true` when it is on |
| `added_by` | what decided `added`: `SENTRAI_EXTENSIONS`, `dashboard`, `settings` or `built_in` |
| `running` | `true` when its core part is running now. A notifier-only extension is never running in the core |
| `configured` | `true` when its settings are filled in; for Cloudflare, also when they fit together |
| `detail` | one line: what it does now, or what it still needs |
| `last_ok` | the last time a call to the service worked since it started, or `null`. The machine's local time, written `YYYY-MM-DD HH:MM:SS`, without an offset |
| `last_error` | what went wrong the last time, or `null` |
| `testable` | `true` when [`POST /extensions/{name}/test`](#post-extensionsnametest) can test it now |
| `error` | why it could not start (its settings do not fit, a package is missing), or `null`. It then stays off, and `configured` is `false` |
| `changed_by`, `changed_at` | who last added or removed it on the dashboard, and when, or `null` |

A Cloudflare token without a zone or an account, for example, leaves it off with:

```json
{
  "name": "cloudflare",
  "added": true,
  "running": false,
  "configured": false,
  "error": "set CLOUDFLARE_ZONE_ID (one site) or CLOUDFLARE_ACCOUNT_ID (every site)"
}
```

An extension that is installed but not added says so in `detail`:
`Not added. Add it to use it; its settings are kept either way.`

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/extensions
```

### `GET /integrations`

The older name of [`GET /extensions`](#get-extensions): the same rows. It still answers, so scripts
written before extensions keep working.

## Add or remove one

### `POST /extensions/{name}/add`

Turn an installed extension on. Its core part starts at once, and the notifier picks up its alert
part within 15 seconds. Its settings are not changed: when they are blank, it is added but not set
up, and `detail` says what to fill in. Writes `extension_added` to the audit trail.

**Body**

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `operator` | string | yes | who added it, for the audit trail |

**Returns** its row, as in [`GET /extensions`](#get-extensions).

**Errors**

- 404 `no extension called nope is installed`: there is no such folder, or `name` is a built-in channel.
- 409 when `SENTRAI_EXTENSIONS` is set on the server: change it there instead.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick"}' http://127.0.0.1:8000/extensions/slack/add
```

### `POST /extensions/{name}/remove`

Turn an installed extension off. Its settings and saved files are kept, so adding it again brings it
back as it was. Blocks it put in place at an outside service (Cloudflare) are taken out there; the
block on the machine itself stays until it ends as usual. Writes `extension_removed` to the audit
trail.

**Body** as for add: `operator`.

**Returns** its row, plus `cleanup`:

```json
{
  "name": "cloudflare",
  "added": false,
  "running": false,
  "detail": "Not added. Add it to use it; its settings are kept either way.",
  "cleanup": {"released": 2, "left_in_place": [], "cloudflare_removed": 2}
}
```

| `cleanup` field | Meaning |
| --- | --- |
| `released` | blocks in force that it took out of its service |
| `left_in_place` | the ones it could not, each with `action_id`, `target` and `error`. Nothing retries them: remove them at the service by hand. The incident's timeline says so too |

Anything else in `cleanup` is the extension's own note on closing.

**Errors** as for add: 404 and 409.

### `POST /extensions/reload`

Read the settings file again and start, stop or restart each extension to match it. The dashboard
calls this after saving settings, so a new key works without a restart. There is no body. Writes
`extensions_reloaded` to the audit trail when something changed.

**Returns** every extension row, as in [`GET /extensions`](#get-extensions), without the built-in
channels.

## Test a connection

### `POST /extensions/{name}/test`

Make one harmless call with the saved settings, and say whether it worked:

- `cloudflare` reads the place SentrAI would write to (the zone's or the account's IP Access rules,
  or the IP list) and never changes it.
- `abuseipdb` looks up 1.1.1.1, a public resolver that is never reported as abusive. It counts as one
  lookup on your AbuseIPDB plan, unless the answer is still kept from an earlier lookup
  (`ABUSEIPDB_CACHE_HOURS`, 24 by default).
- `slack` posts one test message to the channel, which reads
  `:shield: SentrAI test message: alerts will arrive in this channel.`
- `typesafe` asks Jev to classify one ordinary page view.
- `telegram`, `webhook` and `email` have no test yet, and answer with `ok` set to `false`.

Nothing is written to the audit trail. A test also updates `last_ok` or `last_error` in
[`GET /extensions`](#get-extensions). The answer can take a few seconds: the core waits up to 5
seconds for Cloudflare (`CLOUDFLARE_TIMEOUT_S`) and for Slack, and 4 for AbuseIPDB.

There is no body.

**Returns** `ok`, with `detail` when the test worked or `error` when it did not. The status is 200
either way.

```json
{"ok": true, "detail": "Test message posted. Check the channel."}
```

```json
{"ok": false, "error": "Slack is not added."}
```

| `name` | `detail` when it works | `error` when it does not |
| --- | --- | --- |
| `cloudflare` | `Token works. SentrAI will block through IP Access rules on zone 023e105f4ecef8ad9ca31a8372d0c353.`, or `through IP list sentrai_blocklist (12 items).` with an IP list | Cloudflare's own message about the token or the zone, or the settings problem shown as `error` in `GET /extensions` |
| `abuseipdb` | `Key works. Each new attacking address will be looked up once a day at most.` | AbuseIPDB's own message about the key, `HTTP 429` and the like, or a network error |
| `slack` | `Test message posted. Check the channel.` | `the Slack webhook URL must start with https://`; `Slack answered HTTP 404` and the like; a network error |
| `typesafe` | `Jev answered: an ordinary page view is benign (p=0.97).` | why Jev is off, or `Jev did not answer.` |
| any of them | | `Slack is not added.` and the like, or what it still needs when it is added but not set up |
| `telegram` | | `This extension has no test.` |
| `webhook`, `email` | | `Any other system (webhook) has no test here yet.` or `Email has no test here yet.` |

**Errors**

- 404 `no extension called nope is installed`.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/extensions/slack/test
```

### `POST /integrations/{name}/test`

The older name of [`POST /extensions/{name}/test`](#post-extensionsnametest), answering the same way.

## What each one needs

What makes each one `configured`, and what its `detail` says once it is:

| `name` | `kind` | `configured` when | `detail` once set up |
| --- | --- | --- | --- |
| `typesafe` | Classifier | `TYPESAFE_API_KEY` is set and the `typesafe-sdk` package is installed | `12 calls since start, 0 failed, 3 answered from the cache` |
| `telegram` | Alerts | `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are both set | `The notifier runs the bot · 2 linked` |
| `slack` | Alerts | `SLACK_WEBHOOK_URL` is set and starts with `https://` | `The notifier posts a copy of each alert there.` |
| `cloudflare` | Blocking | `CLOUDFLARE_API_TOKEN` is set, with `CLOUDFLARE_ZONE_ID` (one site) or `CLOUDFLARE_ACCOUNT_ID` (every site). With `CLOUDFLARE_METHOD=list`, `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_LIST_ID` instead | `IP Access rules, block on zone 023e105f4ecef8ad9ca31a8372d0c353 · 1 address blocked now`, or `IP list on account · 0 addresses blocked now` |
| `abuseipdb` | Lookups | `ABUSEIPDB_API_KEY` is set | `12 lookups since start, answers kept 24 h` |
| `webhook` | Blocking | `SENTRAI_RESPONDER_WEBHOOK_URL` is set | `Sends block_ip, lock_user to hooks.example.com`: the action types it hands over (`SENTRAI_RESPONDER_WEBHOOK_ACTIONS`) and the host it sends them to |
| `email` | Alerts | `SMTP_HOST` and `ALERT_EMAIL_TO` are both set | `Handled by the notifier.` |

- `CLOUDFLARE_METHOD` is `access_rule` (the default) or `list`. `CLOUDFLARE_MODE` is `block` (the
  default), `managed_challenge`, `challenge` or `js_challenge`. Any other value keeps Cloudflare off,
  with the reason in `error`.
- The address count in Cloudflare's `detail` is the blocks SentrAI put there itself and has not
  removed yet. Protected and private addresses are never sent.
- Telegram, Slack and email alerts are sent by the notifier, not by the core. The core only reports
  whether they are set, and tests Slack.
- Telegram's own endpoints (linking a person's chat, see [Alerts](alerts.html)) answer 404 while
  Telegram is not added.
- What the webhook sends for each block and its removal, and how the receiver checks that it came
  from SentrAI, is on [What SentrAI sends out](outgoing.html).
