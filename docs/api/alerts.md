---
title: Alerts and routing
nav: api
description: Read the alerts waiting to go out, mark them delivered, choose who gets them, and link people's own Telegram chats.
---

# Alerts and routing

SentrAI does not send alerts itself: the core queues them, and the notifier polls the queue, sends
each alert by Telegram, email or Slack and reports back that it went out. The routing file decides
who owns each incident, who else hears about it and who takes over when nobody answers; the
dashboard's routing map edits it. Personal Telegram links let each person get their alerts in a
private chat with the bot instead of one group.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Deliver alerts

### `GET /notifications/pending`

The alerts not yet delivered, oldest first. The notifier polls it every few seconds and sends each
one to the people in `deliver_to`.

**Returns** a list of [notification records](#the-notification-record) with `delivered: false`, or
`[]` when nothing is waiting.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/notifications/pending
```

### `GET /notifications`

Every alert the core has queued, delivered or not, oldest first. The list is kept across restarts.

**Returns** a list of [notification records](#the-notification-record).

### `POST /notifications/{nid}/delivered`

Tell the core an alert went out. The notifier calls it once for each message it sends: once for a
group or channel, and once for each person reached by a private Telegram message, with `to`. The
first call marks the alert delivered and takes it off the pending list; each call adds an entry to
`deliveries`, is written to the audit trail as `notification_delivered` and added to the incident's
timeline. The state is saved to disk.

**Body**

```json
{
  "channel": "telegram",
  "message_id": 4711,
  "to": "Amir"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `channel` | string | yes | how it went out: the notifier sends `telegram`, `email` or `slack` |
| `message_id` | string, integer or null | default `null` | the id the channel gave the message; kept as a string |
| `to` | string or null | default `null` | the one person a private message reached; `null` means the whole group or channel |

**Returns** the updated [notification record](#the-notification-record):

```json
{
  "id": "ntf-0001",
  "incident": "RSK-2026-081",
  "delivered": true,
  "delivered_at": "2026-10-27T02:45:12+00:00",
  "channel": "telegram",
  "message_id": "4711",
  "deliveries": [
    {"channel": "telegram", "message_id": "4711", "delivered_at": "2026-10-27T02:45:12+00:00", "to": null}
  ]
}
```

**Errors**

- 404 `notification ntf-0999 not found`: no alert has that id.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"channel": "email", "message_id": "a1b2c3"}' \
  http://127.0.0.1:8000/notifications/ntf-0001/delivered
```

## Choose who gets them

The routing file holds the people (contacts), the rules that pick an owner for each incident, and
the follow-up policy. It is `SENTRAI_ROUTING`, or `routing.json` next to the audit database. Without
one, the four people in the settings (`ON_DUTY`, `TEAM_LEAD`, `IT_MANAGER`, `CXO`) form a chain where
each one backs up the one before.

For each incident, the first rule that matches wins: its `owner` is assigned the incident and hears
every reminder, and the people under `notify` are told about it once. When the owner does not
answer `escalate_after_reminders` reminders, the incident goes to their `backup`. Alerts addressed to
a role (an escalation to the team lead, protection turned off) go to the first contact with that
role.

### `GET /routing`

The routing in use now, as the dashboard's map shows it.

**Returns**, trimmed:

```json
{
  "source": "/var/lib/sentrai/core/routing.json",
  "contacts": [
    {
      "id": "amir",
      "name": "Amir",
      "role": "on_duty",
      "email": "amir@example.com",
      "telegram": "@amir",
      "backup": "lee",
      "telegram_linked": true
    }
  ],
  "rules": [
    {"name": "Database attacks go to Lee", "match": {"layer": ["db"]}, "owner": "lee", "notify": ["amir"]},
    {"name": "Everything else", "match": {}, "owner": "amir", "notify": []}
  ],
  "follow_up": {
    "escalate_after_reminders": 2,
    "max_escalations": 2,
    "resolve_within_hours": 24.0
  }
}
```

| Field | Meaning |
| --- | --- |
| `source` | the file it came from, or `defaults` when there is none |
| `contacts[].telegram_linked` | whether a private Telegram chat reaches this person, by a [link](#post-telegramlink) or because `telegram` is a numeric chat id |
| `rules[].match` | lists of values for `category`, `severity`, `host` and `layer`; an incident must match every key given, and any value in a list. Values may be shell patterns such as `web-*`. `{}` matches everything |
| `follow_up` | see the body of [`POST /routing`](#post-routing) |

The last rule always matches everything: when the file's last rule has a `match`, an
`Everything else` rule owned by the first contact is added after it.

### `POST /routing`

Replace the whole routing file and use it from the next alert on. The dashboard's routing map sends
it. The new version is checked first; nothing is written when a check fails. The file is written in
one step, readable by its owner only, and the change is written to the audit trail as
`routing_changed`, with the people added and removed.

**Body**

```json
{
  "operator": "erick",
  "routing": {
    "contacts": [
      {"id": "amir", "name": "Amir", "role": "on_duty", "email": "amir@example.com", "telegram": "@amir", "backup": "lee"},
      {"id": "lee", "name": "Lee", "role": "team_lead", "email": "lee@example.com", "telegram": ""}
    ],
    "rules": [
      {"name": "Database attacks go to Lee", "match": {"layer": ["db"]}, "owner": "lee", "notify": ["amir"]},
      {"name": "Everything else", "match": {}, "owner": "amir"}
    ],
    "follow_up": {"escalate_after_reminders": 2, "max_escalations": 2, "resolve_within_hours": 24}
  }
}
```

`operator` (string, required) is the name recorded in the audit trail; `routing` (object, required)
is the whole file:

| Field | Type | Meaning and limits |
| --- | --- | --- |
| `contacts` | list, or object keyed by id | 1 to 200 people |
| `contacts[].id` | string | letters, digits, `_`, `.` and `-`, starting with a letter or digit, up to 40 characters |
| `contacts[].name` | string | required, unique (case ignored) |
| `contacts[].role` | string | `on_duty`, `team_lead`, `it_manager` or `cxo` for the four roles; any other text is kept as a label |
| `contacts[].email` | string | optional; must look like an email address |
| `contacts[].telegram` | string | optional: an `@handle`, or a numeric chat id, which counts as linked |
| `contacts[].backup` | string | optional: the id of another contact, never their own |
| `rules` | list | up to 100, tried in order |
| `rules[].name` | string | required |
| `rules[].match` | object | keys `category`, `severity`, `host`, `layer`; each a value or a list. `category` and `severity` must be known values (see [the incident record](incidents.html#the-incident-record)) |
| `rules[].owner` | string | required: a contact id |
| `rules[].notify` | list of strings | optional: contact ids; the owner is dropped from it |
| `follow_up.escalate_after_reminders` | integer, default 2 | 1 to 20: unanswered reminders to one owner before the backup takes over |
| `follow_up.max_escalations` | integer, default 3 | 0 to 20: how many times an incident may move to a backup |
| `follow_up.resolve_within_hours` | number, default 24 | 0 to 720: an acknowledged incident still not resolved after this long reminds its owner; 0 never does |

Every text field is trimmed and may hold up to 120 characters.

**Returns** the new routing, as [`GET /routing`](#get-routing).

**Errors**

- 400 with the first problem found, such as `the name of x is empty`, `keep at least one person in
  the routing`, `two people are called 'Amir': give each a different name`, `Lee's backup 'sam' is
  not one of the people`, `rule 'Database attacks go to Lee' needs an owner who is one of the people`
  or `follow_up is out of range (1-20 reminders, 0-20 escalations, 0-720 hours)`.
- 503 `could not write the routing file: ...`: the file could not be saved; the old routing stays in use.

## Link personal Telegram chats

A Telegram bot cannot message someone by their `@handle`: the person has to open a private chat with
the bot first. Linking does that once:

1. Someone with dashboard access makes a one-time code for a contact ([`POST /telegram/link-codes`](#post-telegramlink-codes)).
2. The person sends `/link CODE` to the bot in a private chat, or opens the bot's `t.me/<bot>?start=CODE` link.
3. The notifier passes the code and the chat's id to the core ([`POST /telegram/link`](#post-telegramlink)).
   From then on every alert routed to that person also goes to their own chat (`telegram_chat` in
   `deliver_to`).

Links are kept in `core/people/telegram_links.json` in SentrAI's data folder (`SENTRAI_TELEGRAM_LINKS`
changes it), readable by its owner only.

These endpoints belong to the Telegram extension. While Telegram is not added (see
[Extensions](integrations.html)), each of them answers 404
`Telegram is not added. Add it on the dashboard's Extensions page.`, `telegram_linked` is left out of
the routing contacts, and the saved links are kept for when it is added again.

### `POST /telegram/link-codes`

Make a one-time link code for a contact. It works once and for 30 minutes; making a new one for the
same person cancels the old one. Codes are held in memory, so a restart cancels them too. Written
to the audit trail as `telegram_link_code`.

**Body**

```json
{
  "operator": "erick",
  "contact": "amir"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `operator` | string | yes | the name recorded in the audit trail and as `linked_by` |
| `contact` | string | yes | the contact, by id, name, role or Telegram handle, case ignored |

**Returns**

```json
{
  "contact": "amir",
  "name": "Amir",
  "code": "8Y4JVVSJ",
  "expires_at": "2026-10-27T03:15:12+00:00",
  "valid_minutes": 30,
  "send": "/link 8Y4JVVSJ"
}
```

`code` is 8 characters without 0, O, 1, I or L, so it is read off a screen right; `send` is the
message to send the bot.

**Errors**

- 404 `no contact called 'sam' in the routing file`.

### `POST /telegram/link`

Redeem a link code for a private chat. The notifier calls it when the bot receives `/link CODE`; you
do not normally call it yourself. A chat reaches one person only: a chat that was linked to someone
else moves to this contact, and this contact's earlier chat is replaced. Written to the audit trail
as `telegram_linked`.

**Body**

```json
{
  "code": "8Y4JVVSJ",
  "chat_id": 123456789,
  "username": "amir_k"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `code` | string | yes | the code; case, spaces and dashes are ignored |
| `chat_id` | string or integer | yes | the private chat's id: digits, with a leading `-` allowed |
| `username` | string or null | default `""` | the person's Telegram username; a leading `@` is dropped |

**Returns** the link:

```json
{
  "contact_id": "amir",
  "chat_id": "123456789",
  "username": "amir_k",
  "linked_at": "2026-10-27T02:45:12+00:00",
  "linked_by": "erick",
  "name": "Amir",
  "role": "on_duty",
  "replaced": false
}
```

`linked_by` is who made the code; `replaced` is `true` when the contact had another chat before.

**Errors**

- 400 `That code is wrong, already used or expired. Ask for a new one.`: also when `chat_id` is not a number.
- 404 `that contact is no longer in the routing file`: the contact was removed after the code was made.

### `POST /telegram/unlink`

Stop sending a person's alerts to their private chat. Give the chat or the contact; with both, the
chat decides. The notifier calls it with `chat_id` when someone sends the bot `/unlink`. Written to
the audit trail as `telegram_unlinked`.

**Body**

```json
{
  "operator": "erick",
  "contact": "amir"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `operator` | string | yes | the name recorded in the audit trail |
| `contact` | string or null | default `null` | the contact, by id, name, role or Telegram handle |
| `chat_id` | string, integer or null | default `null` | the linked chat |

**Returns**

```json
{
  "contact": "amir",
  "unlinked": true
}
```

**Errors**

- 404 `no linked Telegram chat for that contact`: the contact or chat is unknown, has no link, or
  neither was given. A contact whose routing entry holds a numeric chat id cannot be unlinked here:
  change their `telegram` in the routing file instead.

### `GET /telegram/links`

Every private chat that reaches a contact: the linked chats first, then contacts whose `telegram`
in the routing file is already a numeric chat id (those have `linked_by: "routing file"` and an
empty `linked_at`). The notifier reads it to know where to send direct messages.

**Returns**

```json
[
  {
    "contact_id": "amir",
    "chat_id": "123456789",
    "username": "amir_k",
    "linked_at": "2026-10-27T02:45:12+00:00",
    "linked_by": "erick",
    "name": "Amir",
    "role": "on_duty"
  }
]
```

## The notification record

What every notification endpoint answers with:

```json
{
  "id": "ntf-0001",
  "incident": "RSK-2026-081",
  "kind": "incident_opened",
  "title": "⚠️ RSK-2026-081 · Brute force (web-01, account 'admin') · Risk 53/100",
  "text": "⚠️ RSK-2026-081 · Brute force (web-01, account 'admin') · Risk 53/100\n5 failed logins from 203.0.113.45 against account 'admin' on web-01: a password-guessing (brute force) pattern.\nRecommended: Block 203.0.113.45, lock account 'admin' and rate-limit /login for 2 h.\nOwner: Amir · backup: Lee\nRecord fingerprint: #4 7c95c2493da1be7f",
  "recipients": ["Amir", "Lee"],
  "deliver_to": [
    {"id": "amir", "name": "Amir", "email": "amir@example.com", "telegram": "@amir", "telegram_chat": "123456789"}
  ],
  "owner": "Amir",
  "risk_index": 53,
  "band": "amber",
  "buttons": [
    {"label": "Approve & Patch", "action": "approve"},
    {"label": "Reject with Justification", "action": "reject"},
    {"label": "Acknowledge", "action": "ack"}
  ],
  "report_url": "http://127.0.0.1:8000/reports/RSK-2026-081.md?sig=1d69bc85676e35d2a647e3e8dca27e1b",
  "witness": "SENTRAI-FP v1 seq=4 head=7c95c2493da1be7fd3483cbc732f000fc6b6e2d9ecdfcda1cded70660cdc4946 at=2026-10-27T02:45:11Z sig=af46bbf6ca929217a3a9921414d09cfb",
  "created_at": "2026-10-27T02:45:11+00:00",
  "delivered": false,
  "delivered_at": null,
  "channel": null,
  "message_id": null,
  "deliveries": []
}
```

| Field | Meaning |
| --- | --- |
| `id` | `ntf-<n>`, in the order they were queued |
| `incident` | the incident it is about, or `null` for an alert about SentrAI as a whole (risk band, protection, fingerprint) |
| `kind` | `incident_opened`, `needs_review`, `was_this_you` (root access from an unrecognised sign-in: a person says whether it was them, see [the incident record](incidents.html#the-incident-record)), `escalation` (the index reached red or critical), `escalated` (handed to a backup), `assigned`, `sla_reminder`, `resolve_reminder`, `autonomous_action`, `operator_action`, `needs_operator`, `action_check`, `action_expired`, `undo_failed`, `protection_on`, `protection_off`, `watchdog`, `audit_anchor` or `summary` |
| `title`, `text` | the alert as a person reads it |
| `recipients` | the names it is for |
| `deliver_to` | each recipient's contact from the routing file: `id`, `name`, `email`, `telegram` and `telegram_chat`, the private chat that reaches them (empty when none). A name outside the routing file has an empty `id` and no addresses |
| `owner` | the incident's owner when it was queued, `null` without an incident |
| `risk_index`, `band` | the headline risk index when it was queued |
| `buttons` | the answers to offer under the message: `approve`, `reject` and `ack` for a decision; `rollback`, `permanent` and `ack` after an action. A `was_this_you` alert, and every reminder or escalation about such an incident, carries **This was me** (`mine`), **Not me: block it** (`approve`) and **Acknowledge** (`ack`) instead. The notifier turns them into calls on [Incidents](incidents.html): `mine` is [`POST /incidents/{iid}/mine`](incidents.html#post-incidentsiidmine) |
| `report_url` | a signed link to the incident's evidence report that opens without the token (see [Signed links](index.html#signed-links)); `null` without an incident. It starts with `SENTRAI_PUBLIC_URL` |
| `witness` | the signed fingerprint of the audit trail when it was queued, so each alert is a copy of it the server cannot recall (see [`GET /audit/verify`](audit.html#get-auditverify)) |
| `delivered`, `delivered_at`, `channel`, `message_id` | the first delivery reported, all unset until then |
| `deliveries` | every delivery reported: `channel`, `message_id`, `delivered_at`, `to` |

Queuing an alert is written to the audit trail as `notification_queued` and added to the incident's
timeline.
