---
title: Events and log sources
nav: api
description: Send log events, alerts from other tools and heartbeats to the SentrAI core, and choose which log files the collector reads.
---

# Events and log sources

Everything SentrAI decides starts as an event: one log line, sent to the core. The collector sends
the lines it reads from the logs you approved, each agent does the same for its own machine on a
central panel, and any other tool that can post JSON can send its alerts to the webhook. The
log-source endpoints choose which files the collector reads; the dashboard's **Collector** page
uses them.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Send events in

### `POST /events`

Send one event, or a list of them, to be classified and scored. The collector checks its logs every
50 ms and sends new lines as soon as it finds them, keeping them while the core cannot be reached.
Each event goes through the rules first, then
the TypeSafe "Jev" model when a key is set, then a keyword fallback. An event that looks like an
attack is written to the audit trail as `event_classified` and opens an incident, or joins an open
one about the same address, account or machine. A new incident is written as `incident_opened` and
queues an alert (see [Incidents](incidents.html)).

A machine key may call it ([Machine keys](index.html#machine-keys)). The core then sets `host` to
that machine's own name on every event, whatever the event says.

**Body**: one event, or a list of them.

```json
{
  "event_id": "evt-3f9c2a7d1b04",
  "timestamp": "2026-10-27T10:00:01+08:00",
  "host": "web-01",
  "layer": "web",
  "source": "nginx",
  "src_ip": "203.0.113.45",
  "user": "admin",
  "raw": "POST /login 401 user=admin",
  "asset_criticality": 1.5
}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `event_id` | string | made by the core, `evt-core-` and 12 hex characters | unique id. An event whose id the core already holds is skipped, so sending a batch again after a timeout is safe |
| `timestamp` | string | none | when the line was written, ISO 8601 with an offset. A time without an offset is read as the core's local time; a missing or unreadable one counts as the time the event arrived |
| `host` | string | `unknown` | the machine the line comes from. Incidents and each machine's risk index go by it |
| `layer` | string | `web` | which analyst reads it: `web` (Gatehouse), `db` (Vault), `os` (Garrison), `network` or `cloud` (Watchtower). Any other value is read as `web`; an sshd line sent as `web` is moved to `os` |
| `source` | string | `unknown` | the program or log it came from, such as `nginx` or `sshd`. `heartbeat` makes it a heartbeat (see [`POST /heartbeat`](#post-heartbeat)). `tripwire`, `log_integrity`, `audit_integrity`, `threat_scan` and `staff_report` belong to SentrAI's own checks and are trusted as such: never send them from another tool |
| `src_ip` | string or null | `null` | the address at the other end. Left out, it is read from `raw` for sshd lines and web access lines |
| `user` | string or null | `null` | the account involved. Left out, it is read from `raw` for sshd lines |
| `raw` | string | `""` | the log line as written |
| `asset_criticality` | number | `1.0` | how much the machine or its data matters. An incident's points are multiplied by the highest value among its events. The collector sends 1.5 for database events and 1.0 for the rest |

Any other field is kept with the event. Two of them have a meaning:

- `parsed` is what the collector understood of the line: its `format` (`nginx_access`, `syslog`,
  `journald`, `winevent`, `suricata`, `mysql` and so on), its `kind`, and the fields of that format,
  such as `method`, `path` and `status` for a web request. The rules read it first and fall back to
  `raw`. Every format and field is listed in the
  [contract](https://github.com/RexGuard/SentrAI/blob/main/mvp/CONTRACT.md#parsed-fields-optional-parsed-object-on-an-event).
- `chain` is the line chain, `{"stream", "seq", "prev", "hash"}`, which lets the core notice a
  missing or altered line. `seq` counts up from 1 for each `stream` (one per collector), `prev` is
  the `hash` of the event before it (64 zeros for the first), and

  ```
  hash = sha256(prev + json([event_id, timestamp, host, layer, source, raw]))
  ```

  where the JSON is compact (no spaces) with non-ASCII characters kept as they are. An event that
  does not match its seal, or a gap in `seq`, opens a `log_tampering` incident. The core starts
  trusting a stream at the first event it sees after it starts. Events without `chain` are accepted
  as before. With the off-box copy turned on, sealed events also go to the witness (see
  [What SentrAI sends out](outgoing.html)).

**Returns**

```json
{
  "accepted": 1,
  "risk_index": 28
}
```

`accepted` counts the events that were new to the core; duplicates are left out. The core holds the
latest 20,000 events in memory and saves the ones that belong to an incident with it. `risk_index`
is the headline risk index after this batch, as [`GET /risk`](status.html#get-risk) gives it.

One request waits at most `JEV_BUDGET_S` seconds in all (2 by default) for the Jev model. Events
after that which the rules cannot place go straight to the keyword fallback, so a big batch still
answers quickly.

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"host": "web-01", "source": "sshd", "raw": "Failed password for root from 192.0.2.10 port 4242 ssh2"}' \
  http://127.0.0.1:8000/events
```

The core reads the address (192.0.2.10) and the account (`root`) from the sshd line itself, and
files the event under the `os` layer.

### `POST /webhook/{name}`

Send the alerts of another tool (a WAF, an IDS such as Wazuh, fail2ban, a cloud alert) without
writing a collector for it. Each JSON object in the body becomes one event, handled exactly like one
sent to [`POST /events`](#post-events). Point the tool at `/webhook/<name>` on the core, with the
API token as a header. A machine key cannot call it.

`name` is the tool's name: letters, digits, `-` and `_`, at most 40 characters. It picks the field
map below and goes into every event: `source` is always `webhook_<name>`, so a webhook can never
pass for a heartbeat, a tripwire or one of SentrAI's own checks, and its events never carry a line
chain.

**Query**

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `layer` | string | `web` | the layer for objects that do not name one: `web`, `db`, `os`, `network` or `cloud`. Anything else becomes `web` |
| `host` | string | `webhook-<name>` | the machine for objects that do not name one |

**Body**: a JSON object, a list of objects, or an object holding a list of objects under `events`,
`alerts`, `records`, `items`, `logs` or `data`. At most 500 objects per request. This is an alert
from Wazuh:

```json
{
  "timestamp": "2026-10-27T10:05:00+08:00",
  "agent": {
    "name": "db-01"
  },
  "data": {
    "srcip": "192.0.2.77"
  },
  "rule": {
    "level": 10
  },
  "full_log": "sshd[4242]: Failed password for root from 192.0.2.77 port 51515 ssh2"
}
```

Each field of the event comes from the `<name>` entry of `SENTRAI_WEBHOOK_MAPS` when it has one, and
otherwise from the first of these keys the object has. A dotted key reaches into a nested object
(`agent.name`); a key that itself contains a dot (`host.name`) is tried whole first.

| Event field | Keys tried, in order |
| --- | --- |
| `event_id` | `event_id`, `id`, `_id`, `uuid`, `alert_id`, `eventId` |
| `timestamp` | `timestamp`, `@timestamp`, `time`, `ts`, `date`, `datetime`, `created_at`, `eventTime` |
| `host` | `host`, `hostname`, `host.name`, `agent.name`, `server`, `device`, `computer`, `beat.hostname` |
| `src_ip` | `src_ip`, `source_ip`, `srcip`, `client_ip`, `clientip`, `remote_addr`, `remote_ip`, `ip`, `source.ip`, `client.ip`, `data.srcip`, `sourceIPAddress`, `attacker_ip` |
| `user` | `user`, `username`, `user_name`, `account`, `login`, `user.name`, `actor.login`, `data.dstuser`, `userIdentity.userName` |
| `raw` | `raw`, `message`, `msg`, `log`, `full_log`, `description`, `summary`, `text`, `event.original` |
| `layer` | `layer` |
| `asset_criticality` | `asset_criticality`, `criticality` |

With none of the `raw` keys, `raw` is the whole object as JSON; either way it is cut at 8,000
characters. `asset_criticality` is kept between 0.5 and 3. The event id is `wh-<name>-` followed by
the object's own id or, without one, by a fingerprint of the whole object, so an alert the tool
delivers twice is counted once.

`SENTRAI_WEBHOOK_MAPS` is JSON, or the path of a JSON file, read when the core starts. For each
webhook name it gives event fields a dotted key, a list of keys (the first one present wins) or a
fixed value written as `=value`:

```bash
SENTRAI_WEBHOOK_MAPS='{"wazuh": {"src_ip": "data.srcip", "raw": "full_log", "layer": "=os", "host": "agent.name"}}'
```

**Returns** what `POST /events` returns, plus the id of the event made from each object, in order,
duplicates included:

```json
{
  "accepted": 1,
  "risk_index": 0,
  "events": [
    "wh-wazuh-8ebfae774404204a0ebf"
  ]
}
```

**Errors**

- 400 `the webhook name may use letters, digits, '-' and '_' (at most 40)`: the name in the path has
  other characters or is too long.
- 400 `the body must be a JSON object or a list of objects`: the body is a JSON string, a number or
  similar.
- 400 `at most 500 objects per request`: split the batch.

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"alerts": [{"ip": "203.0.113.99", "message": "Ban 203.0.113.99", "host": "web-01"}]}' \
  "http://127.0.0.1:8000/webhook/fail2ban?layer=os"
```

## Say a collector is alive

### `POST /heartbeat`

Say that a collector is still running. The first heartbeat from a machine puts it under the
watchdog. From then on, when nothing at all arrives from that machine for `WATCHDOG_SILENCE_S`
seconds (30 by default), the core writes `collector_silent` to the audit trail, queues a `watchdog`
alert for the person on duty and shows the machine as `silent` in
[`GET /machines`](status.html#get-machines). The next event or heartbeat from it writes
`collector_recovered`. The collector does the same thing with an event whose `source` is
`heartbeat`, sent to `POST /events` every 10 seconds.

A machine key may call it: the heartbeat then counts for that machine, whatever `collector` says.

**Body**

```json
{"collector": "web-01"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `collector` | string | required | the machine's name, as in the `host` of its events. Still required, but not used, with a machine key |

**Returns**

```json
{"ok": true}
```

## Add log files from a process scan

Besides the demo portal's logs, the collector on the machine the core runs on reads a list of
approved files. A file joins that list only when a person approves it: by its id from a process scan, or from
Scout's proposals below. The list is `lab/scout/sources.json` (`SENTRAI_SCOUT_SOURCES` moves it), and
the collector reads it again while it runs. An agent on another machine keeps its own list; see
[Log sources](../log-sources.html) for adding the usual logs in one go.

### `GET /log-sources`

The approved files, in the order they were added.

**Returns**

```json
[
  {
    "path": "/var/log/nginx/access.log",
    "layer": "web",
    "format": "nginx_access",
    "why": "nginx is running and writes here",
    "found_by": "Scout",
    "confirmed_by": "erick",
    "confirmed_at": "2026-10-27T02:45:12"
  },
  {
    "path": "/var/log/app/app.log",
    "layer": "web",
    "format": "text",
    "why": "found by process scan (app-server)",
    "found_by": "process scan",
    "confirmed_by": "erick",
    "confirmed_at": "2026-10-27T02:45:12"
  }
]
```

- `path` is the file, with a home folder shown as `~`. `journald:<unit>` and `winevent:<channel>`
  stand for the systemd journal and a Windows event log.
- `format` is how the collector reads it, such as `nginx_access`, `syslog`, `journald`, `winevent`,
  `suricata`, `mysql`, `postgres`, `mongodb`, `jsonl` or `text`.
- `found_by` is `process scan` or `Scout`. Files added by the guided setup or by the collector's
  `--add-system-logs` have none, and their `confirmed_by` names that tool.
- `confirmed_at` is the machine's local time, without an offset.

### `POST /log-sources`

Approve one file from the latest process scan ([`POST /system/scan`](scans.html#post-systemscan)),
by its id. Only ids from that scan work, so neither a crafted request nor the AI model can point the
collector at a file of its choosing. The file is added to the list with `found_by` set to
`process scan` (approving it again replaces its entry), the approval is written to the audit trail
as `log_source_added`, and the collector starts reading it within a few seconds.

**Body**

```json
{"operator": "erick", "file_id": "s1f1", "layer": "web"}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | required | who approves it |
| `file_id` | string | required | a file's `id` in the scan's `suggestions[].files`, such as `s1f1` |
| `layer` | string | the suggestion's `layer` | `web`, `db`, `os`, `network` or `cloud` |

**Returns**

```json
{
  "ok": true,
  "file": "/var/log/app/app.log",
  "layer": "web",
  "watching": 2,
  "note": "The collector picks this up within a few seconds."
}
```

`watching` is how many files are on the list now.

**Errors**

- 404 `s7f1 is not in the latest scan; scan again`: no such id in the latest scan. Scans are kept in
  memory only, so this also happens after the core restarts.
- 409 `layer must be one of web, db, os, network, cloud`.
- 409 `that file no longer exists; scan again`.

## Answer Scout's proposals

Scout, SentrAI's log finder (`python -m scout find` in `mvp/lab`), looks through the folders for log
files. When no technician is at the keyboard, it decides on its own and leaves what it found waiting
for a person, in `pending.json` beside the list (`SENTRAI_SCOUT_PENDING` moves it).

### `GET /log-sources/pending`

The proposals waiting for a yes or no.

**Returns**

```json
[
  {
    "id": "p4c1d9e07a2",
    "layer": "web",
    "format": "nginx_access",
    "why": "nginx is running and writes here",
    "goal": "web and login logs",
    "proposed_at": "2026-10-27T09:00:00",
    "path": "/var/log/nginx/access.log",
    "name": "access.log"
  }
]
```

`id` is `p` and 10 hex characters, the same for the same file every time. `layer` and `format` are
how Scout suggests reading it, `why` is its reason, and `goal` is what it was asked to find.
`proposed_at` is the machine's local time, without an offset.

### `POST /log-sources/pending/{pid}`

Approve or reject one proposal by its id. Approving adds the file to the list with `found_by` set to
`Scout`, and the collector starts reading it within a few seconds; rejecting drops it. Either way the
proposal leaves the waiting list, and the answer is written to the audit trail as `log_source_added`
or `log_source_rejected`.

**Body**

```json
{"operator": "erick", "approve": true}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | required | who answers |
| `approve` | boolean | required | `true` to read the file, `false` to drop the proposal |
| `layer` | string | the proposal's `layer` | `web`, `db`, `os`, `network` or `cloud`; checked only when approving |
| `reason` | string | `""` | why, kept in the audit trail |

**Returns**

```json
{
  "ok": true,
  "file": "access.log",
  "layer": "web",
  "approved": true,
  "note": "The collector picks this up within a few seconds."
}
```

After a rejection `approved` is `false` and `note` is `Dropped.`.

**Errors**

- 404 `p4c1d9e07a2 is not a pending Scout proposal`: no proposal has that id, or it was answered
  already.
- 409 `layer must be one of web, db, os, network, cloud`.
- 409 `that file no longer exists; reject it or run Scout again`.

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick", "approve": true}' \
  http://127.0.0.1:8000/log-sources/pending/p4c1d9e07a2
```
