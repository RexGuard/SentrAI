---
title: Central panel and agents
nav: api
description: Join machines to the central panel with a one-time code, manage their machine keys, and send scans and backups to them.
---

# Central panel and agents

When SentrAI runs as a central panel, each protected machine runs an agent. A machine joins with a
one-time **join code** made on the panel and gets its own **machine key** (`sa_...`) in return. The
agent uses that key to send its events, report what runs on it, pick up jobs and report back after
working offline. The operator calls on this page are what the dashboard's Machines page uses.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.
The ones marked **agent** also answer a machine key, for that machine only (see
[Machine keys](index.html#machine-keys)).

## Join a machine

### `POST /fleet/join-codes`

Makes a one-time join code. It is shown only here, once: the panel keeps just a hash of it. A code
works for 24 hours and for one machine. Written to the audit trail (`join_code_created`).

**Body**

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `operator` | string | `operator` | who made the code |
| `name` | string | none | the name the machine will get, instead of the one its agent sends (letters, digits, `.`, `-`, `_`, up to 63) |

```json
{"operator": "erick", "name": "office-pc"}
```

**Returns** the code with what a new machine needs to reach the panel (see `GET /fleet/panel`).

```json
{
  "code": "VGT7-6ULJ-J3C4",
  "expires_at": "2026-10-28T02:45:12+00:00",
  "name": "office-pc",
  "panel_url": "https://panel.example.com:8443",
  "pin": "sha256:..."
}
```

**Errors**: `400` `machine names use letters, digits, dot, dash and underscore (up to 63)`.

### `GET /fleet/panel`

The address and certificate pin new machines use to reach this panel, from `SENTRAI_PANEL_URL` and
`SENTRAI_PANEL_CERT`. Both are empty strings when they are not set.

**Returns**: `{"panel_url": "https://panel.example.com:8443", "pin": "sha256:..."}`

### `POST /fleet/enrol`

**Open: no token needed.** A new machine swaps its join code for a machine key. The installer does
this for you (`install-agent.sh --code` or `install-agent.ps1`). The code is used up. Written to the
audit trail (`machine_joined`).

**Body**

| Field | Type | Meaning |
| --- | --- | --- |
| `code` | string, required | the join code; dashes and letter case do not matter |
| `host` | string, required | the machine's name; ignored when the code fixed one |

```json
{"code": "VGT7-6ULJ-J3C4", "host": "DESKTOP-7F3K"}
```

**Returns**

```json
{
  "agent_id": "7d21e8c6d783",
  "host": "office-pc",
  "key": "sa_7d21e8c6d783.<secret>",
  "risk_scope": "fleet"
}
```

`key` is shown only here; keep it on the machine (the installer saves it readable by the agent only).
`risk_scope` says whether the risk index is counted per machine (`host`) or for the whole fleet (`fleet`).

**Errors**

| Status | `detail` |
| --- | --- |
| `400` | `machine names use letters, digits, dot, dash and underscore (up to 63)` |
| `403` | `join code is wrong, used or expired; make a new one on the panel` |
| `409` | `a machine named 'office-pc' has already joined; revoke it on the panel first or join with another --name` |
| `429` | `too many wrong join codes; try again in a few minutes` (after 10 wrong codes in 10 minutes) |

## Manage machines

### `GET /fleet/agents`

Every machine that has joined, revoked ones included.

**Returns**

```json
[
  {
    "agent_id": "7d21e8c6d783",
    "host": "office-pc",
    "joined_at": "2026-10-27T02:45:12+00:00",
    "invited_by": "erick",
    "last_seen": "2026-10-27T02:50:01+00:00",
    "revoked_at": null,
    "revoked_by": null
  }
]
```

A machine that has sent an offline report also has `offline` (its last report, as
`POST /fleet/offline-report` returns it) and `offline_total` (how many it has sent).

### `POST /fleet/agents/{agent_id}/revoke`

Revokes a machine's key at once: its next call gets `401`
`unknown or revoked machine key: join the panel again`. Jobs still waiting for it are dropped. Written
to the audit trail (`machine_revoked`).

**Body**: `{"operator": "erick"}` (`operator` defaults to `operator`).

**Returns** the machine's record, as in `GET /fleet/agents`, now with `revoked_at` and `revoked_by`.

**Errors**: `404` `no machine with id 7d21e8c6d783`.

### `GET /fleet/me`

**Agent.** Which machine a key belongs to. Agents call it to check their key works.

**Returns**: `{"agent_id": "7d21e8c6d783", "host": "office-pc", "risk_scope": "fleet"}`

**Errors**: `400` `only a machine's agent key has a /fleet/me` (called with the API token).

### `POST /fleet/services`

**Agent.** What runs on a machine: its agent reports this every minute, and the Machines page shows
it next to the machine's open incidents. Each report replaces the last one.

**Query**

| Name | Type | Meaning |
| --- | --- | --- |
| `host` | string | the machine, when called with the API token; a machine key always reports for itself |

**Body**: `services`, a list of up to 200 entries.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string, required | the service, up to 64 characters |
| `port` | integer | the port it listens on, 0 to 65535 |
| `proto` | string | `tcp` or `udp` |
| `process` | string | the program's name |

```json
{"services": [{"name": "nginx", "port": 443, "proto": "tcp", "process": "nginx"},
              {"name": "sshd", "port": 22, "proto": "tcp", "process": "sshd"}]}
```

**Returns**: `{"ok": true, "services": 2}`

**Errors**: `400` `which machine? (?host=)` (API token with no `host`).

## Send a job to a machine

A job asks a machine to run a threat scan or take a backup of its own folders. The panel only queues
it; the machine's agent picks it up, runs it and reports the result. A job nobody picks up in 24 hours
is dropped, and one that never reports back within 3 hours is marked failed. The last 20 finished jobs
per machine are kept.

### `POST /fleet/jobs`

Queues a job. Written to the audit trail (`machine_job_queued`).

**Body**

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `host` | string, required | | a joined machine |
| `kind` | string, required | | `threat_scan` or `backup` |
| `operator` | string | `operator` | who asked |

```json
{"host": "office-pc", "kind": "threat_scan", "operator": "erick"}
```

**Returns** the job.

```json
{
  "id": "j-f7d2dc41",
  "host": "office-pc",
  "kind": "threat_scan",
  "status": "queued",
  "requested_by": "erick",
  "created_at": "2026-10-27T02:45:12+00:00",
  "started_at": null,
  "finished_at": null,
  "result": null,
  "error": null,
  "summary": "waiting for the machine to pick it up"
}
```

`status` is `queued`, `running`, `done`, `failed` or `cancelled`. `summary` says it in a sentence.

**Errors**

| Status | `detail` |
| --- | --- |
| `400` | `unknown job 'format_disk'; use one of: threat_scan, backup` |
| `404` | `no joined machine named 'nope'` |
| `409` | `a threat scan is already queued on office-pc (j-f7d2dc41)` |

### `GET /fleet/jobs`

Jobs, newest first.

**Query**

| Name | Type | Meaning |
| --- | --- | --- |
| `host` | string, up to 63 characters | only this machine's jobs |

**Returns** a list of jobs, as `POST /fleet/jobs`.

### `POST /fleet/jobs/{job_id}/cancel`

Cancels a job that is still waiting. One the machine has started cannot be cancelled.

**Body**: `{"operator": "erick", "justification": "wrong machine"}` (`justification` is optional).

**Returns** the job, now `cancelled`, with `error` and `summary` `cancelled by erick`.

**Errors**: `404` `no job j-2a2efdf4`; `409` `job j-2a2efdf4 is running; only a job still waiting can be cancelled`.

### `GET /fleet/jobs/next`

**Agent.** The next job for this machine, which is marked `running`. Agents ask every minute.

**Returns**: `{"job": {"id": "j-f7d2dc41", "kind": "threat_scan"}}`, or `{"job": null}` when there is none.

**Errors**: `400` `only a machine's agent key picks up jobs`.

### `POST /fleet/jobs/result`

**Agent.** The machine reports how a job went. A threat scan's findings raise "Malware found" alerts
on the panel, as a [local threat scan](scans.html#post-threatsscan) does; a failed backup alerts the
person on duty. Written to the audit trail (`machine_job_done` or `machine_job_failed`).

**Body**

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string, required | the job |
| `ok` | boolean, required | whether it worked |
| `result` | object | what the scan or backup returned (cleaned and size-limited on the panel) |
| `error` | string | why it failed, up to 2000 characters |

```json
{
  "id": "j-f7d2dc41",
  "ok": true,
  "result": {
    "roots": ["~/site"],
    "files_checked": 120,
    "counts": {"critical": 1, "high": 0, "medium": 0},
    "took_s": 0.8,
    "findings": [{"path": "~/site/uploads/img.php", "line": 1, "kind": "web_shell", "severity": "critical",
                  "label": "PHP web shell", "key": "php_eval", "sha256": "abab...", "snippet": "@eval($_POST['cmd'])"}]
  }
}
```

The `result` fields are those of [`POST /threats/scan`](scans.html#post-threatsscan) or
[`POST /backups`](scans.html#post-backups).

**Returns**: `{"ok": true, "status": "done", "new_alerts": 1}`

**Errors**: `400` `only a machine's agent key reports a job`; `404` `no job j-f7d2dc41 for this machine`;
`409` `job j-f7d2dc41 is done, not running`.

## Working offline

### `POST /fleet/offline-report`

**Agent.** A machine that could not reach the panel keeps protecting itself with local rules. When it
is back it sends the logs it held through [`POST /events`](events.html#post-events) as usual, and this
report of what it decided alone. Each local block is written to the audit trail (`agent_local_block`),
with a summary (`agent_offline_report`), and the person on duty is alerted when it blocked anything.
The blocks expire on the machine by themselves.

**Body**

| Field | Type | Meaning |
| --- | --- | --- |
| `from`, `to` | string | when the panel was out of reach |
| `scored` | integer | how many events the agent scored alone |
| `actions` | list, up to 500 | each local block, below |

Each action: `ip` (required), `category` (required), `reason`, `score`, `at`, `until`, `applied`
(whether the block took effect) and `event_ids` (up to 50).

```json
{
  "from": "2026-10-27T01:00:00+00:00",
  "to": "2026-10-27T01:40:00+00:00",
  "scored": 312,
  "actions": [{"ip": "192.0.2.10", "category": "brute_force", "reason": "9 failed SSH logins in 2 minutes",
               "score": 0.92, "at": "2026-10-27T01:12:00+00:00", "until": "2026-10-27T03:12:00+00:00",
               "applied": true, "event_ids": ["evt-a1", "evt-a2"]}]
}
```

**Returns**

```json
{
  "ok": true,
  "from": "2026-10-27T01:00:00+00:00",
  "to": "2026-10-27T01:40:00+00:00",
  "scored": 312,
  "local_blocks": 1,
  "reported_at": "2026-10-27T02:45:12+00:00"
}
```

**Errors**: `400` `only a machine's agent sends an offline report`.
