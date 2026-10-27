---
title: Risk and protection
nav: api
description: Read the risk index for all machines or one, switch SentrAI's protection on and off, and read the list of blocked addresses and accounts.
---

# Risk and protection

These endpoints answer "how bad is it right now, and is SentrAI allowed to act?". The dashboard's
overview reads the risk index, each machine and the protection switch from here; the lab website,
a proxy or an agent on another machine reads the block list to refuse blocked addresses and
accounts.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Check that the core is up

### `GET /health`

Answers as soon as the core is running. The launchers and your own monitoring use it as a readiness
check. Open: no token needed (see [Open endpoints](index.html#open-endpoints)).

**Returns**

```json
{
  "ok": true
}
```

```bash
curl http://127.0.0.1:8000/health
```

## Read the risk index

The risk index runs from 0 to 100. SentrAI adds up the points of every incident that is still
`open` or `acknowledged` (see the `contribution` field of [the incident record](incidents.html#the-incident-record))
into a raw score, and turns it into the index with `100 × (1 − e^(−raw / 60))`. The index then falls
in a band:

| Band | Index |
| --- | --- |
| `green` | 0 to 29 |
| `amber` | 30 to 59 |
| `red` | 60 to 79 |
| `critical` | 80 to 100 |

When the index reaches the threshold (`RISK_THRESHOLD`, 80 by default), SentrAI may contain open
incidents on its own, within the [limits](#get-limits).

`SENTRAI_RISK_SCOPE` decides how machines count. In `fleet` scope (the default, as on a single
server) every machine's incidents add up into one score. In `host` scope, which a central panel
uses, each machine is scored on its own and the headline index is the worst machine's, so an attack
on one machine never blocks traffic on another.

### `GET /risk`

The headline risk index with its recent history, or one machine's own with `?host=`. The dashboard
polls it for the gauge and the chart.

**Query**

- `history` (integer, default 600, 0 to 3600): how many of the newest history points to return.
  The core adds a point every second (`TICK_S`) and after each batch of events, and keeps the last
  3,600. `0` returns an empty list.
- `host` (string, optional): one machine's own index, incidents and history, by the name in
  [`GET /machines`](#get-machines). A name the core has never heard of answers with an index of 0
  and an empty history.

**Returns**

```json
{
  "risk_index": 83,
  "band": "critical",
  "raw_score": 106.2,
  "threshold": 80,
  "risk_scope": "fleet",
  "open_incidents": ["RSK-2026-082"],
  "needs_review": [],
  "contained_incidents": ["RSK-2026-081"],
  "monitor_only": false,
  "demo_speed": 1.0,
  "demo_hours_elapsed": 0.0,
  "timestamp": "2026-10-27T02:45:11+00:00",
  "history": [
    {"t": "2026-10-27T02:45:11+00:00", "risk_index": 83, "raw": 106.2, "band": "critical"}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `raw_score` | the sum of the incidents' contributions before it is turned into the index |
| `threshold` | the index at which SentrAI may contain on its own (`RISK_THRESHOLD`) |
| `risk_scope` | `fleet` or `host`, see above |
| `open_incidents` | incidents still counting: `open` or `acknowledged` |
| `needs_review` | those of them the classifier was unsure about, which SentrAI never contains on its own |
| `contained_incidents` | incidents whose actions were put in force |
| `monitor_only` | `true` while protection is off (see [`GET /protection`](#get-protection)) |
| `demo_speed`, `demo_hours_elapsed` | the timer speed (`DEMO_SPEED`, 1.0 is real time; higher speeds up the timers for testing) and the timer hours since the core started |
| `history` | oldest first: `t`, `risk_index`, `raw` and `band` at each point |
| `host` | only with `?host=`: the machine asked about |

```bash
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/risk?host=web-01&history=60"
```

### `GET /machines`

Every machine SentrAI has heard from or opened an incident for, each with its own score, worst
first (ties by name). The dashboard's machine list and a central panel's overview read it.

**Returns**

```json
[
  {
    "host": "web-01",
    "risk_index": 53,
    "band": "amber",
    "raw_score": 45.0,
    "open_incidents": 1,
    "contained_incidents": 1,
    "blocked": 2,
    "last_seen": "2026-10-27T02:45:11+00:00",
    "silent": false,
    "services": [
      {"name": "nginx", "port": 443, "proto": "tcp", "process": "nginx", "open_incidents": 1}
    ],
    "services_at": "2026-10-27T02:45:00+00:00",
    "hardware": {"cpu": {"percent": 12.5, "cores": 4}, "memory": {"percent": 41.0}, "at": "2026-10-27T02:45:20+00:00",
                 "warnings": []}
  }
]
```

| Field | Meaning |
| --- | --- |
| `risk_index`, `band`, `raw_score` | the machine's own score, counted as in `host` scope whatever `SENTRAI_RISK_SCOPE` says |
| `open_incidents`, `contained_incidents` | how many of its incidents are counting, and how many are contained |
| `blocked` | how many addresses its [block list](#get-blocklist) holds |
| `last_seen` | when its last event or heartbeat arrived since the core started, `null` when only an incident names it |
| `silent` | `true` when its collector sent no heartbeat for `WATCHDOG_SILENCE_S` seconds (30 by default) |
| `services` | what runs on it, as its agent reported through [`POST /fleet/services`](fleet.html#post-fleetservices), each with the number of open incidents about it. A service that only an incident names is listed with `null` port, protocol and process |
| `services_at` | when the agent last reported its services, `null` if it never did |
| `hardware` | its agent's latest hardware reading, as in [`GET /fleet/hardware`](fleet.html#get-fleethardware) `latest`; `null` until one arrives |

## Switch protection on and off

Protection is on by default. Turned off, SentrAI is in **monitor-only** mode: it keeps collecting,
classifying and scoring, but applies no containment, autonomous or approved. Actions already in
force stay until they expire or are rolled back.

### `GET /protection`

Whether protection is on, who last changed it and why.

**Returns**

```json
{
  "protection": "off",
  "monitor_only": true,
  "changed_at": "2026-10-27T02:45:12+00:00",
  "changed_by": "erick",
  "reason": "Load test tonight",
  "active_actions": ["act-0001", "act-0002"]
}
```

| Field | Meaning |
| --- | --- |
| `protection`, `monitor_only` | `on` and `false`, or `off` and `true` |
| `changed_at`, `changed_by`, `reason` | the last switch; all `null` when it was never switched. When `SENTRAI_MONITOR_ONLY` set it at start, `changed_by` is `SENTRAI_MONITOR_ONLY` and `reason` is `set in the environment` |
| `active_actions` | the ids of the protective actions in force now (see the `actions` table in [the incident record](incidents.html#the-incident-record)) |

### `POST /protection`

Turn protection on or off. Turning it off needs a reason. The setting is saved in `protection.json`
next to the audit database and kept across restarts; `SENTRAI_MONITOR_ONLY=1` or `0` overrides it
when the core starts.

A switch is written to the audit trail as `protection_changed`, with the actions left in force, and
added to the timeline of every incident that is still counting. It queues an alert: `protection_off`
to the on-duty person, the IT manager and the CXO, or `protection_on` to the on-duty person and the
IT manager. Asking for the state it is already in changes nothing and records nothing.

While protection is off, each containment SentrAI would have applied is written as
`containment_skipped`, and approving an incident answers 409 (see
[`POST /incidents/{iid}/decision`](incidents.html#post-incidentsiiddecision)).

**Body**

```json
{
  "operator": "erick",
  "on": false,
  "reason": "Load test tonight"
}
```

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `operator` | string | yes | the name recorded in the audit trail and in the alert |
| `on` | boolean | yes | `true` turns protection on, `false` turns it off |
| `reason` | string or null | needed to turn it off, default `null` | why; spaces at either end are dropped |

**Returns** the new state, as [`GET /protection`](#get-protection).

**Errors**

- 400 `turning protection off requires a reason`: `on` is `false` and `reason` is missing or blank.

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick", "on": false, "reason": "Load test tonight"}' \
  http://127.0.0.1:8000/protection
```

### `GET /limits`

The business limits on protective actions as in force now: which types SentrAI may take on its own,
how long each lasts and how many it may take in an hour. The dashboard's settings page shows them.
They are set in the environment; nothing here changes them.

**Returns**

```json
{
  "auto_actions": ["block_ip", "rate_limit", "waf_rule"],
  "needs_a_person": ["kill_process", "lock_user", "revoke_public_acl"],
  "ttl_hours": {
    "block_ip": 2.0,
    "lock_user": 2.0,
    "rate_limit": 2.0
  },
  "max_ttl_hours": 24.0,
  "max_auto_actions_per_hour": 10,
  "auto_actions_last_hour": 4,
  "permanent_needs_a_person": true,
  "check_after_min": 10.0,
  "health_url_set": false
}
```

| Field | Meaning |
| --- | --- |
| `auto_actions` | action types SentrAI may take on its own (`AUTO_ACTIONS`, default `block_ip,rate_limit,waf_rule`), among those a responder can carry out |
| `needs_a_person` | the other types: they wait for a person to approve them |
| `ttl_hours` | how long a temporary action of each type lasts: `ACTION_TTL_HOURS` per type (such as `lock_user=1,block_ip=4`), else `HOTPATCH_TTL_HOURS` (2), never more than `max_ttl_hours` |
| `max_ttl_hours` | the longest any temporary action may last (`MAX_TTL_HOURS`) |
| `max_auto_actions_per_hour`, `auto_actions_last_hour` | the budget of automatic actions in any rolling hour (`MAX_AUTO_ACTIONS_PER_HOUR`, 0 means none on its own) and how many were taken in the last hour; past it a person decides |
| `permanent_needs_a_person` | always `true`: only a person makes an action permanent |
| `check_after_min` | minutes after an action starts when SentrAI checks it worked and did no harm (`CHECK_AFTER_MIN`) |
| `health_url_set` | whether `SENTRAI_HEALTH_URL` is set, a page that should keep answering while SentrAI blocks things; the after-action check probes it |

## Read the block list

### `GET /blocklist`

The addresses and accounts blocked right now: every `block_ip` and `lock_user` action in force. A
website or proxy in front of your service polls it and refuses what it lists (the lab website polls
every 2 seconds and lets traffic through while the core is down); on a central panel each agent
polls it to put its own machine's blocks in place.

Open without `?host=`: no token needed, since it lists nothing else (see
[Open endpoints](index.html#open-endpoints)). With `?host=` it needs the token or that machine's
key. A machine key may call it, for its own machine only ([Machine keys](index.html#machine-keys)):
the core then answers for the key's own machine, whether or not `?host=` is given.

**Query**

- `host` (string, optional): only the blocks this machine must put in place. In `host` scope that
  means the confirmed `block_ip` and `lock_user` actions taken for that machine's incidents. In
  `fleet` scope every machine guards against every block, so the answer is the full list whatever
  the host.

**Returns**

```json
{
  "ips": ["203.0.113.45"],
  "users": ["admin"]
}
```

`ips` and `users` are sorted; both are empty lists when nothing is blocked.

**Errors**

- 401 `missing or wrong API token (python sentrai_config.py token shows it)`: `?host=` was given
  without the token or a machine key.
- 401 `unknown or revoked machine key: join the panel again`: the machine key is not known.
- 403 `a machine key only sends its own events and reads its own block list`: a machine key asked
  with `?host=` naming another machine.

```bash
curl "http://127.0.0.1:8000/blocklist"
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/blocklist?host=web-01"
```

## See what each part of SentrAI is doing

### `GET /agents`

The parts of SentrAI that read events and act on them, each with its role and how much it has done.
The dashboard's **Agents** page shows it. The list is in a fixed order; the first entry is the
orchestrator (`Cyanide`, or `Warden` when `SENTRAI_ENGINE=saguaro` keeps the fixed playbooks), and
`Planner` appears only with `Cyanide`.

**Returns**, trimmed:

```json
[
  {
    "name": "Gatehouse",
    "role": "web layer: web/WAF logs, proposes WAF rules",
    "can_execute": false,
    "analyzed": 7
  },
  {
    "name": "Watchdog",
    "role": "collector heartbeats; flags silent collectors",
    "can_execute": false,
    "collectors": [
      {"collector": "web-01", "silent": false, "last_seen_ts": 1793069111.9793544}
    ]
  },
  {
    "name": "Jev",
    "role": "TypeSafe System One classifier",
    "status": "disabled: TYPESAFE_API_KEY not set (fallback classifier in use)",
    "calls": 0,
    "failures": 0,
    "last_error": null,
    "cache": {"size": 0, "max": 2048, "hits": 0, "misses": 0}
  },
  {
    "name": "Planner",
    "role": "Cyanide's AI model (system-aware containment plans)",
    "status": "off (CYANIDE_ENABLED=0 turns the AI model off); playbooks only",
    "calls": 0,
    "failures": 0,
    "last_error": null,
    "profile": "none"
  }
]
```

| Field | Meaning |
| --- | --- |
| `name`, `role` | which part it is: `Cyanide` (orchestrator), `Gatehouse` (web), `Vault` (databases), `Watchtower` (network), `Garrison-Linux` and `Garrison-Win` (machines), `Countersign` (the safety check that approves every action SentrAI takes on its own), `Watchdog`, `Scribe` (the audit trail), `HelpDesk`, `Jev` and `Planner` |
| `can_execute` | whether it may carry out actions itself; only the Garrison parts can |
| `analyzed` | the layer parts only: events it has read since the core started |
| `collectors` | `Watchdog` only: each collector, whether it has gone silent, and when it last sent anything, as Unix seconds |
| `status`, `calls`, `failures`, `last_error` | `Jev` and `Planner`: whether the AI model is in use, and how its calls went |
| `cache` | `Jev` only: the classification cache, its size, limit, hits and misses |
| `profile` | `Planner` only: the organisation in the system profile the plans are made for, `none` without one |
