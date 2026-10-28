---
title: Incidents
nav: api
description: Read the incidents SentrAI opened, record what people decide about them, and take in what staff report.
---

# Incidents

An incident is one attack or problem SentrAI found: what it was, how many risk points it adds, what
SentrAI did about it and everything that happened since. These endpoints read incidents and record what
people decide about them; staff reports let anyone at the business describe something odd in their own
words, for a person to review. The dashboard's Incidents, Approvals and Staff reports pages use them,
and so do the notifier's Telegram buttons and its `/report` command.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Read incidents

### `GET /incidents`

Every incident, oldest first, as a list of [incident records](#the-incident-record). The numbers that
grow with time (`inaction_penalty`, `time_unaddressed_hours`, `sla_breached`) are brought up to date on
every call.

**Query**: `host` (string, optional): only the incidents on this machine, such as `web-01`; `unknown`
gives the ones with no host. Without it, every machine's.

### `GET /incidents/{iid}`

One [incident record](#the-incident-record), brought up to date the same way.

**Errors**: 404 `incident RSK-2026-999 not found`.

### `GET /incidents/{iid}/why`

The incident in plain text, one line each: why it was opened, how its points were worked out, who
acknowledged it, each action with its status and end time, what SentrAI recommends and how to undo it.

**Returns**

```json
{
  "incident": "RSK-2026-081",
  "answer": "RSK-2026-081 (brute_force, high) was opened at 2026-10-27T02:45:11+00:00.\nWhy: 5 failed logins from 203.0.113.45 against account 'admin' on web-01: a password-guessing (brute force) pattern.\nClassified by rules with AI confidence 1.0 -> 45.0 points (base 30 x confidence x asset criticality 1.5), plus inaction penalty 0.0.\nNobody has acknowledged it yet.\nAction act-0001: block_ip 203.0.113.45 approved by Countersign (autonomous, two-key approval), status active, expires 2026-10-27T04:45:11+00:00.\n...\nTo undo: POST /incidents/RSK-2026-081/rollback with a justification."
}
```

**Errors**: 404 `incident RSK-2026-999 not found`.

### `GET /helpdesk/why`

"Why is this blocked?" for one address, account, path or rule, when someone says they cannot reach the
site: the explanation above for every incident with an action on that target, whatever its status now.

**Query**: `target` (string, required): the target exactly as the action names it, such as
`203.0.113.45`, `admin` or `/login`.

**Returns** the incidents and their explanations, separated by a blank line. When no action ever had
that target there is no `incidents` list, and `answer` says `192.0.2.77 is not in any SentrAI containment record.`

```json
{"target": "203.0.113.45", "incidents": ["RSK-2026-081"], "answer": "RSK-2026-081 (brute_force, high) was opened at ..."}
```

```bash
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/helpdesk/why?target=203.0.113.45"
```

### `GET /waves`

Waves, newest first. A wave is many addresses doing the same kind of attack (a scan, password
guessing) to one machine within a few minutes, the background noise of a public game server or a big
network. Each address keeps its own incident, which carries the wave's `id` in its `wave` field; the
wave counts on the risk index about as much as its worst incident, and its alerts arrive as one
summary every few minutes. Waves are on with `BUSY_SERVER=on` (or `WAVE_MIN_ADDRESSES`), see
[Busy servers](../settings.html#busy-servers).

**Returns**

```json
[
  {
    "id": "WAVE-001",
    "host": "game-01",
    "category": "port_scan",
    "addresses": 312,
    "incidents": ["RSK-2026-081", "RSK-2026-082"],
    "networks": [{"network": "45.0.1.0/24", "addresses": 120}],
    "started_at": "2026-10-28T14:02:11+08:00",
    "last_seen_at": "2026-10-28T14:31:40+08:00",
    "active": true,
    "updates_sent": 2
  }
]
```

## Decide what happens next

Each of these answers with the updated [incident record](#the-incident-record) and adds a line to its
`timeline`. `operator` is the name recorded on the incident and in the audit trail (see
[Conventions](index.html#conventions)). Decision, This was me, rollback and permanent also acknowledge
the incident if nobody had, with their own name as the channel.

### `POST /incidents/{iid}/ack`

Say that a person has seen the incident. Its inaction penalty stops growing, reminders and escalation
stop, and SentrAI no longer contains it on its own; instead the owner is reminded to resolve it every
24 hours (`resolve_within_hours` in the routing file), at most three times. An `open` incident becomes
`acknowledged`; a `contained` one stays so. Written to the audit trail as `acknowledged`, with the
penalty at that moment. A second acknowledgement changes nothing.

**Body**

```json
{"operator": "erick", "channel": "dashboard"}
```

- `operator` (string, required): who acknowledged it.
- `channel` (string, default `dashboard`): where, shown in the evidence report; the notifier sends `telegram`.

**Returns** the incident with `acked` true and `acked_by`, `acked_at` and `ack_channel` set.

**Errors**: 404 `incident RSK-2026-999 not found`.

### `POST /incidents/{iid}/decision`

A person's answer to an incident, as the Approve and Reject buttons on the dashboard and in Telegram
send it. Written to the audit trail as `decision`.

- `approve` puts the recommended steps in force now, as actions with `mode` `operator` and the
  operator as `approved_by`, for the usual [time limit](../settings.html#limits-on-automatic-actions).
  The safety check (Countersign) still drops any step outside the allowlist or aimed at a protected
  address or account (`needle_review` in the audit trail); each step applied is `action_applied`.
  The incident becomes `contained` and an `operator_action` alert is queued. When containment is
  already in force, approving only records that a person endorsed it; when no allowed step applies,
  as for a staff report, nothing is applied and the timeline says so.
- `reject` closes the incident as not a real threat: every action still in force is undone
  (`action_rolled_back`), the status becomes `rejected` and `closed_at` is set.

**Body**

```json
{"operator": "erick", "decision": "approve", "justification": "Clear SQL injection from one address"}
```

- `operator` (string, required): who decided.
- `decision` (string, required): `approve` or `reject`; case and spaces around it are ignored.
- `justification` (string, optional): why, kept in `decisions` and the audit trail. Required to reject.

**Returns** the incident, with the decision added to `decisions`.

**Errors**

- 400 `decision must be 'approve' or 'reject'`, or `reject requires a justification`.
- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-082 is already resolved` (or `rejected`) when it is closed, or, when you approve while
  nothing is in force and [protection](status.html#post-protection) is off,
  `Protection is off (monitor-only mode), so an approved hotpatch is not applied. Turn protection back on first.`

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick", "decision": "reject", "justification": "Our own load test"}' \
  http://127.0.0.1:8000/incidents/RSK-2026-082/decision
```

### `POST /incidents/{iid}/mine`

"This was me": the root work behind a **Root access from an unrecognised sign-in** incident (category
`unauthorised_admin`, see [the incident record](#the-incident-record)) was the administrator's own. The
dashboard's **This was me** button and the Telegram button of the same name send it. SentrAI then:

- learns the sign-in: its address, its SSH key fingerprint and its account on that machine become a
  known administrator's (`how: taught` in [`GET /admins`](status.html#get-admins)), so the next root
  command from the same sign-in is recorded as admin activity instead of raised. An address that was
  suspect after password guessing is trusted again.
- undoes any block or lock the incident had put in force (`action_rolled_back`, with the reason
  `the sign-in was the administrator's own`), for instance after **Not me** was pressed by mistake.
- closes the incident as `resolved`, with the operator as `resolved_by` and `mine` in `decisions`,
  and closes the same person's other open incidents on that machine with it: the ones from the same
  sign-in, or from the same address or account when the incident is about the machine itself.
- writes `admin_confirmed` to the audit trail and the incident's timeline.

It is meant for a root-access incident. The core accepts it on any incident that is not closed and
learns that incident's address and account, so never answer it for an incident you do not
recognise. It is refused while `ADMIN_SESSIONS` is off.

**Body**

```json
{"operator": "erick", "channel": "dashboard"}
```

- `operator` (string, required): who said so. Recorded on the incident, and as who taught the sign-in.
- `channel` (string, default `dashboard`): where, kept in the audit record; the notifier sends `telegram`.

**Returns** the incident, now `resolved`, plus what was learned and what else was closed:

```json
{
  "id": "RSK-2026-091",
  "category": "unauthorised_admin",
  "status": "resolved",
  "resolved_by": "erick",
  "resolution": "This was me (erick): address 203.0.113.5, SSH key SHA256:Q7w3cZk2u5Yd…, account erick on web-01",
  "learned": ["address 203.0.113.5", "SSH key SHA256:Q7w3cZk2u5Yd…", "account erick on web-01"],
  "also_closed": ["RSK-2026-092"],
  "...": "..."
}
```

`learned` is empty, and the resolution says `nothing new to learn`, when SentrAI knew every part of
the sign-in already.

**Errors**

- 400 `ADMIN_SESSIONS is off: SentrAI is not keeping track of the administrators`.
- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-091 is already resolved` (or `rejected`).

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operator": "erick", "channel": "telegram"}' \
  http://127.0.0.1:8000/incidents/RSK-2026-091/mine
```

### `POST /incidents/{iid}/rollback`

Undo every action of the incident still in force, permanent ones included, for example when a block
stops real users. A `contained` incident becomes `acknowledged`: it counts toward the risk index again
and waits for a person's decision. A resolved incident stays resolved. Written to the audit trail as
`action_rolled_back` for each action, with the snapshot it returns to, then `action_undone`, or
`action_undo_failed` when the responder could not confirm it: that raises an `undo_failed` alert, and
the undo is tried again every minute (`UNDO_RETRY_S`), up to 3 more times (`UNDO_RETRIES`).

**Body**

```json
{"operator": "erick", "justification": "Customer's office NAT"}
```

- `operator` (string, required): who rolled it back.
- `justification` (string, optional): why, kept in `decisions` and the audit trail.

**Returns** the incident. Each action undone is `rolled_back`, with the responder's answer in `undo`:

```json
{"action_id": "act-0004", "status": "rolled_back", "undo": {"ok": true, "at": "2026-10-27T02:45:12+00:00", "attempts": 1}}
```

**Errors**

- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-082 has no active containment to roll back`: nothing is in force; it expired, was
  undone already or was never applied.

### `POST /incidents/{iid}/permanent`

Keep the incident's actions for good: each one still in force, or expired, becomes `permanent` with no
end time (`expires_at` is `null`); an expired one is put back in force first. The incident is then
`resolved`, with `closed_at` set. A permanent action stays until you roll it back. Written to the audit
trail as `action_made_permanent` for each action.

**Body** as for rollback, such as `{"operator": "erick", "justification": "Known botnet address"}`:
`operator` (string, required) and `justification` (string, optional).

**Errors**

- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-081 has no active or expired hotpatch to make permanent` when it never had an action
  or they were all undone, or, when an expired one would go back in force while protection is off,
  `Protection is off (monitor-only mode), so putting an expired hotpatch back in force is not applied. Turn protection back on first.`

## Hand over and close

### `POST /incidents/{iid}/assign`

Give the incident to someone. `assignee` is looked up among the routing contacts by id, name, role or
Telegram handle, case ignored (see [`GET /routing`](alerts.html#get-routing)), and gets their backup
from there; any other name is taken as written, with the previous owner as backup. SentrAI queues an
`assigned` alert for the new owner unless they took it themselves (`operator` is the assignee).
Written to the audit trail as `incident_assigned`. Giving it to its current owner changes nothing,
and assigning does not acknowledge the incident.

**Body**

```json
{"operator": "erick", "assignee": "Team lead", "note": "Please check the search page"}
```

- `operator` (string, required): who handed it over.
- `assignee` (string, required): who gets it. Not blank.
- `note` (string, optional): shown in the timeline and in the alert to the new owner.

**Returns** the incident with its new `owner`, `owner_id`, `backup`, `backup_id`, `assigned_by` (the
operator) and `assigned_at`, and the alert's id added to `notifications`.

**Errors**

- 400 `assignee is required`.
- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-082 is already resolved` (or `rejected`).

### `POST /incidents/{iid}/resolve`

Close the incident with a note on what was done. It is acknowledged first if nobody had (channel
`resolve`), becomes `resolved` and stops counting toward the risk index. Actions still in force stay
until they expire or you roll them back; the timeline says how many. Written to the audit trail as
`incident_resolved`, with the actions still in force.

**Body**

```json
{"operator": "erick", "note": "Search page patched"}
```

- `operator` (string, required): who closed it.
- `note` (string, required): what was done, not blank. Kept as `resolution`.

**Returns** the incident with `resolved_by`, `resolution` and `closed_at` set, and `resolve` in `decisions`.

**Errors**

- 400 `resolving requires a short note on what was done`.
- 404 `incident RSK-2026-999 not found`.
- 409 `RSK-2026-082 is already resolved` (or `rejected`).

## Take staff reports

### `POST /staff-reports`

Send in a report, in the reporter's own words. The dashboard's open report page (see
[Staff reports](../settings.html#staff-reports)) and the notifier's `/report` command send it here;
your own forms can too. SentrAI then:

- sorts it: what kind of problem it sounds like, how urgent, what the reporter should do now and what
  technical staff should check, with the AI model when one is set up (the call waits for it) or else
  with keyword rules.
- saves it in `staff_reports.json` next to the core database (`SENTRAI_STAFF_REPORTS` moves it) and
  writes `staff_report_received` to the audit trail.
- opens a `staff_report` incident through an event with source `staff_report`, marked `needs_review`
  and worth 20 points scaled by urgency (1.5 times when high, half when low). It alerts like any
  incident and is never contained automatically; a later report from the same reporter joins it
  while it is not closed.

**Body**

```json
{
  "text": "I got an email from 'IT support' asking me to confirm my password. I clicked the link and typed my password before I noticed the address was wrong.",
  "reporter": "Mei (front desk)",
  "contact": "mei@example.com",
  "where": "Front desk PC",
  "channel": "dashboard",
  "sender": "mei@example.com"
}
```

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `text` | string | required | what they saw: at least 10 characters, cut at 4,000; control characters are removed |
| `reporter` | string | `""` | their name; `anonymous` when empty |
| `contact` | string | `""` | how to reach them |
| `where` | string | `""` | where it happened, in their words; the incident's machine when `host` is empty |
| `host` | string | `""` | the machine it is about, a name from [`GET /machines`](status.html#get-machines); with neither, the core's own machine |
| `channel` | string | `api` | how it came in, such as `dashboard` or `telegram`; lower-cased, cut at 30 characters |
| `sender` | string | `""` | who sent it, for the rate limit: an address or chat id. Without it, `reporter` (or `channel`) counts |

`reporter`, `contact`, `where`, `host` and `sender` are cut at 120 characters and kept on one line.
Each sender may send 5 reports in 10 minutes, and everyone together 60 an hour.

**Returns** only what the reporter should see:

```json
{"id": "SR-2026-001", "status": "new", "kind": "phishing", "kind_label": "Suspicious email, message or link", "urgency": "high", "advice": ["Do not click any link or open any attachment in it.", "..."]}
```

**Errors**

- 400 `Please describe what you saw in a sentence or two.`: fewer than 10 characters.
- 429 `Too many reports in a short time. Please wait 10 minutes, or tell technical staff directly if it is urgent.`:
  the sender's limit. The message says 60 minutes when the overall limit is reached.

### `GET /staff-reports`

Reports, newest first, with a count per status. The newest 2,000 are kept.

**Query**: `status` (string, optional): `new`, `reviewing`, `resolved`, `not_a_threat`, or `open`
for new and reviewing together. Without it, every report; any other value gives an empty list.

**Returns** [staff report records](#the-staff-report-record) and counts of every report, whatever the filter:

```json
{"reports": [ ... ], "counts": {"new": 1, "reviewing": 0, "resolved": 0, "not_a_threat": 0}}
```

### `GET /staff-reports/{rid}`

One [staff report record](#the-staff-report-record).

**Errors**: 404 `staff report SR-2026-999 not found`.

### `POST /staff-reports/{rid}`

Pick a report up, hand it to someone, add a note or close it. Each change is added to the report's
`history`, written to the audit trail as `staff_report_updated` and carried over to its incident; a
body that changes nothing returns the report as it is.

- An assignee or a note on a `new` report makes it `reviewing`, unless you set `status` too.
- While the report is open (`new` or `reviewing`), a change acknowledges its incident if nobody had
  (channel `staff reports`), which stops the reminders.
- Closing the last open report on an incident closes the incident too, with the reason
  `Staff report reviewed: <note>`: rejected when every report on it is `not_a_threat`, resolved
  otherwise. Reopening a report later leaves a closed incident closed.

**Body**

```json
{"operator": "erick", "status": "resolved", "note": "Password changed, sender blocked"}
```

- `operator` (string, required): who made the change. Cut at 120 characters.
- `status` (string, optional): `new`, `reviewing`, `resolved` or `not_a_threat`.
- `assignee` (string, optional): who handles it, cut at 120 characters; `""` unassigns.
- `note` (string, optional): added to `notes`, cut at 1,000 characters. Needed to close a report.

**Returns** the updated [staff report record](#the-staff-report-record).

**Errors**

- 400 `status must be one of new, reviewing, resolved, not_a_threat`, or
  `Add a short note saying what was found before closing a report.` for `resolved` or
  `not_a_threat` without a note.
- 404 `staff report SR-2026-999 not found`.

## The incident record

What every incident endpoint answers with, trimmed:

```json
{
  "id": "RSK-2026-081",
  "category": "brute_force",
  "severity": "high",
  "points": 45.0,
  "classified_by": "rules",
  "src_ip": "203.0.113.45",
  "host": "web-01",
  "opened_at": "2026-10-27T02:45:11+00:00",
  "status": "contained",
  "acked": false,
  "contribution": 0.0,
  "recommended_action": "Block 203.0.113.45, lock account 'admin' and rate-limit /login for 2 h",
  "actions": [
    {"action_id": "act-0001", "type": "block_ip", "target": "203.0.113.45", "mode": "autonomous", "approved_by": "Countersign", "status": "active", "expires_at": "2026-10-27T04:45:11+00:00", "enforcement": "blocklist", "verified": true}
  ],
  "timeline": [
    {"ts": "2026-10-27T02:45:11+00:00", "demo_hours": 0.0, "kind": "detected", "text": "Brute force detected by Gatehouse (rules, confidence 1.0)", "points": 45.0}
  ],
  "owner": "On-duty responder"
}
```

| Field | Meaning |
| --- | --- |
| `id`, `category`, `severity` | `RSK-<year>-<n>`; the kind of attack (`brute_force`, `sql_injection`, `xss`, `port_scan`, `privilege_escalation`, `data_exfiltration`, `misconfiguration`, `log_tampering`, `malware`, `prompt_injection`, `staff_report`, `unauthorised_admin`) and the severity that comes with it |
| `status` | `open`, `acknowledged`, `contained`, `resolved` or `rejected`, see below |
| `src_ip`, `user`, `host`, `layer`, `service` | where it came from and what it hit; `layer` is `web`, `os`, `db`, `network` or `cloud`, and `service` the program on the machine (`nginx`, `sshd`) or `null` |
| `actor` | only when the line behind it was a person's work on a machine (a `sudo` or `su` command, a sign-in, a Windows administrator event): the sign-in it came from, as `host`, `user`, `via` (`ssh`, `console`, `windows`, `logind` or `who`; `null` when no sign-in was seen), `address`, `key` (the SSH key's fingerprint, `SHA256:...`, or `null`), `session`, `trust` (`trusted`, `unknown` or `suspect`), `why` in plain words, and `since`. See [`GET /admins`](status.html#get-admins) |
| `opened_at`, `contained_at`, `closed_at` | when it opened, was contained and was closed; the last two appear once that happens |
| `base_points`, `ai_confidence`, `asset_criticality`, `points` | `points` is the category's `base_points` times how sure the classifier is (up to 1) times how much the machine matters; the highest values among its events count |
| `classified_by`, `classification_reason`, `malicious_probability` | `rules`, `jev` (the TypeSafe Jev model) or `fallback` (keywords); why; and how likely an attack it is, from 0 to 1 |
| `needs_review` | the classifier was unsure (0.4 to 0.6), so SentrAI never contains it on its own. Always true for a staff report, and for root access from an unrecognised sign-in |
| `strong_signal`, `signals` | whether a rule found it, and each separate piece of evidence as `classifier:source` (`rules:nginx`). On one weak signal the safety check does not act alone |
| `analyzed_by`, `explanation`, `recommended_action`, `next_steps` | the part of SentrAI that looked at it (`Gatehouse` for web, `Vault` for databases, `Watchtower` for network and cloud, `Garrison-Linux` or `Garrison-Win` for machines); what happened, the steps it recommends and what a person should do next, in plain words |
| `acked`, `acked_by`, `acked_at`, `ack_channel` | the first acknowledgement |
| `inaction_penalty` | 5 points for each full hour nobody acknowledged a high incident (a quarter of that for low, half for medium, 1.5 times for critical, none for info), up to 30 on the same scale; it stops at the acknowledgement |
| `time_unaddressed_hours`, `sla_breached` | hours until someone acknowledged it (or it closed, or now), and whether that passed the response time (`SLA_HOURS`, 2 by default) |
| `contribution` | what it adds to the risk index ([`GET /risk`](status.html#get-risk)): `points` plus `inaction_penalty` while `open` or `acknowledged`, else 0 |
| `actions` | its protective actions, see below |
| `event_ids`, `notifications` | the events behind it (see [Events](events.html)) and the alerts queued about it (see [Alerts and routing](alerts.html)) |
| `timeline` | every step: `ts`, `demo_hours` since it opened, `kind` (`detected`, `assigned`, `notified`, `action`, `ack`, `decision`, `expired`, `escalated`, `resolved`, `admin_confirmed`, `admin_distrusted` and more), `text`, and `points`, the change to its score |
| `decisions` | each person's decision: `operator`, `decision` (`approve`, `reject`, `mine`, `rollback`, `permanent` or `resolve`), `justification`, `at` |
| `owner`, `owner_id`, `backup`, `backup_id` | who handles it and who takes over when they do not answer; the ids are routing contacts, `null` for a name outside the routing file |
| `assigned_by`, `assigned_at`, `route`, `notify` | `routing: <rule>`, an operator or `escalation`; when; the routing rule that matched; who else it told |
| `escalation_level`, `escalations` | each move to the backup after unanswered reminders: `from`, `to`, `at`, `level`, `why` |
| `wave` | the [wave](#get-waves) it is part of (`WAVE-001`), when many addresses did the same thing to this machine at once; absent otherwise |
| `resolved_by`, `resolution` | who resolved it and the note; `auto-close` when a port scan or password guessing went quiet for 60 minutes (`AUTO_CLOSE_QUIET_MIN`) |
| `reputation`, `planned_by` | only sometimes: what AbuseIPDB knows about `src_ip` when a key is set, and `Cyanide` when the AI responder planned the steps |

**Root access from an unrecognised sign-in** (`unauthorised_admin`, critical, 60 base points) is the
one category about who did something rather than what was done: administrator (root) work on a
machine, such as a `sudo` command or a Windows administrator event, from a sign-in SentrAI does not
know as an administrator's (see [`GET /admins`](status.html#get-admins)). The same work from a known
administrator's sign-in is recorded as admin activity and opens nothing. There is one such incident
per address, it is always `needs_review`, SentrAI never contains it on its own, and its alert is of
kind `was_this_you` with three buttons: **This was me** ([`POST /incidents/{iid}/mine`](#post-incidentsiidmine)),
**Not me: block it** (an `approve` decision: the address is blocked and the account locked where the
safety check allows it, and whatever was only learned from that sign-in is forgotten, written as
`admin_distrusted`) and **Acknowledge**. A command the rules would pass on its own scores three
quarters of the points (45); one they flag on its own, such as wiping a log, scores the full 60. With
`ADMIN_SESSIONS=off` the category is never used and every line is judged on its own, as before.

| Status | Means |
| --- | --- |
| `open` | nobody has acknowledged it. It counts toward the risk index, and SentrAI may contain it on its own once the index reaches the threshold |
| `acknowledged` | a person has seen it. It still counts, and SentrAI leaves the decision to people |
| `contained` | actions were put in force. It no longer counts, and stays `contained` when they expire |
| `resolved` | closed with a note, made permanent, or closed when it went quiet |
| `rejected` | closed as not a real threat, with its actions undone |

Each entry in `actions`:

| Field | Meaning |
| --- | --- |
| `action_id`, `incident`, `host` | `act-<n>`, its incident, and the machine whose agent enforces it |
| `type`, `target` | `block_ip`, `lock_user`, `rate_limit`, `waf_rule`, `kill_process` or `revoke_public_acl`, and what it is aimed at |
| `ttl_hours`, `expires_at` | how long it lasts; `expires_at` is `null` once permanent |
| `mode`, `approved_by`, `proposed_by`, `executed_by` | `autonomous` (approved by `Countersign`, the safety check) or `operator` (approved by that person); the part that proposed it and the responder that applied it |
| `status`, `applied_at`, `ended_at`, `rolled_back_at` | `active`, `expired`, `rolled_back` or `permanent`, and when it started and ended |
| `snapshot_hash` | hash of the block list just before it was applied: the state a rollback returns to |
| `enforcement`, `verified` | how it is carried out (`blocklist`, `blocklist + firewall (nftables)`, `webhook`, or `recorded (simulated)` when nothing enforces that type), and whether the responder confirmed it; one not confirmed is rolled back at once |
| `check_at`, `check` | the after-action check, 10 minutes in (`CHECK_AFTER_MIN`) or when it ends sooner, also written as `action_checked`: `worked`, `worked_note`, `disruption`, `disruption_note`, traffic counts before and after, `at`, `window_min` |
| `undo` | once it ends: `ok`, `at`, `attempts`, and `error` when the responder could not confirm it |
| `firewall`, `cloudflare`, `webhook` | only with those responders: what each reported, with a `_revert` twin for the undo |

## The staff report record

```json
{
  "id": "SR-2026-001",
  "received_at": "2026-10-27T02:45:12+00:00",
  "reporter": "Mei (front desk)",
  "host": null,
  "text": "I got an email from 'IT support' asking me to confirm my password. ...",
  "triage": {"kind": "phishing", "urgency": "high", "summary": "I got an email from 'IT support' asking me to confirm my password.", "advice": ["..."], "for_tech": "Find the message in the mail system, check who else received it, ...", "by": "keywords"},
  "status": "resolved",
  "assignee": "On-duty responder",
  "incident": "RSK-2026-083",
  "notes": [{"at": "2026-10-27T02:45:12+00:00", "by": "erick", "text": "Password changed, sender blocked"}],
  "history": [{"at": "2026-10-27T02:45:12+00:00", "by": "Mei (front desk)", "what": "reported via dashboard"}],
  "kind_label": "Suspicious email, message or link"
}
```

| Field | Meaning |
| --- | --- |
| `id` | `SR-<year>-<n>` |
| `received_at`, `channel`, `reporter`, `contact`, `where`, `host`, `text` | as sent, cleaned; empty ones are `null`, and `reporter` is `anonymous` |
| `triage.kind`, `kind_label` | `phishing`, `account`, `device`, `data`, `physical`, `scam` or `other`, and the same in words |
| `triage.urgency` | `high`, `medium` or `low` |
| `triage.summary`, `triage.advice`, `triage.for_tech` | one sentence; up to three steps for the reporter now; what technical staff should check first |
| `triage.by` | `ai` or `keywords`. When the AI model failed, keywords sorted it and `ai_error` names the error |
| `status`, `assignee` | `new`, `reviewing`, `resolved` or `not_a_threat`, and who handles it |
| `incident` | the incident it opened or joined |
| `notes`, `history` | the notes people added, and every change: `at`, `by`, and `text` or `what` (`status reviewing -> resolved; note added`) |
