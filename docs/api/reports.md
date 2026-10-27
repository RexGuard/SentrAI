---
title: Reports and summaries
nav: api
description: Fetch an incident's evidence report as JSON, Markdown or PDF, and the one-page client summary with its schedule.
---

# Reports and summaries

Two kinds of document come out of SentrAI. An **evidence report** tells the story of one incident:
what happened, who was told, what SentrAI did and whether the record behind it is intact. The
**client summary** is one page for the business owner, covering the last day or week. The
dashboard's report buttons and the links in alerts fetch them from here.

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Evidence reports

### `GET /reports/{iid}`

The evidence report for incident `iid` (such as `RSK-2026-081`), as JSON. It is built fresh on each
call from the incident and the audit trail, so it always shows the current state.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/reports/RSK-2026-081
```

**Returns** (trimmed)

```json
{
  "report_id": "ER-RSK-2026-081",
  "title": "Security Evidence Report",
  "generated_at": "2026-10-27T02:45:12+00:00",
  "incident_id": "RSK-2026-081",
  "incident": {
    "category": "brute_force",
    "severity": "high",
    "status": "resolved",
    "host": "web-01",
    "src_ip": "203.0.113.45",
    "user": "admin",
    "points": 45.0,
    "recommended_action": "Block 203.0.113.45, lock account 'admin' and rate-limit /login for 2 h"
  },
  "in_plain_words": "Password guessing on web-01 from 203.0.113.45, first seen 2026-10-27 02:45. ...",
  "outcome": "Closed at 2026-10-27 02:45.",
  "next_steps": ["If you do not recognise the address, keep it blocked.", "..."],
  "how_to_check": ["Every line of this report comes from the activity record on the server. ...", "..."],
  "responsible_entity": "On-duty responder",
  "handling": {
    "owner": "On-duty responder",
    "backup": "Team lead",
    "route": "High",
    "escalation_level": 0,
    "history": [ ... ]
  },
  "sla": {
    "policy_hours": 2.0,
    "breached": false,
    "summary": "Within SLA: 0 hrs 0 mins of 2 hrs used; acknowledged by erick at 2026-10-27T02:45:12+00:00"
  },
  "timeline_of_inaction": [ ... ]
}
```

| Field | Meaning |
| --- | --- |
| `in_plain_words`, `outcome`, `next_steps` | the story for someone who is not technical |
| `how_to_check` | how anyone can check the report against the audit trail |
| `responsible_entity`, `handling` | who owned the incident, who backed them up, the routing rule, escalations and who closed it |
| `sla` | the agreed response time and how much of it was used |
| `timeline_of_inaction` | the incident's timeline, with the time elapsed since it opened (`demo_time`, such as `T+0h00m`) |

**Errors**: `404` `incident RSK-2026-999 not found`.

### `GET /reports/{iid}.md`

The same report as Markdown (`text/markdown`), ready to paste into a ticket or email. This is the
one version that also opens with a [signed link](index.html#signed-links) (`?sig=`) instead of the
token. The `report_url` in each alert is such a link.

**Errors**: `404` as above.

### `GET /reports/{iid}.pdf`

The same report as a PDF, sent as a download named `RSK-2026-081-evidence-report.pdf`. Needs the
token; signed links do not open it.

```bash
curl -H "Authorization: Bearer $TOKEN" -o report.pdf http://127.0.0.1:8000/reports/RSK-2026-081.pdf
```

**Errors**: `404` as above.

## The client summary

### `GET /summary/{period}`

The one-page summary for `period`, `daily` (the last 24 hours) or `weekly` (the last 7 days), as JSON.

**Query**

| Name | Type | Default | Meaning |
| --- | --- | --- | --- |
| `until` | integer | now | end the period at this Unix time instead |

**Returns** (trimmed)

```json
{
  "summary_id": "SUM-D-20261027-0245",
  "title": "Daily security summary",
  "period": "daily",
  "from": "2026-10-26T02:45:12+00:00",
  "until": "2026-10-27T02:45:12+00:00",
  "until_ts": 1793069112,
  "period_text": "Tue 27 Oct 2026",
  "client": "Harbour Clinic",
  "headline": "4 threats today. 1 still needs your attention.",
  "numbers": {
    "threats": 4,
    "stopped_automatically": 2,
    "handled_by_staff": 3,
    "closed": 3,
    "need_attention": 1,
    "late_response": 0,
    "alerts_sent": 10,
    "alerts_delivered": 0,
    "alerts_acknowledged": 6
  },
  "risk_now": {"index": 28, "band": "green"},
  "attention": [
    {
      "incident": "RSK-2026-084",
      "what": "Staff report",
      "machine": "web-01",
      "severity": "medium",
      "open_for": "1 min",
      "seen_by_staff": false,
      "late": false,
      "next_step": "SentrAI is not sure this is an attack, so it did nothing on its own: please take a look."
    }
  ],
  "machines": [{"machine": "web-01", "threats": 2, "stopped": 2, "open": 0}],
  "kinds": [{"what": "Password guessing", "count": 1}],
  "actions": {
    "done": {"blocked an address": 2, "slowed down sign-in attempts": 1},
    "total": 4,
    "undone": 2,
    "expired": 0,
    "permanent": 2
  },
  "proof": {
    "chain_valid": true,
    "first_invalid_seq": null,
    "records": 68,
    "fingerprint": "SENTRAI-FP v1 seq=68 head=5c15f770... at=2026-10-27T02:45:12Z sig=d362579f...",
    "short": "#68 5c15f7703654efe3",
    "how_to_check": "Keep this summary. Your technical staff can check the line below against the record ..."
  },
  "responsible": "On-duty responder"
}
```

`attention` lists the incidents still open, `proof.fingerprint` is an
[audit fingerprint](audit.html#get-auditfingerprint) the reader can check later with
[`GET /audit/verify`](audit.html#get-auditverify). `until_ts` is what goes in `?until=` to fetch the
same period again.

**Errors**: `404` `period must be one of daily, weekly`.

### `GET /summary/{period}.md`

The same summary as Markdown. Opens with the token or a [signed link](index.html#signed-links)
(`?until=...&sig=...`). Query and errors as above.

### `GET /summary/{period}.pdf`

The same summary as a one-page PDF download (`SUM-D-20261027-0245.pdf`). Opens with the token or a
signed link. Query and errors as above.

## When the summary is sent

### `GET /summary/schedule`

When the summary goes out and to whom.

**Returns**

```json
{
  "every": "daily",
  "at": "08:00",
  "day": "mon",
  "to": "Client",
  "changed_by": null,
  "changed_at": null,
  "last_sent_at": "2026-10-27T02:45:11+00:00",
  "next_at": "2026-10-27T08:00:00+00:00"
}
```

`every` is `daily`, `weekly` or `off`; `at` is the local time of day; `day` is the weekday for a
weekly summary; `to` is the name the summary is addressed to.

### `POST /summary/schedule`

Changes the schedule. Send only what changes. Saved, and written to the audit trail.

**Body**

```json
{"operator": "erick", "every": "weekly", "at": "08:30", "day": "mon", "to": "Harbour Clinic"}
```

| Field | Type | Meaning |
| --- | --- | --- |
| `operator` | string, required | who made the change |
| `every` | string | `daily`, `weekly` or `off` |
| `at` | string | time of day, `HH:MM` |
| `day` | string | weekday for `weekly`, such as `mon` or `friday` |
| `to` | string | who the summary is addressed to |

**Returns** the schedule, as `GET /summary/schedule`.

**Errors**: `400` with `every must be one of ...`, `day must be a weekday such as mon or friday` or
`at must be a time of day such as 08:00`.

### `POST /summary/send`

Sends the summary for the scheduled period now, outside the schedule: it is queued as an alert of
kind `summary` with a signed link to the PDF.

**Body**: `{"operator": "erick"}` (`justification` is accepted and ignored).

**Returns**

```json
{
  "summary": { "summary_id": "SUM-W-20261027-0245", "period": "weekly", "...": "as GET /summary/{period}" },
  "notification": { "id": "ntf-0011", "kind": "summary", "...": "see Alerts and routing" },
  "link": "http://127.0.0.1:8000/summary/weekly.pdf?until=1793069112&sig=a432690e977d955040c8157901532a2c"
}
```

The alert record is described on [Alerts and routing](alerts.html).
