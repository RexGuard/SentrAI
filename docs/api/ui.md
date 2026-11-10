---
title: Web dashboard pages
nav: api
description: The page data and bulk actions the web dashboard draws from, one group of endpoints per page.
---

# Web dashboard pages

These endpoints give the web dashboard each page's data already shaped for drawing, so the browser does
not repeat the rules. They answer the API token or a signed-in session (see [Web sign-in](auth.html)).
When a signed-in person calls a write, they are the operator in the audit trail, whatever the body says.

## Approvals

### `GET /ui/approvals`

Everything waiting on a person: open incidents to approve or reject, contained ones to keep or roll back.

**Query** `by` (optional): `attacker`, `machine` or `type`, to also get `grouped`. `brief` (optional, a number): only the first that many rows and no groups, for a summary such as the Command center.

**Returns** `headline`, `total`, `rows` (the ones not in a group), `rows_total` (how many rows there are in full), `grouped`, `groups` (the groups people made, each with `name` and `rows`) and `protection_on`. Each row has `id`, `what`, `host`, `severity`, `status`, `owner`, `open_for`, `needs`, `target`, `points`, `attacker`, `summary` and `can` (`decide`, `ack`, `contain_controls`, `mine`).

### `POST /ui/approvals/bulk`

One action on several incidents. Each is written to the audit trail on its own.

**Body** `{"verb": "approve", "ids": ["INC-1"], "justification": "..."}`. `verb` is `approve`, `reject` (a reason is required), `rollback`, `keep` or `mine`.

**Returns** `{"done": [...], "failed": [{"id": "...", "why": "..."}], "message": "Approved & patched 1 of 2 incidents. Not done: ..."}`.

### `POST /ui/approvals/groups`

Keep incidents together as one card: `{"name": "...", "ids": [...]}` (an existing name adds to it), or `{"ungroup": "name"}`.

**Returns** `{"groups": {...}, "message": "..."}`.

### `POST /ui/approvals/group-name`

A starting name for a new group: the attacker or machine the incidents share, else `Group N`.

**Body** `{"ids": [...]}` **Returns** `{"name": "..."}`

## Machines

### `GET /ui/machines`

The machine list, worst first. On a central panel (`SENTRAI_RISK_SCOPE=host`) it holds every machine the core scores plus joined agents that have sent nothing yet; otherwise just this computer.

**Returns** `panel`, `machines` (each with `name`, `host`, `place`, `online`, `waiting`, `index`, `band`, `threshold`, `monitor_only`, `open`, `contained`, `blocked`, `last_seen`, `services`, `hardware` with `cpu`, `memory` and `disk` percentages, `sessions`, and `blocking`: null with no agent, else `state` (`on`, `dry_run` or `unknown` for an agent too old to say), `word`, `backend`, `version` and `detail`), `joined` (the agents), `stats`, `panel_info` and `band_words`.

### `POST /ui/machines/join-code`

A one-time join code, valid 24 hours, with the commands to paste on the new machine.

**Body** `{"name": "web-01", "panel_url": "https://..."}` (both optional; the address falls back to `SENTRAI_PANEL_URL`). `400` when no address is known.

**Returns** `{"code": "...", "expires_at": "...", "https": true, "pin": "...", "commands": {"linux": "...", "windows": "..."}}`.

### `POST /ui/machines/{host}/delete`

The Machines list's Delete. Owner and Admin only (`403` for an Auditor). Revokes the machine's agent key, cancels its
queued jobs and hides it from the machine list. Its incidents and audit records are kept. It stays hidden even if logs
that name it keep arriving (for example from a collector using the panel token); it shows again only when it joins
again with a new code or is restored (below). Recorded in the audit log as `machine_removed`. `GET /ui/machines` lists
deleted machines under `removed`.

**Returns** `{"host": "...", "revoked": ["<agent id>"], "removed_at": "...", "jobs_cancelled": 0, "message": "..."}`.

### `POST /ui/machines/{host}/restore`

Undoes a Delete: the machine is listed again. Owner and Admin only (`403` for an Auditor); `404` if it was not deleted.
Its old agent key stays revoked, so to manage it again join it with a new code. Recorded in the audit log as
`machine_restored`. CLI: `sentrai machines restore HOST`.

**Returns** `{"host": "...", "restored_by": "...", "was_removed_at": "...", "message": "..."}`.

### `POST /ui/machines/{host}/owner`

Who is responsible for a machine (the Machines list's three-dot menu, "Who is responsible…"). Owner and Admin only
(`403` for an Auditor). Send `{"kind": "person", "contact": "<routing contact id or name>"}` for someone in Routing,
`{"kind": "agent", "backup": "<contact>"}` for the AI agent (Sentry) with an optional backup person, or `{"kind": ""}`
to clear it. An unknown person is a `400`. Kept in `fleet.json`; recorded as `machine_owner_set`.

From then on the machine's new incidents go to that owner (rule `Machine owner`; the matching Routing rule's people are
still told), and its open ones move over. The AI agent handles alerts for the owner, on headless servers nobody
watches: it acknowledges incidents whose containment is already in force, hands critical, uncertain and
"was this you" ones to its backup, and keeps the rest (unanswered, the usual reminders escalate them to the backup).
It never approves, rejects or undoes anything and never acknowledges an open incident, so automatic containment still
applies. Nothing is sent to the agent itself. CLI: `sentrai machines owner HOST PERSON`, `--agent [--backup PERSON]`,
`--clear`. In the chat, Sentry can offer a button for it.

**Returns** `{"host": "...", "owner": {"kind", "contact", "backup", "by", "at"} | null, "moved": 0, "agent": [...], "message": "..."}`.
`GET /ui/machines` shows each row's `owner` (`{"kind", "name", "contact", "backup", "backup_name"}` or `null`), plus
`contacts` (Routing's people) and `agent_name`.

### `POST /ui/machines/{host}/ping`

The Machines list's bell: asks whoever is responsible to look at the machine now. A person gets a `machine_ping`
notification listing its open alerts (by email or Telegram when Routing has them); the AI agent goes through its
alerts straight away and the message says what it did. `409` when nobody is responsible yet or the machine was
deleted. Recorded as `machine_owner_pinged`. CLI: `sentrai machines ping HOST`.

**Returns** `{"host": "...", "owner": "...", "kind": "person" | "agent", "open": 2, "message": "..."}`.

### `POST /ui/machines/{host}/rename`

The Machines list's pencil: the name people see for a machine. Owner and Admin only (`403` for an Auditor). Send
`{"name": "Shop server"}`; a blank name goes back to the host name, and more than 60 characters is a `400`. The host
name itself, which the agent, incidents and audit records use, never changes. Kept in `fleet.json` and recorded in the
audit log as `machine_renamed`.

**Returns** `{"host": "...", "name": "...", "message": "..."}`.

### `GET /ui/machines/{host}/details`

The single-machine page's Signed in, Services and Packages tabs in one call.

**Returns** `services` (name, port, proto, process, open_incidents) and `services_at`; `admins` with `on`, `sessions`, `suspect`, `activity` and `entries` (the known administrators: `kind`, `value`, `host`, `headline`, `known`, `note`, `forget`); `packages` with `latest` (the newest finished package check, each finding with a ready-made `line`), `updates` (made and not yet undone) and `busy`; and `admin_kinds`. Adding or forgetting an administrator uses `POST /admins`; checks, updates and undos use `POST /fleet/jobs`.

## Automation guardrails

### `GET /ui/limits`

The limits map's data: `settings` (the eight guardrail settings), `actions` (the kinds of action it can move between "on its own" and "asks a person"), `version`, `read_only`, `lock_reason` and `changed` (`at` and `by` of the last save, empty when never).

### `POST /ui/limits`

The map's Save. **Body** `{"settings": {...}}`. Checked again on the core; `400` with the reason when a number is out of range or an address is not one, `403` for a role that cannot configure. Writes the settings file the Configuration page uses and leaves the "changed by" note.

## Guided setup

Cyanide's setup questions on the Chat page (`mvp/setup_chat.py`). The conversation lives in the core's memory for the signed-in person, never in the chat history; secret answers are shown as dots. Nothing is written until the person confirms the summary, and saving needs the `configure` permission.

### `GET /ui/setup`

**Returns** `done` (this machine was set up before), `assistant`, `active`, and while a conversation is open `state` (`asking`, `review`, `saved`, `cancelled`), `messages` (`role` is `assistant` or `user`), `options` (`value`, `label`) and `secret` (the next answer is hidden).

### `POST /ui/setup/start`

Start a conversation, replacing any open one. Returns the same shape as `GET /ui/setup`.

### `POST /ui/setup/answer`

Answer the open question. **Body** `{"text": "..."}`: an option's value or typed words. `409` when no conversation is open. Returns the same shape as `GET /ui/setup`; when the answer confirms the summary, the settings are saved first.

### `POST /ui/setup/leave`

Close the conversation. Returns the same shape as `GET /ui/setup`.

## Report something suspicious

For registered users only, like every other endpoint (a sign-in, or the API token). The report is sorted and tracked like any staff report; the answer holds only what the reporter may see.

### `GET /ui/report`

**Returns** `on` (false when `SENTRAI_REPORT_PAGE=off`), `reporter` (the signed-in person's name) and `machines` (the machines a report can be about, on a central panel).

### `POST /ui/report`

**Body** `{"text": "...", "reporter": "...", "contact": "...", "where": "...", "host": "..."}`; only `text` is needed (at least a sentence). The sender is the signed-in account. **Returns** `id`, `kind_label`, `urgency` and `advice`. `400` for a too-short text, `404` when the page is off, `429` when one sender has sent too many (5 in 10 minutes).

## Contact Us

### `POST /ui/feedback`

The panel's Contact Us form, for the SentrAI team. Anyone signed in may send one. It is kept on the panel (`feedback.json`) and the audit record notes who sent it (not what it says). With `SENTRAI_FEEDBACK_EMAIL` set it is also emailed there in the background (the row then has `emailed` or `email_error`).

**Body** `{"name": "...", "contact": "email or company", "message": "question, feedback or bug report"}`, all three needed (at most 120, 200 and 5000 characters), plus `"incident"` when a risk card's "Ask the SentrAI team" sends it. **Returns** `{"id": "FB-...", "message": "..."}`. `400` for a missing or too-long field, `429` past 20 messages an hour from one person.

### `GET /ui/feedback`

The messages that are not done yet, oldest first (`?all=true` for every one). For the SentrAI team: `sudo sentrai feedback`.

**Returns** `{"feedback": [{"id", "at", "name", "contact", "message", "by", "done"}], "total": n}`. `403` for an Auditor.

### `POST /ui/feedback/done`

Mark messages handled, or open again.

**Body** `{"ids": ["FB-..."], "done": true}` **Returns** `{"changed": n, "message": "..."}`. `403` for an Auditor.

### `GET /ui/feature-ideas`

Feature ideas: things people asked Sentry (the chat) for that SentrAI can't do yet, grouped so the same idea asked again counts up. Most asked first; only `new` and `planned` ones unless `?all=true`. Only the person's own words are kept, with addresses, emails, links, file paths and anything that looks like a password or key taken out; never attached files or log lines. For the SentrAI team: `sudo sentrai ideas`.

**Returns** `{"ideas": [{"id": "FI-...", "title", "why", "status", "count", "asked_by", "people", "examples", "first_at", "last_at"}], "count": n}`.

### `POST /ui/feature-ideas/status`

Mark ideas `planned`, `done`, `dismissed`, or `new` again. A dismissed idea that someone asks for again goes back to `new`.

**Body** `{"ids": ["FI-..."], "status": "planned", "note": "optional"}` **Returns** `{"changed": n, "message": "..."}`. `403` unless Owner or Admin.

## Audit trail

### `GET /ui/audit`

The newest audit records in plain words, whether the chain checks out, and who did what.

**Query** `limit` (1 to 500, default 60): how many records. `before` (a record #): only records older than it, to page back through the whole log.

**Returns** `chain_valid`, `first_invalid_seq`, `count`, `head_hash`, `feed` (newest first: `seq`, `date`, `time`, `agent`, `person` (the account when a person did it, blank for an agent), `type`, `summary`, `hash`) and `agents` (`agent`, `role`, `can_act`, `records`, `last`).

### `POST /ui/audit/pdf`

The Activity Log's Export to PDF. Send `{"seqs": [12, 13, ...]}` for the chosen records or `{"all": true}` for every
record; at most 5000 in one file (`400` beyond that). The PDF lists them oldest first, the order the actions were
taken in, with the time, #, who and what was done, and whether the hash chain is intact.

**Returns** `application/pdf` (`sentrai-activity-log.pdf`).

## Team

These need a signed-in Owner or Admin: the API token alone gets `403`, because there is no person to act as. The rules are the console's: only an Owner can add, change or remove an Owner, and there is always at least one Owner. A refused change returns `400` with the reason.

### `GET /ui/team`

**Returns** `me`, `my_role`, `roles`, `invite_hours`, `people` (`email`, `name`, `role`, `role_label`, `authenticator`, `last_sign_in`, `last_ip`) and `invites` waiting to be used.

### `POST /ui/team/invite`

**Body** `{"email": "...", "role": "admin"}` **Returns** `{"code": "...", "path": "/?invite=...", "message": "..."}`. Send the link yourself: it works once, for 72 hours.

### `POST /ui/team/role`

**Body** `{"email": "...", "role": "auditor"}` **Returns** `{"message": "..."}`.

### `POST /ui/team/reset`

For a forgotten password or a lost phone: the old password stops working and a link sets both again.

**Body** `{"email": "..."}` **Returns** `{"code": "...", "path": "/?invite=...", "message": "..."}`.

### `POST /ui/team/remove`

**Body** `{"email": "..."}` **Returns** `{"message": "..."}`.

### `POST /ui/team/withdraw`

Withdraw an invite that has not been used. **Body** `{"email": "..."}` **Returns** `{"message": "..."}`.

## Incidents

### `GET /ui/incidents`

Who owns each incident and what still needs a person.

**Query** `closed` (also list resolved and rejected ones) and `mine` (only incidents owned by the signed-in person), both default `false`. `brief` (optional, a number): only `counts`, the first that many `todo` rows and `todo_total`, for a summary such as the Command center.

**Returns** `counts` (`open`, `attention`, `overdue`, `escalated`, `unassigned`, `mine`), `todo` (rows that need a person, most urgent first), `todo_total` (how many need a person in full), `todo_waves` (a wave's incidents as one line each), `all` (rows), `waves`, and `contacts` (who an incident can be assigned to). Each row has `id`, `what`, `host`, `severity`, `status`, `owner`, `backup`, `open_for`, `needs`, `closed`, `attention`, `wave` and `summary`. Assign and resolve use `POST /incidents/{iid}/assign` and `/resolve`.

### `GET /ui/risks`

The Command center's risk bubbles: approvals (a decision, or a block to keep or undo) and incidents that need a person, joined into one list per severity. A wave of many addresses doing the same thing is one bubble.

Risks SentrAI already handled on its own are left out of the counts, the rows, the bell, Approvals and the open incidents. "Handled" means contained with the block still in force. These stay on the lists: a block that failed its after-action check (it did not work, or may be hurting real users), one that was rolled back or ran out, a "was this you?" root sign-in, and one the AI was unsure about. Handled risks are still in the Activity Log and under `/ui/incidents?closed=true` (`handled: true`). Undoing one puts the incident back on the lists.

**Query** `severity` (optional: `critical`, `high`, `medium`, `low`, or `all` for every bubble newest first, used by the bell in the top bar; anything else is `400`). **Returns** `levels` (one per severity: `severity`, `count` incidents, `bubbles`, `overdue`, `oldest`), `headline` (one plain sentence), `protection_on`, `handled_count` (how many SentrAI already handled), `groups` (the table under the Command Center cards: `type` and `machine`, each a list of `name`, `open` incidents waiting for a person, `overdue`, `handled` (blocked by SentrAI on its own), `done` (the percent handled out of both) and `worst` (the most severe open level, or empty), most open first), and with `severity` also `rows`, most urgent first, and `handled` (that level's handled risks as rows of the same shape, newest first; their `actions` still offer Keep the block and Undo the block). Each row has `id` (the incident, or the wave), `ids` (every incident in it), `incident` (the one to talk about), `title`, `category`, `severity`, `host`, `source`, `owner`, `open_for`, `overdue`, `status`, `needs`, `what_happened` (plain words: the address and machine once, no file paths or jargon), `meaning` (in everyday words), `fix` (the suggested fix in plain words, such as "Block the IP address mentioned above for 2 hours so that ..."), `steps`, `unsure` (the AI was not sure), `actions` (`verb`, `label`, `hint`: the one-click steps possible now, sent to `POST /ui/approvals/bulk` with all `ids`; `escalate`, offered when there is no safe automatic step, instead sends the risk to the SentrAI team through `POST /ui/feedback` with `incident`) and `inc` (what the chat's suggestion buttons need). The person's own fix goes to `POST /chat` as `"My fix for <incident>: ..."`; Sentry (the chat assistant) weighs it and offers the closest button.

### `GET /ui/readiness`

Whether SentrAI is set up to really protect this business, for the card at the top of the Command Center and `sentrai status`. **Returns** `ready`, `missing` (how many checks are not ready), `headline`, `checks` (each `key`: `protection`, `reporting`, `blocking`, `alerts` or `backup`, with `ok`, `title`, `detail`, `fix` in plain words and `fix_cli`, the team's command) and `ai_spend` (`month`, `usd` spent by the AI helper this month, `calls`, `budget_usd`; 0 = no cap).

## Analytics

How incidents add up over time, and fixes learned from similar past incidents. A playbook is advice only: any block it mentions still goes through Approvals and the automation guardrails.

### `GET /ui/analytics`

Every incident as a row for the charts, and the patterns (incidents of the same type on the same layer, across machines) with a playbook each.

**Query** `host` (only patterns and rows that touch this machine). **Returns** `rows` (`id`, `what`, `category`, `severity`, `host`, `status`, `closed`, `attacker`, `user`, `opened`, `day`, `contain_min`, `close_min`, `answer_min`, `contain`, `close`, `auto`, `pattern`, `pattern_label`), `patterns` (`id`, `label`, `count`, `open`, `closed`, `machines`, `here`, `elsewhere`, `attackers`, `last`, `history` with the blocks that `held` or were `rolled_back` and closing `notes`, `playbook`, `rules`) and `ai` (whether an AI model can draft playbooks). A pattern's `playbook` has `title`, `summary`, `steps`, `prevent`, `watch_for` and `source` (`rules`, or `ai` once drafted).

### `GET /ui/analytics/similar`

Incidents like one incident, on any machine, with why each is similar, and its pattern's playbook.

**Query** `incident` (required). **Returns** `similar` (rows as above plus `score` from 0 to 1, `why` and the closing `note`), `pattern` (as above) and `ai`. `404` when there is no such incident.

### `POST /ui/analytics/playbooks/draft`

Ask the AI model to draft the playbook for one pattern from how its past incidents were handled. The draft replaces the rules-based playbook for that pattern until it is forgotten.

**Body** `{"pattern": "brute_force:web"}` **Returns** `{"pattern": ..., "playbook": {...}}`. `409` when no AI model is set up, `502` when the model failed (the rules-based playbook still applies).

### `POST /ui/analytics/playbooks/forget`

Drop a pattern's AI draft and go back to the rules-based playbook.

**Body** `{"pattern": "brute_force:web"}` **Returns** `{"pattern": ..., "forgotten": true}`.

### `GET /ui/tuning`

What made the most incidents and alerts in the last 7 days, and what would quiet each without hiding real attacks. Nothing changes on its own.

**Returns** `days`, `incidents`, `alerts`, `alerts_per_day`, `noisy` (more than 20 alerts a day), `false_alarms` (rejected, or resolved with a note that says it was not real), `learning` (`day`, `of`, `on`: the first week of an install), `settings` (`busy_server`, `trusted`) and `rows` (`kind` = `machine` or `network`, `key`, `what`, `incidents`, `false_alarms`, `addresses`, `per_day`, `suggestion` with `do` = `trust`, `busy`, `review` or `keep`, `text` and `where`, the setting to change on Configuration).
### `GET /ui/privacy`

The Privacy page: what SentrAI records about people, why, who can see it, how long the organisation keeps it, and how old the oldest record is.

**Returns** `policy` (`organisation`, `contact`, `months` per kind, `updated_at`, `updated_by`), `kinds` (`key`, `what`, `about`, `why`, `months`, `kept`, `who`, `oldest_days`, `over`, `in_use`), `over` (kinds older than their period), `ai_on` and `roles` (each role's permissions). SentrAI flags data past its period; it does not delete it on its own, except the Security Coach's two kinds (`coach_activity`, 0 to 3 months, and `coach_notes`, 1 to 24 months), which are deleted when their period runs out.

### `POST /ui/privacy`

Save the privacy policy. Owner or Admin only; the change goes on the audit record (`privacy_policy_changed`).

**Body** `{"organisation": "...", "contact": "...", "months": {"events": 6, "accounts": null}}` (0 to 120 months, `null` = while it exists; the coach's kinds have their own range and need a period). **Returns** the page as `GET /ui/privacy`. `400` for an unknown kind or a period out of range, `403` for an Auditor.

### `GET /ui/privacy/notice.md`

A staff notice in plain words, built from the live policy, for HR to check and share. Markdown, as a download.
### `GET /ui/recovery`

The recovery checklist for one incident: five phases (stop it, lock the doors, put things back, tell people, learn from it) with the usual steps for its type, which steps are ticked off, whether personal data may be involved, and the newest backup made before the incident opened (checked ones first).

**Query** `incident` (required). **Returns** `incident`, `what`, `machine`, `status`, `phases` (`key`, `title`, `about`, `steps` with `id`, `text` and `done` = `{by, at}` or null), `done`, `total`, `personal_data` and `backup` (`id`, `created`, `checked`, or null). `404` when there is no such incident.

### `POST /ui/recovery/check`

Tick a step off (or untick it). Needs the `act` permission; written to the audit record as `recovery_step`. Nothing is done on a machine.

**Body** `{"incident": "INC-...", "step": "secure-1", "done": true}` **Returns** the plan as `GET /ui/recovery`. `400` for a step not in the plan, `404` for an unknown incident.

## Security Coach

The coach teaches each member of staff right after a risky action in a work app (Google Workspace, Microsoft 365 and others). Nothing is recorded until the regions' checklists are ticked and the staff notice is marked as shared. Only the apps, kinds of action and people the admin chose are kept, with a fixed set of fields: never message or file contents, file names only if turned on, sign-in addresses reduced to a country. Changing anything needs the `configure` right (Owner or Admin); `403` for an Auditor.

### `GET /ui/coach`

The Coach page. **Returns** `settings` (`apps_on`, `kinds_on`, `groups_off`, `regions`, `region_checks`, `show_names`, `file_names`, `notice_shared`, ...), `ready` and `why_not_ready`, `apps` (the catalogue: `key`, `name`, `covers`, `wave`, `sees`, `needs`, `status` = `live`, `sample` or `planned`), `kinds`, `regions` (`key`, `name`, `law`, `consent`, `checks`), `team` (totals for the last 30 days, `by_group`, `top` lessons), `moments` (open ones, urgent first; `who` is "A team member" unless the moment is urgent or names are turned on), `people` (only when names are on), `kept` and `has_sample`. Records past their retention period are deleted first.

### `POST /ui/coach/settings`

Change any of the settings above. On the audit record as `coach_settings_changed`. **Body** e.g. `{"apps_on": ["google"], "regions": ["sg"], "region_checks": {"sg": [0, 1, 2]}, "notice_shared": true}`. **Returns** the page. `400` for an unknown app, kind or region.

### `GET /ui/coach/lessons`

The lesson library: `lessons` (`id`, `title`, `card`, `steps`, `questions` without the answers, `deeper`).

### `POST /ui/coach/people`

Add or change a person. **Body** `{"email": "...", "name": "...", "group": "...", "region": "sg", "reach": "email|slack|teams|app", "coaching": true, "notice_confirmed": true}`. **Returns** `person`.

### `GET /ui/coach/people/{email}/data`

Everything the coach holds about one person, for them to see or download: `person` (with `level`), `activity`, `moments`, `notes`, `kept`. `404` when it holds nothing.

### `POST /ui/coach/people/{email}/erase`

Delete everything about one person, including their phone app password, sign-ins and phone checks. On the audit record as `coach_person_erased` (counts only). **Returns** `erased` counts (`app_password`, `app_sign_ins` and `app_checks` for the phone app).

### `POST /ui/coach/events`

What connectors send. **Body** `{"events": [{"person": "a@acme.com", "app": "google", "kind": "file_shared_public", "ts": 1800000000, "file_type": "spreadsheet", "country": "SG", "device": "phone"}]}` (up to 500). Other fields are dropped. **Returns** `recorded`, `moments`, `dropped`, `why_dropped`, `urgent` (each also goes on the audit record as `coach_urgent`). `409` while the coach is not switched on.

### `POST /ui/coach/moments/{moment_id}`

The person's answer to a note. **Body** `{"answer": "fixed|was_me|not_me|reported|dismissed"}`. `not_me` raises the moment to urgent. **Returns** `moment`.

### `POST /ui/coach/lessons/{lesson_id}/answer`

Mark a lesson's two-question check. **Body** `{"person": "a@acme.com", "answers": [1, 0]}`. **Returns** `passed`, `right`, `level`, `tip`.

### `POST /ui/coach/sample`

Add three made-up people and a day of made-up activity (Google and Microsoft) to try the coach, or `{"clear": true}` to remove them. Needs the coach switched on. **Returns** `added` or `cleared`, and the page.

### `GET /ui/coach/notice.md`

The Security Coach notice for staff, built from the live settings and the Privacy page's organisation and contact. Markdown, as a download.

## Company Rules

What the company teaches SentrAI about itself: guides (policies, handbooks, how-tos) and quick facts. Sentry's answers, the Security Coach's notes and the phone app use them. Nothing is trained: SentrAI cuts each guide into short passages and looks up the few that match a question. Reading needs any role; changing needs `configure` (Owner or Admin), `403` for an Auditor. Changes go on the audit record with the guide's title and size, never its text.

### `GET /ui/knowledge`

**Returns** `guides` (`id`, `kind` file/text/link, `title`, `source`, `url`, `by`, `at`, `for_staff`, `chars`, `passages`), `facts` (`it_contact`, `report_how`, `allowed_apps`, `blocked_apps`, `systems` with `name`, `what`, `looks_after`, `importance` critical/important/normal, `extra`), `passages`, `empty` and `limits`.

### `POST /ui/knowledge/guides`

Teach a guide. **Body** a file `{"kind": "file", "name": "policy.docx", "content_base64": "..."}` (text, Markdown, CSV, HTML, Word .docx, PDF when pypdf is installed; up to 5 MB), typed text `{"kind": "text", "title": "...", "text": "..."}`, or a link `{"kind": "link", "url": "https://...", "title": "...", "text": "what it says"}` (never fetched). Add `"for_staff": false` to keep it from staff. A guide with the same title replaces the old one. On the audit record as `knowledge_added`. **Returns** the guide and `replaced`. `400` for an unreadable file, an empty text, or a link that isn't http(s).

### `GET /ui/knowledge/guides/{gid}`

One guide with its full `text`. `404` when there is none.

### `DELETE /ui/knowledge/guides/{gid}`

Forget a guide everywhere at once. On the audit record as `knowledge_removed`. **Returns** `removed`.

### `POST /ui/knowledge/facts`

Change the quick facts. **Body** any of `it_contact`, `report_how`, `allowed_apps` and `blocked_apps` (lists or comma-separated text), `systems` (the whole list), `extra`. On the audit record as `knowledge_facts_changed` (field names and counts). **Returns** the page. `400` when an app is on both lists.

### `GET /ui/knowledge/ask`

Try a question: `?q=can staff use WhatsApp&staff=true` (`staff`: only guides staff can see). **Returns** `found`, `text`, `passages` (`guide`, `title`, `text`, `url`), `help` (the IT contact) and `report_how`.

## Website check

An outside look at the company's own websites, like a stranger online would see them (app/websites.py). A website is checked only after it is added and the company proves it owns it with a DNS TXT record (`sentrai-site-verification=TOKEN`) or a file at `/.well-known/sentrai-site-verification.txt` holding `TOKEN`. The proof is read again before every check; a sub-domain of a proven domain counts as proven. Addresses that resolve to private or other non-public networks are refused. One check makes at most 12 requests to the site, spaced out, never signs in or sends a form, never follows a redirect off the domain, and stops early when the site slows down or refuses. DNS (SPF, DMARC) is read through a public DNS-over-HTTPS resolver (`SENTRAI_DOH_URL`, default Cloudflare). Values it finds (keys, `.env` lines) are never stored in full. Sentry uses it through the chat tools `get_website_check` and `check_website`; `sentrai websites` is the command line.

### `GET /ui/websites`

**Returns** `sites` (`domain`, `added_by`, `added_ts`, `verified`, `verified_by` dns/file/"part of DOMAIN", `verified_ts`, `proof` with `dns_name`, `dns_value`, `file_url`, `file_text`, `how`, `last` with `checked_at`, `grade`, `score`, `headline`, `partial`, and `grades` over time) and `max_requests`.

### `POST /ui/websites`

Add one of the company's websites. Needs Owner or Admin. **Body** `{"domain": "example.com"}` (a full address is cut to its host name; number addresses are refused). On the audit record as `website_added`. **Returns** the site as in the list, with its `proof` instructions. `400` for something that is not a domain.

### `GET /ui/websites/{domain}`

The latest check of one website. **Returns** `domain`, `checked_at`, `by`, `grade` (A to F, or `?` when not enough could be read to grade it), `score` (0 to 100), `partial`, `stopped`, `requests`, `headline`, `fix_first`, `findings` (`id`, `key`, `check`, `severity` urgent/high/medium/low/info, `severity_word`, `title`, `saw`, `detail`, `risk`, `fix`, `fix_prompt` a note to give whoever builds the site, `where`), `checks` (`key`, `label`, `status` ok/problem/not_checked, `note`), `not_checked`, `note`, and after a second check `compared_with`, `fixed_since`, `new_since`. `404` when it is not on the list or not checked yet.

### `POST /ui/websites/{domain}/verify`

Look for the proof of ownership now. Needs Owner or Admin. On the audit record as `website_verified` when found. **Returns** the site and `found` (`dns`, `file` or null). `400` when it is not on the list or does not point to a public address.

### `POST /ui/websites/{domain}/check`

Check one website now (up to about 20 seconds). On the audit record as `website_check` (grade and counts, no findings text). **Returns** the check as in `GET /ui/websites/{domain}`. `400` when it is not on the list, its ownership is not proven (or the proof was taken down), it is being checked already, or it does not point to a public address.

### `DELETE /ui/websites/{domain}`

Take a website off the list, with its results. Needs Owner or Admin. On the audit record as `website_removed`. **Returns** `removed`. `404` when it is not on the list.

## Phone app

The panel's side of the [phone app](mobile.html): who is signed in on a phone, and app invites for staff.

### `GET /ui/mobile`

Signed-in phones: `phones` (`id`, `email`, `kind` = `staff` or `panel`, `device`, `created_at`, `last_at`, `checked_at`, `to_fix`), `team` (`phones_checked`, `all_good`, `by_problem`) and `show_names`. `to_fix` (how many things a phone's check found) is `null` unless the coach shows names.

### `POST /ui/mobile/invites`

A one-time app invite for a person already on the Security Coach's list. Valid 72 hours; a new one replaces the old. Needs `configure`; on the audit record as `phone_invite_created`. **Body** `{"email": "a@acme.com"}`. **Returns** `code` (shown once), `email`, `expires_at`, `organisation` and `steps` to pass on. `404` when the person is not on the coach's list.

### `POST /ui/mobile/{sid}/sign-out`

Sign one phone out (the person signs in again to use it). Its phone check is deleted. Needs `configure`; on the audit record as `phone_signed_out`. **Returns** `id`, `email`, `device`. `404` for an unknown phone.

## Configuration

### `GET /ui/settings`

Every setting the setup wizard knows, in sections (the extensions' own settings included).

**Returns** `sections` (`key`, `title`, `about`, `extension`, and `fields` with `env`, `prompt`, `kind`, `secret`, `generated`, `choices`, `preset_field`, `advanced`, `value`, `is_set`, `default`), `presets` (each with `label`, `about` and the `values` it sets), `advanced` and `advanced_about`. A secret or generated field (such as the API token) never comes back: only `is_set` tells whether it has a value.

### `POST /ui/settings`

Save changed settings. A blank secret keeps the saved one; a generated field cannot be changed here. An advanced setting (`advanced: true`) is read-only in the panel and returns `403`: the SentrAI team changes it in the terminal with `sudo sentrai settings set`. Everything is checked before anything is written, and a bad value returns `400` naming the setting.

**Body** `{"values": {"BRUTE_FORCE_COUNT": "8"}}` **Returns** `{"saved": ["BRUTE_FORCE_COUNT"], "message": "Saved. ..."}`.

## Overview canvas

### `GET /ui/overview`

Everything the pipeline canvas draws: the steps with their live numbers, each machine, each extension, the settings each block offers, the wires between them, the saved layout and whether this person may change anything.

**Returns** `blocks`, `wires`, `defaults`, `doc` (the saved layout), `version`, `read_only`, `lock_reason`, `results` and `panel`.

### `POST /ui/overview/layout`

Save where the blocks sit, which are hidden, the notes and the hand-drawn wires, in one file next to the settings that every console shares.

**Body** `{"doc": {...}}` **Returns** `{"message": "Layout saved."}`.

### `POST /ui/overview/settings`

A block's Save: only the settings that block offers, checked as the Configuration and Automation guardrails pages check them, then written to the settings file. A bad value returns `400` with the reason.

**Body** `{"block": "step:responder", "changes": {"MAX_AUTO_ACTIONS_PER_HOUR": "5"}}` **Returns** `{"message": "..."}`.

### `POST /ui/overview/toggle`

The switch on an extension's block: add or remove it, as on the Extensions page.

**Body** `{"name": "telegram", "on": true, "title": "Telegram"}` **Returns** `{"message": "..."}`.

## Who gets what

### `GET /ui/routing`

The routing as the map editor draws it: the people, the rules, the follow-up, the layout, the choices each panel offers, and whether this person may change anything.

**Returns** `source`, `escalate_after` and `editor` (`routing`, `version`, `linked`, `categories`, `severities`, `read_only`, `lock_reason`, and the rest the editor reads).

### `POST /ui/routing`

The editor's Save: the whole routing file is replaced and used from the next alert on. The core checks it and refuses a bad file with `400` and the reason. Needs the `configure` right.

**Body** `{"routing": {...}, "summary": "what changed"}` **Returns** `{"message": "Saved. ..."}`.
