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

**Query** `by` (optional): `attacker`, `machine` or `type`, to also get `grouped`.

**Returns** `headline`, `total`, `rows` (the ones not in a group), `grouped`, `groups` (the groups people made, each with `name` and `rows`) and `protection_on`. Each row has `id`, `what`, `host`, `severity`, `status`, `owner`, `open_for`, `needs`, `target`, `points`, `attacker`, `summary` and `can` (`decide`, `ack`, `contain_controls`, `mine`).

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

**Returns** `panel`, `machines` (each with `name`, `host`, `place`, `online`, `waiting`, `index`, `band`, `threshold`, `monitor_only`, `open`, `contained`, `blocked`, `last_seen`, `services`, `hardware` with `cpu`, `memory` and `disk` percentages, and `sessions`), `joined` (the agents), `stats`, `panel_info` and `band_words`.

### `POST /ui/machines/join-code`

A one-time join code, valid 24 hours, with the commands to paste on the new machine.

**Body** `{"name": "web-01", "panel_url": "https://..."}` (both optional; the address falls back to `SENTRAI_PANEL_URL`). `400` when no address is known.

**Returns** `{"code": "...", "expires_at": "...", "https": true, "pin": "...", "commands": {"linux": "...", "windows": "..."}}`.

### `POST /ui/auto-mode`

The Auto mode switch at the top of every web dashboard page. **Body** `{"on": false, "reason": "..."}`. Owner and Admin
only (`403` for an Auditor), `400` unless `on` is true or false. On (the default), SentrAI contains incidents over the
threshold by itself, within the Automation guardrails. Off, nothing is contained on its own: each would-be action is
recorded once as `containment_skipped` (reason `auto mode off`) and waits for a person on Approvals. Separate from the
Protection switch (`/protection`), which stops all containment, approved or not. Recorded as `auto_mode_changed` and
kept across restarts in `protection.json`.

**Returns** the same as `GET /protection`, which now also carries `auto_mode` and `auto_mode_meta`.

### `POST /ui/machines/{host}/delete`

The Machines list's Delete. Owner and Admin only (`403` for an Auditor). Revokes the machine's agent key, cancels its
queued jobs and hides it from the machine list. Its incidents and audit records are kept. It shows again if it reports
after being deleted, or when it joins again with a new code. Recorded in the audit log as `machine_removed`.

**Returns** `{"host": "...", "revoked": ["<agent id>"], "removed_at": "...", "jobs_cancelled": 0, "message": "..."}`.

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

## Audit trail

### `GET /ui/audit`

The newest audit records in plain words, whether the chain checks out, and who did what.

**Query** `limit` (1 to 500, default 60): how many records.

**Returns** `chain_valid`, `first_invalid_seq`, `count`, `head_hash`, `feed` (newest first: `seq`, `time`, `agent`, `type`, `summary`, `hash`) and `agents` (`agent`, `role`, `can_act`, `records`, `last`).

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

**Query** `closed` (also list resolved and rejected ones) and `mine` (only incidents owned by the signed-in person), both default `false`.

**Returns** `counts` (`open`, `attention`, `overdue`, `escalated`, `unassigned`, `mine`), `todo` (rows that need a person, most urgent first), `todo_waves` (a wave's incidents as one line each), `all` (rows), `waves`, and `contacts` (who an incident can be assigned to). Each row has `id`, `what`, `host`, `severity`, `status`, `owner`, `backup`, `open_for`, `needs`, `closed`, `attention`, `wave` and `summary`. Assign and resolve use `POST /incidents/{iid}/assign` and `/resolve`.

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

### `GET /ui/privacy`

The Privacy page: what SentrAI records about people, why, who can see it, how long the organisation keeps it, and how old the oldest record is.

**Returns** `policy` (`organisation`, `contact`, `months` per kind, `updated_at`, `updated_by`), `kinds` (`key`, `what`, `about`, `why`, `months`, `kept`, `who`, `oldest_days`, `over`), `over` (kinds older than their period), `ai_on` and `roles` (each role's permissions). SentrAI flags data past its period; it does not delete it on its own.

### `POST /ui/privacy`

Save the privacy policy. Owner or Admin only; the change goes on the audit record (`privacy_policy_changed`).

**Body** `{"organisation": "...", "contact": "...", "months": {"events": 6, "accounts": null}}` (0 to 120 months, `null` = while it exists). **Returns** the page as `GET /ui/privacy`. `400` for an unknown kind or a period out of range, `403` for an Auditor.

### `GET /ui/privacy/notice.md`

A staff notice in plain words, built from the live policy, for HR to check and share. Markdown, as a download.

## Configuration

### `GET /ui/settings`

Every setting the setup wizard knows, in sections (the extensions' own settings included).

**Returns** `sections` (`key`, `title`, `about`, `extension`, and `fields` with `env`, `prompt`, `kind`, `secret`, `generated`, `choices`, `preset_field`, `value`, `is_set`, `default`), `presets` (each with `label`, `about` and the `values` it sets), `advanced` and `advanced_about`. A secret or generated field (such as the API token) never comes back: only `is_set` tells whether it has a value.

### `POST /ui/settings`

Save changed settings. A blank secret keeps the saved one; a generated field cannot be changed here. Everything is checked before anything is written, and a bad value returns `400` naming the setting.

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
