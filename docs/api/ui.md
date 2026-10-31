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
