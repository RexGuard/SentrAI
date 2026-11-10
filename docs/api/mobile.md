---
title: Phone app
nav: api
description: What the SentrAI phone app calls - sign-in, a person's own coaching notes and lessons, the phone check, staff reports and alerts for owners.
---

# Phone app

The SentrAI Android app talks to these endpoints, through the same address people use for the web
dashboard (`https://panel.example.com/api/mobile/...`). Two kinds of people sign in:

- **Owners, Admins and Auditors** with the same email, password and authenticator code as the web
  dashboard. They see alerts as well as their own coaching.
- **Staff** on the Security Coach's list. An Owner or Admin makes an app invite for them on the Coach
  page ([`POST /ui/mobile/invites`](ui.html#post-uimobileinvites)). The first time, the person types
  the invite code and chooses a password; after that they sign in with email and password.

Signing in gives the phone a **phone key** (`sm_...`), shown once, which the app sends as
`Authorization: Bearer sm_...`. It reaches `/mobile/*` only, and only that person's own things. It
lasts 30 days from its last use. A new password, an authenticator reset, a removed account or a person
erased from the coach ends it. The panel keeps only hashes of keys, invite codes and passwords, in
`people/mobile.json`.

Five wrong tries from one address in five minutes block sign-in from it for the rest of the five
minutes (`429`).

## Signing in

### `GET /mobile/hello`

Open. Lets the app check the address is a SentrAI panel before anyone signs in: `{"app": "sentrai",
"min_password": 10}`. It says nothing about the business.

### `POST /mobile/login`

Open. **Body** `{"email": "maya@acme.com", "password": "...", "code": "123456", "device": "Pixel 8"}`.
A panel account without `code` gets `{"need_code": true}` and nothing else; send the same body again
with the 6-digit authenticator code (or a recovery code). **Returns** `key`, `expires_days` and `me`
(as `GET /mobile/me`). `401` for a wrong email, password or code; `403` for a panel account that has no
authenticator yet. On the audit trail as `phone_signed_in`.

### `POST /mobile/invite/accept`

Open. Staff, the first time. **Body** `{"code": "ABCD-EFGH-JKLM", "password": "at least 10 characters",
"device": "Galaxy A55"}`. **Returns** as `POST /mobile/login`. `403` for a wrong or expired code.
Setting a new password this way ends the person's other phone sign-ins.

### `POST /mobile/logout`

Ends this phone's sign-in and deletes its phone check. **Returns** `{"signed_out": true}`.

## The person's own coaching

### `GET /mobile/me`

**Returns** `email`, `name`, `kind` (`staff` or `panel`), `role` (`Owner`, `Admin`, `Auditor` or
`Staff`), `device`, `organisation`, `sees_alerts`, and `coach`: `in_coach`, `coaching_on`,
`notice_confirmed`, `level`, `points`, `lessons_done`, `open` and `notes` (newest first, up to 30:
`id`, `moment`, `at`, `text`, `buttons`, `lesson`, `lesson_done`, `level`, `level_word`, `status`,
`fix`, `kind`). Notes stay hidden until the person has confirmed the staff notice; once shown here
they count as delivered (`sent_via: "app"`).

### `GET /mobile/notice`

The staff notice as Markdown: `{"text": "..."}`.

### `POST /mobile/notice`

The person has read the notice. Their held notes then show. On the audit trail as
`coach_notice_confirmed`. **Returns** as `GET /mobile/me`.

### `GET /mobile/lessons`

The lesson library, as [`GET /ui/coach/lessons`](ui.html#get-uicoachlessons).

### `POST /mobile/moments/{moment_id}`

The person's answer to one of their own notes. **Body** `{"answer": "fixed|was_me|not_me|reported|dismissed"}`.
`not_me` makes it urgent and goes on the audit trail. **Returns** `moment` (`id`, `status`, `level`)
and `me`. `404` for a note that is not this person's.

### `POST /mobile/lessons/{lesson_id}/answer`

The lesson's two-question check, for this person. **Body** `{"answers": [1, 0]}`. **Returns**
`passed`, `right`, `level`, `tip`.

### `GET /mobile/my-data`

Everything SentrAI holds about this person: `coach` (as
[`GET /ui/coach/people/{email}/data`](ui.html#get-uicoachpeopleemaildata), empty when they are not
coached) and `phones` (their phone sign-ins).

## Phone check and reports

### `POST /mobile/check`

What the phone check found. Only these fields are kept; anything else is dropped:

| Field | Type | Meaning |
| --- | --- | --- |
| `screen_lock` | boolean | a PIN, pattern, password or fingerprint/face lock is set |
| `usb_debugging` | boolean | USB debugging is on |
| `rooted` | boolean | signs that Android's safety locks are off |
| `encrypted` | boolean | the phone's storage is encrypted |
| `outside_apps` | integer | how many apps came from outside the Play Store (no names) |
| `screen_reading_apps` | integer | how many of those can read the screen (accessibility access) |
| `android` | integer | Android's API level |
| `patch` | string | the security patch date, `YYYY-MM-DD` |
| `app_version` | string | the SentrAI app's version |

**Returns** `result` (the kept fields, plus `patch_days`), `problems`, `new` (problems since the last
check) and `coached`. Each new problem becomes a coaching note (`phone_no_lock`, `phone_out_of_date`
for a patch over 120 days old, `phone_outside_apps`, `phone_screen_readers`, `phone_dev_mode`,
`phone_rooted`) when the coach is switched on with the "SentrAI phone app" app ticked. The same
problem is not raised again until it has been fixed and comes back.

### `POST /mobile/report`

"Something looks wrong": a [staff report](incidents.html#post-staff-reports) with the person's email as
reporter and `channel: "app"`. **Body** `{"text": "...", "where": "front desk"}`. **Returns** the report
as its reporter sees it.

## Company rules

### `GET /mobile/company`

The company's quick facts for staff: `it_contact`, `report_how`, `allowed_apps`, `blocked_apps`, and `guides`
(`id`, `title`, `url`) staff can see.

### `POST /mobile/ask`

A question about the company's rules, answered from its own guides (no AI model needed). **Body**
`{"question": "Can I use WhatsApp for work?"}`. **Returns** as
[`GET /ui/knowledge/ask`](ui.html#get-uiknowledgeask); staff only get guides marked for staff. The audit
record notes that a question was asked and whether anything matched, never the question.

## Owners

### `GET /mobile/alerts`

Owners, Admins and Auditors only (`403` for staff). **Returns** `risk_index`, `band`, `open`,
`alerts` (up to 20 open ones, worst first: `id`, `title`, `what`, `fix`, `severity`, `status`,
`needs_review`, `opened_at`), `staff_reports_new`, `coach` (`urgent_open`, `moments_30d`) and
`phones` (team totals: `phones_checked`, `all_good`, `by_problem`, no names).
