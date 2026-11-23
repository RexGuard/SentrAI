---
title: Security Coach connections
nav: docs
description: Connect the Security Coach to the company's Google Workspace or Microsoft 365 activity log, read-only.
---

# Security Coach connections: Google Workspace and Microsoft 365

The Security Coach teaches each member of staff right after a risky action in a work app. With these
connections it reads the company's own activity log every 15 minutes, read-only, instead of sample data.
SentrAI's team sets them up in the terminal. The owner then only ticks the app on the Coach page.

Nothing is read until the coach may record: the regions' checklists are done, the staff notice is marked as
shared, and the app is switched on on the Coach page. Only the fixed fields the coach keeps leave the
connection: who, which app, the kind of action, when, a country, the kind of device, a count, and a file's type
(its name only when the owner turned file names on). The text of emails, chats and files is never asked for.

## Google Workspace

You need the company's super admin for about five minutes.

1. In the Google Cloud console (any project, the company's own is best), turn on the **Admin SDK API**.
2. Under **APIs and services, Credentials**, create an **OAuth client ID** of type *Desktop app*.
3. Have the super admin sign in once with that client and the scope
   `https://www.googleapis.com/auth/admin.reports.audit.readonly` (for example with Google's OAuth Playground,
   using your own client ID and secret under its settings). Keep the **refresh token** it gives.
4. Save the connection on the panel:

```bash
sudo sentrai settings set COACH_GOOGLE_CLIENT_ID=... COACH_GOOGLE_CLIENT_SECRET=... \
     COACH_GOOGLE_REFRESH_TOKEN=... COACH_GOOGLE_DOMAIN=example.com
sudo sentrai coach apps on google
sudo sentrai coach read google      # read now instead of waiting up to 15 minutes
```

`COACH_GOOGLE_DOMAIN` is the company's own email domain, so that sharing with a colleague is not counted as
sharing outside.

| In Google's log | Becomes |
| --- | --- |
| Suspicious sign-in, government-backed attack warning | A risky sign-in |
| 5 or more wrong passwords for one person in one read | Many failed sign-ins |
| 2-step verification turned off | 2-step turned off |
| Mail forwarded to another domain | Mail forwarded outside |
| An app given access to the account | An app given access |
| A file made public or shared with anyone who has the link | A file shared publicly |
| A file shared with a personal address (Gmail, Yahoo, Outlook.com and the like) | A file shared with a personal account |
| 50 or more downloads by one person in one read | A large download |

## Microsoft 365

You need a Global Administrator (or Privileged Role Administrator) for about five minutes.

1. In the Entra admin center, **App registrations, New registration**. One tenant, no redirect address.
2. Under **API permissions**, add Microsoft Graph *application* permission **AuditLog.Read.All**, and choose
   **Grant admin consent**.
3. Under **Certificates and secrets**, make a client secret.
4. Save the connection on the panel:

```bash
sudo sentrai settings set COACH_MS_TENANT_ID=... COACH_MS_CLIENT_ID=... COACH_MS_CLIENT_SECRET=...
sudo sentrai coach apps on microsoft
sudo sentrai coach read microsoft
```

Reading sign-ins needs Entra ID P1 (Microsoft 365 Business Premium includes it). Without it only the directory
log is read.

| In Microsoft's log | Becomes |
| --- | --- |
| A sign-in Entra marked as medium or high risk | A risky sign-in |
| 5 or more failed sign-ins for one person in one read | Many failed sign-ins |
| A sign-in from a country new for that person (from the second read on) | A sign-in from a new place |
| Consent given to an app | An app given access |
| Security info (2-step) removed | 2-step turned off |

Mail forwarding rules in Microsoft 365 are in the Office 365 Management Activity API, not in Graph, and are not
read yet.

## Notes by email

The coach's notes reach each person in the SentrAI phone app. To email them too, the owner ticks **Email coaching
notes** on the Coach page (or `sudo sentrai coach setup --email-notes on`). Then every 15 minutes each person whose
way to reach them is email, and who confirmed the staff notice, gets one email with up to 3 of their notes that
are ready, oldest first. The rest go in the next round. Notes held for the notice wait until the person confirms
it (notes from the last 7 days are then sent). Sample notes are never emailed.

The emails have no links on purpose: staff are taught not to trust links in unexpected security emails. They use
the same mail server as the alerts: the company's own `SMTP_*` settings, or SentrAI's mail relay when the company
has none. A failed send keeps the notes for the next round.

```bash
sudo sentrai coach send    # email the notes that are ready now
```

## Checking a connection

```bash
sudo sentrai coach connectors   # connected or not, switched on, the last read and its error
```

The Coach page shows each app as **Live** once connected, with its last read or what went wrong in plain words.
A failed read does not stop the other app. Each read looks three hours back again, because both logs can show an
action late, and skips what it already counted.

The connections keep only when each last read, its result, and per person (by a hash of the email, never the
email) the last few sign-in countries, in `people/coach-connectors.json` on the panel.
