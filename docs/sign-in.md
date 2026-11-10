---
title: Signing in
nav: docs
description: Create the Owner account, invite your team, pick roles, and reset a sign-in.
---

# Signing in

Everyone signs in to the dashboard with their own account: an email, a password and a 6-digit
code from an authenticator app. Every approval, block and scan is recorded under that person's
name. There is no open sign-up; people join by invite.

## Create the Owner account

1. **Get a setup code.** On a new machine, `run.ps1` / `run.sh` prints a one-time **setup code**.
   You can also make one with `python sentrai_config.py admin` (laptop) or `sudo sentrai-admin`
   (server). A setup code works once, for 24 hours.
2. **Open the dashboard** (the web dashboard at `http://127.0.0.1:5173` after `run-web`; the classic one
   at `http://127.0.0.1:8501` on a laptop, `https://<server>:8501` on a server). It opens on *Create your Owner account*. Type the setup code, your name, email and a
   password of at least 12 characters.
3. **Add an authenticator app.** Scan the QR code with any authenticator app (Google
   Authenticator, Microsoft Authenticator, 1Password and the like), then type the 6-digit code.
4. **Save the recovery codes.** You get 8 one-time codes for when your phone is lost. Keep them
   somewhere other than the server.

On a server, the installer can make the Owner for you instead: it asks for the Owner's email and
password on a first install (or takes `--admin-email`). Press Enter to skip and use a setup code.

A machine set up before accounts existed keeps its sign-in: that email and password become the
Owner, who adds an authenticator at the next sign-in.

## Invite your team

On the **Team** page (Owners and Admins only), type a person's email, pick a role and press
**Make invite link**. Send them the link; it lasts 72 hours. They pick their own password and add
their own authenticator.

| Role | Can |
| --- | --- |
| Owner | everything, including adding and removing Owners |
| Admin | approve and block, scan, back up and restore, add or revoke machines, change settings, invite and remove Admins and Auditors |
| Auditor | see every page, including Machines and Backups, check that a backup is intact and download reports; changes nothing |

For an Auditor, buttons that would change something are greyed out with the reason, and the
dashboard refuses the change before it reaches the core.

Each sign-in shows when and from where your previous one happened, so a sign-in you did not make
stands out. After five wrong passwords or codes from one address, that address waits five minutes.

A sign-in as Owner or Admin also tells SentrAI where you are: for the next 12 hours, root work
(`sudo`) from your computer's address on any machine counts as your own and is recorded, not raised
as an incident. An Auditor's sign-in does not. See
[Your own administrators](settings.html#your-own-administrators).

### Each person's own view

On the **Incidents** page, everyone first sees **Your part**: the incidents they own or back up,
the rules that send incidents to them, who takes over when they don't answer, and their own corner
of the "Who gets what" map. You are a person on that map when your sign-in email is the email on
your box there (click your box on the map and type it in, or ask an Owner or Admin to).

Owners and Admins can pick **See it as** to check what anyone else sees, and change the whole map
below it. Auditors see the whole map too, read-only, behind a switch.

## Reset a sign-in

A forgotten password or a lost phone: an Owner or Admin opens the **Team** page, picks the person
and presses **Reset sign-in**. Their old password stops working, and the link it makes lets them
set a new password and authenticator. A recovery code also gets you in once without your phone.

If no one else can sign in, reset from the machine itself:

| | Laptop (from the `mvp` folder) | Server |
| --- | --- | --- |
| Who may sign in (a setup code on a new machine) | `python sentrai_config.py admin` | `sudo sentrai-admin` |
| The first Owner: new password, printed once | `python sentrai_config.py admin --reset` | `sudo sentrai-admin --reset` |
| The same for another account | `python sentrai_config.py admin --reset --email you@example.com` | `sudo sentrai-admin --reset --email you@example.com` |

After a reset, the authenticator app is added again at the next sign-in.

For local testing where you do not want to sign in, start SentrAI with
`SENTRAI_DASHBOARD_LOGIN=off` (`$env:SENTRAI_DASHBOARD_LOGIN = "off"` in PowerShell). Never use it
on a server.

## The API token

The dashboard, collector and notifier talk to the core with a token made on the first run. The
launchers and the installer pass it along, so you never need to type it. To call the API yourself:

```bash
t=$(python sentrai_config.py token)
curl -H "Authorization: Bearer $t" http://127.0.0.1:8000/incidents
```

```powershell
$t = python sentrai_config.py token
Invoke-RestMethod http://127.0.0.1:8000/incidents -Headers @{ Authorization = "Bearer $t" }
```

## Upgrading from the old single sign-in

A panel set up before team accounts had one shared email and password. It moves over by itself: that
sign-in becomes the Owner, and adds an authenticator at its next sign-in. Then invite everyone else
from the **Team** page, as above.
