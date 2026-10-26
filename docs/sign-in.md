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
   You can also make one with `python cactai_config.py admin` (laptop) or `sudo cactai-admin`
   (server). A setup code works once, for 24 hours.
2. **Open the dashboard** (`http://127.0.0.1:8501` on a laptop, `https://<server>:8501` on a
   server). It opens on *Create your Owner account*. Type the setup code, your name, email and a
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

## Reset a sign-in

A forgotten password or a lost phone: an Owner or Admin opens the **Team** page, picks the person
and presses **Reset sign-in**. Their old password stops working, and the link it makes lets them
set a new password and authenticator. A recovery code also gets you in once without your phone.

If no one else can sign in, reset from the machine itself:

| | Laptop (from the `mvp` folder) | Server |
| --- | --- | --- |
| Who may sign in (a setup code on a new machine) | `python cactai_config.py admin` | `sudo cactai-admin` |
| The first Owner: new password, printed once | `python cactai_config.py admin --reset` | `sudo cactai-admin --reset` |
| The same for another account | `python cactai_config.py admin --reset --email you@example.com` | `sudo cactai-admin --reset --email you@example.com` |

After a reset, the authenticator app is added again at the next sign-in.

For local testing where you do not want to sign in, start SentrAI with
`CACTAI_DASHBOARD_LOGIN=off` (`$env:CACTAI_DASHBOARD_LOGIN = "off"` in PowerShell). Never use it
on a server.

## The API token

The dashboard, collector and notifier talk to the core with a token made on the first run. The
launchers and the installer pass it along, so you never need to type it. To call the API yourself:

```bash
t=$(python cactai_config.py token)
curl -H "Authorization: Bearer $t" http://127.0.0.1:8000/incidents
```

```powershell
$t = python cactai_config.py token
Invoke-RestMethod http://127.0.0.1:8000/incidents -Headers @{ Authorization = "Bearer $t" }
```

## Coming next: team accounts

> **Not on the main version yet.** This part describes a change still under review
> ([pull request #53](https://github.com/RexGuard/SentrAI/pull/53)). Until it is merged, the
> single sign-in above is how the dashboard works.

The shared email and password become personal accounts, so every approval shows who made it.

1. **Create the Owner account.** A new machine opens on *Create your Owner account*. It asks for
   a one-time **setup code**, printed by `run.ps1` / `run.sh`, `python cactai_config.py admin` or
   `sudo cactai-admin`. A setup code lasts 24 hours.
2. **Add an authenticator app.** Scan the QR code with any authenticator app (Google
   Authenticator, Microsoft Authenticator, 1Password and the like), then type the 6-digit code.
3. **Save the recovery codes.** You get 8 one-time codes for when your phone is lost. Keep them
   somewhere other than the server.
4. **Invite your team.** On the new **Team** page, make an invite link for each person. Links last
   72 hours. Each person picks a password of their own and adds their own authenticator.

Every sign-in is then email, password and a 6-digit code. There are three roles:

| Role | Can |
| --- | --- |
| Owner | everything, including adding and removing Owners |
| Admin | everything except changing Owners |
| Auditor | look at everything, change nothing |

Each sign-in shows when and from where your previous one happened, so a sign-in you did not make
stands out. An existing sign-in moves over by itself: it becomes the Owner, and adds an
authenticator at its next sign-in.
