---
title: Signing in
nav: docs
description: Sign in to the SentrAI dashboard, find or reset the sign-in, and what changes when team accounts arrive.
---

# Signing in

The dashboard asks for an email and a password on every new browser session. Only a salted hash
of the password is saved, never the password itself.

## Your first sign-in

The first start makes the sign-in for you:

- **Demo:** the setup questions ask for an email and a password (press Enter and one is made for
  you). At the end, `run_demo` prints the sign-in, with the password shown that one time.
- **Server:** the installer asks for both, or takes `--admin-email`, and prints the sign-in at the
  end.

Open the dashboard (`http://127.0.0.1:8501` for the demo, `https://<server>:8501` on a server)
and sign in.

After five wrong tries from one address, that address has to wait five minutes.

## Find or reset the sign-in

| | Demo (from the `mvp` folder) | Server |
| --- | --- | --- |
| Show the sign-in email | `python cactai_config.py admin` | `sudo cactai-admin` |
| New password, printed once | `python cactai_config.py admin --reset` | `sudo cactai-admin --reset` |
| New email and password | `python cactai_config.py admin --email you@example.com --reset` | `sudo cactai-admin --email you@example.com --reset` |

You can also change the password on the dashboard, under **Configuration**, section **6. Access**.

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
   a one-time **setup code**, printed by `run_demo`, `python cactai_config.py admin` or
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
