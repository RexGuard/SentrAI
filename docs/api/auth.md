---
title: Web sign-in
nav: api
description: How the web dashboard signs a person in with a password and an authenticator code, and keeps them signed in with a cookie.
---

# Web sign-in

The web dashboard never holds the API token. A person signs in with email and password, then an
authenticator code (or a recovery code), and the core sets a `sentrai_session` cookie (HttpOnly,
SameSite=Strict, 12 hours). The cookie works on the other endpoints in place of the token:

- reads need a signed-in account;
- writes need the **Owner** or **Admin** role, and the header `X-SentrAI-Web: 1`;
- an **Auditor** reads and exports, and gets `403` on any write.

Five wrong tries from one address in five minutes end in `429` for the rest of the window. Sessions
are kept in memory, so restarting the core signs everyone out. Scripts and machine agents keep using
the token or their own key. None of the endpoints here needs the token; each checks its own cookie.

## Before anyone is known

### `GET /auth/state`

Whether the machine has any account yet and whether a setup code is waiting.

**Returns** `{"has_accounts": false, "setup_code_waiting": true}`

### `POST /auth/register-owner`

The first screen: the one-time setup code from `python sentrai_config.py admin` makes this person the Owner.

**Body** `{"code": "...", "name": "...", "email": "...", "password": "..."}` (password: at least 12 characters)

**Returns** `{"next": "add_authenticator"}` and sets a five-minute `sentrai_pending` cookie. `400` with the reason when the code or password is wrong.

### `GET /auth/invite`

What an invite code is for.

**Query** `code`

**Returns** `{"email": "...", "role": "auditor", "reset": false}`, or `404` when the code is wrong or expired.

### `POST /auth/invite/accept`

The invited person sets their name and password.

**Body** `{"code": "...", "name": "...", "password": "..."}`

**Returns** `{"next": "add_authenticator"}` and sets the `sentrai_pending` cookie.

## Signing in

### `POST /auth/login`

Step one.

**Body** `{"email": "...", "password": "..."}`

**Returns** `{"next": "code"}`, or `{"next": "add_authenticator"}` for an account without an authenticator. `401` for a wrong email or password, `429` when waiting.

### `POST /auth/totp`

Step two, with the `sentrai_pending` cookie.

**Body** `{"code": "123456"}` (a recovery code works once)

**Returns** `{"me": {...}, "used": "totp", "recovery_left": 8, "last_sign_in": 1760000000.0, "last_address": "..."}` and sets the session cookie.

### `POST /auth/authenticator/start`

With the pending cookie: a new authenticator secret for the account.

**Returns** `{"secret": "...", "uri": "otpauth://totp/..."}`; show `uri` as a QR code.

### `POST /auth/authenticator/confirm`

**Body** `{"code": "123456"}` from the new authenticator.

**Returns** the same as `/auth/totp` plus `"recovery_codes": [...]`, shown once. Sets the session cookie.

## Signed in

### `GET /auth/me`

**Returns** `{"email": "...", "name": "...", "role": "owner", "role_label": "Owner", "permissions": ["act", "configure", "export", "people", "view"]}`, or `401`.

### `POST /auth/logout`

Ends the session and clears the cookie. **Returns** `{"ok": true}`.
