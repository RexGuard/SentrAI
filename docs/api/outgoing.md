---
title: What SentrAI sends out
nav: api
description: The calls SentrAI makes to other systems, the responder webhook and the witness, and the signed links in its alerts.
---

# What SentrAI sends out

The rest of this reference is about calls you make to SentrAI. This page is about the calls SentrAI
makes to you: what arrives, how to check it really came from SentrAI, and what to answer. Build
against these when you connect a firewall, WAF or SOAR, or run a witness.

The outside services SentrAI talks to through their own APIs (Cloudflare, AbuseIPDB, Slack, Telegram,
email) are set up on the [Extensions](integrations.html) page and are not described here.

## The responder webhook

When SentrAI contains an incident it blocks an address, locks an account, rate-limits a page and so
on. On its own it enforces blocks only through [`GET /blocklist`](status.html#get-blocklist), which
your apps or agents read. The responder webhook hands each action to another system as well, so a
firewall API, a WAF or a SOAR playbook can carry it out.

| Setting | Default | Meaning |
| --- | --- | --- |
| `SENTRAI_RESPONDER_WEBHOOK_URL` | empty (off) | where to send actions; must start with `https://` or `http://` |
| `SENTRAI_RESPONDER_WEBHOOK_ACTIONS` | all six | which action types to send, comma separated |
| `SENTRAI_RESPONDER_WEBHOOK_SECRET` | empty | signs each request; or `SENTRAI_RESPONDER_WEBHOOK_SECRET_FILE` with the secret in a file |
| `SENTRAI_RESPONDER_WEBHOOK_TIMEOUT_S` | `3` | seconds to wait for your answer |

### What arrives

One `POST` to your URL each time an action is put in place (`"op": "apply"`) and each time it is taken
out again (`"op": "revert"`: undone by an operator, rejected, or expired). The body is the action
record as JSON, with keys sorted and no spaces:

```http
POST /sentrai HTTP/1.1
Host: firewall.example.com
Content-Type: application/json
User-Agent: SentrAI-responder/1
Authorization: Bearer <secret>
X-SentrAI-Signature: sha256=4f0c1e...

{"action_id":"act-0007","approved_by":"Countersign","expires_at":"2026-10-27T04:45:12+00:00","incident":"RSK-2026-081","mode":"autonomous","op":"apply","target":"203.0.113.45","ttl_hours":2,"type":"block_ip"}
```

| Field | Meaning |
| --- | --- |
| `op` | `apply` or `revert` |
| `action_id` | the action, such as `act-0007`; a revert carries the same id as its apply |
| `type` | `block_ip`, `lock_user`, `rate_limit`, `waf_rule`, `kill_process` or `revoke_public_acl` |
| `target` | what it acts on: an address, an account, a page, a process |
| `incident` | the incident it is for |
| `ttl_hours`, `expires_at` | how long it lasts; SentrAI sends the `revert` itself when it expires |
| `mode`, `approved_by` | `autonomous` (SentrAI decided) or `operator`, and who approved it |

Other fields of the action record may be present too; ignore those you do not use. The action
record is described on [Incidents](incidents.html).

### Checking it came from SentrAI

With a secret set, each request carries it as `Authorization: Bearer <secret>`, and
`X-SentrAI-Signature` is `sha256=` followed by the hex HMAC-SHA256 of the raw body, keyed with the
secret. Check the signature over the bytes you received, before parsing them:

```python
import hashlib, hmac

def from_sentrai(body: bytes, signature: str, secret: str) -> bool:
    want = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(want, signature)
```

### What to answer

Any `2xx` means the action is in force. Anything else, a timeout or no connection means it is not:
SentrAI marks the action as not in force, records the error with the action, and for a failed
revert retries it and tells the person on duty. SentrAI does not follow redirects. Make `apply` and
`revert` safe to receive twice.

## The witness

The witness keeps a copy of every audit record and every sealed log line on another machine, where
someone with full access to the SentrAI server cannot change it (see
[The off-box copy](audit.html#the-off-box-copy)). SentrAI ships one, `mvp/witness/witness.py`
(Python standard library only); this is its protocol, for running it or writing your own.

```bash
python3 witness.py token > append.token          # the core's token
python3 witness.py token > read.token            # the auditor's token
python3 witness.py serve --data /var/lib/sentrai-witness --port 8600 \
  --append-token-file append.token --read-token-file read.token
```

The core is pointed at it with `SENTRAI_REMOTE_COPY_URL` and `SENTRAI_REMOTE_COPY_TOKEN` (the append
token). The core's token can add records and read a stream's newest record, nothing else; only the
read token reads the copy back. Each request carries its token as `Authorization: Bearer <token>`.

A **stream** is one chain:

| Stream | Holds |
| --- | --- |
| `audit-<host>-<first 12 characters of record 1's hash>` | audit records exactly as stored (`seq`, `ts`, `type`, `data`, `prev_hash`, `hash`) |
| `lines-<collector stream>` | raw log events with the `chain` their collector sealed them with |

Stream names are `audit-` or `lines-` followed by up to 120 letters, digits, `.`, `_` or `-`.

### `POST /append` (witness)

The core sends new records as they are written, up to 500 at a time. Needs the append token.

```json
{"stream": "audit-web-01-5c15f7703654", "items": [{"seq": 80, "ts": "...", "type": "...", "data": {}, "prev_hash": "...", "hash": "..."}]}
```

Each audit record must match its own hash (see [Checking a record yourself](audit.html#read-the-trail))
and continue the copy: `seq` one more than the last, `prev_hash` equal to the last hash. A record
sent again unchanged is accepted once. A lines stream may start mid-chain, and a line that does not
follow is kept with a note (the core has already raised it as tampering).

**Returns** `200` with the stream's head and how many records were added:

```json
{"stream": "audit-web-01-5c15f7703654", "seq": 80, "hash": "...", "added": 1}
```

**Errors** (the body is `{"error": "..."}`)

| Status | When |
| --- | --- |
| `400` | `expected {stream, items}` |
| `401` | `append token required` |
| `409` | a record does not fit: `record #80 differs from the copy kept here`, `record #80 does not follow #78 kept here` or `record #80 does not match its own hash`. The body also has the stream's head. Records before it are kept; it is written to `conflicts.jsonl`. |
| `413` | `body too large` (over 8 MB) |

A `409` on an audit stream means the record on the server was changed after the witness got it. The
core then stops sending to that stream and opens a `log_tampering` incident.

### `GET /head` (witness)

`?stream=` names the stream. Answers either token with the newest record kept:
`{"stream": "audit-web-01-5c15f7703654", "seq": 80, "hash": "..."}` (`seq` 0 and 64 zeros for a
new stream). The core asks once at start to know where to carry on.

### `GET /streams` (witness)

Read token only. Every stream with its head.

### `GET /records` (witness)

Read token only. `?stream=` and `from=` (the first `seq`, default 1) and `limit` (up to 5000): the
records kept, as they were sent. On the SentrAI server,
`python -m app.remote_copy compare --read-token-file read.token` reads them back and shows exactly
which records differ from the ones on disk.

### `GET /health` (witness)

Open: `{"ok": true}`.

Nothing can change or remove what the witness stores: `PUT`, `DELETE` and `PATCH` answer `405`
`the witness only adds`, and the core's token gets `403` `this token can only add records` on the
read endpoints.

## Links in alerts

Each alert can carry links back to SentrAI (its `report_url`, a summary's PDF). They open in a
browser without the token because they are signed for that one document; see
[Signed links](index.html#signed-links). Each alert also carries a fingerprint of the audit trail in
its `witness` field, which anyone can check later with [`GET /audit/verify`](audit.html#get-auditverify).
The alert record itself is on [Alerts and routing](alerts.html#the-notification-record).
