---
title: Audit trail
nav: api
description: Read the hash-chained record of everything SentrAI did, take a fingerprint of it, check one later, and see the off-box copy.
---

# Audit trail

Everything SentrAI does is written to the audit trail: each event it scored, each incident, decision,
block and undo, each alert, setting change and chat question. Records are chained: each one holds the
hash of the one before, so changing or removing any record breaks every hash after it.

To prove the trail was not rebuilt from scratch on the server, SentrAI also sends a signed
**fingerprint** of the newest record with its alerts, and can keep a copy of every record on another
machine (the **witness**, see [What SentrAI sends out](outgoing.html#the-witness)).

Every endpoint here needs the API token (see [Signing in](index.html#signing-in)) unless it says otherwise.

## Read the trail

### `GET /audit`

The records, oldest first, with whether the chain checks out.

**Query**

| Name | Type | Default | Meaning |
| --- | --- | --- | --- |
| `limit` | integer, 0 or more | 0 | the last this many records; 0 returns all |
| `incident` | string | none | only records about this incident, such as `RSK-2026-081` |

```bash
curl -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8000/audit?limit=2"
```

**Returns**

```json
{
  "chain_valid": true,
  "first_invalid_seq": null,
  "count": 79,
  "head_hash": "97876778a68a9dfaa4edb711c44625b59afe078a524221dcdfdba5b174951a28",
  "records": [
    {
      "seq": 78,
      "ts": "2026-10-27T02:45:12+00:00",
      "type": "telegram_linked",
      "data": {"agent": "Cyanide", "contact": "amir", "name": "Amir", "code_made_by": "erick", "...": "..."},
      "prev_hash": "37ec2b9e7064fe4cc407cefb43d50e89e6504fd5d230a6c55f85da5d6a62006e",
      "hash": "85b2953244d0c0c61c453c3c4fdd93796ddd0c94984f20ae9cc92fd998913ab9"
    },
    {
      "seq": 79,
      "ts": "2026-10-27T02:45:12+00:00",
      "type": "telegram_unlinked",
      "data": {"agent": "Cyanide", "contact": "amir", "operator": "erick", "...": "..."},
      "prev_hash": "85b2953244d0c0c61c453c3c4fdd93796ddd0c94984f20ae9cc92fd998913ab9",
      "hash": "97876778a68a9dfaa4edb711c44625b59afe078a524221dcdfdba5b174951a28"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `chain_valid` | whether every record's hash checks out, over the whole trail (not only the records returned) |
| `first_invalid_seq` | the first record that does not, or `null` |
| `count` | how many records the trail holds in all |
| `head_hash` | the newest record's hash |

Each record has `seq` (from 1, no gaps), `ts`, `type` (what happened, such as `incident_opened` or
`machine_joined`), `data` and the two hashes.

**Checking a record yourself.** `hash` is the SHA-256, in hex, of `prev_hash` followed by the JSON of
`{"seq", "ts", "type", "data"}` written with sorted keys, no spaces (`,` and `:` as separators) and
non-ASCII characters kept as they are. The first record's `prev_hash` is 64 zeros. In Python:

```python
import hashlib, json

def record_hash(rec):
    body = json.dumps({k: rec[k] for k in ("seq", "ts", "type", "data")},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((rec["prev_hash"] + body).encode("utf-8")).hexdigest()
```

## Fingerprints

A fingerprint is one line naming the newest record and its hash, signed with a key only this SentrAI
holds:

```
SENTRAI-FP v1 seq=79 head=97876778...51a28 at=2026-10-27T02:45:12Z sig=3acfc07b5b80e4ba2f15807208dce9e1
```

Every alert carries one (its `witness` field), SentrAI sends one on its own every hour when new
records were written (`ANCHOR_EVERY_MIN`, in minutes), and each client summary holds one. Once a line has left the server, nobody there can recall it, so it can later prove
the records up to it were not changed, even by someone with full access to the server.

### `GET /audit/fingerprint`

A fingerprint of the trail as it is now.

**Returns**

```json
{
  "seq": 79,
  "head": "97876778a68a9dfaa4edb711c44625b59afe078a524221dcdfdba5b174951a28",
  "at": "2026-10-27T02:45:12Z",
  "line": "SENTRAI-FP v1 seq=79 head=97876778a68a9dfaa4edb711c44625b59afe078a524221dcdfdba5b174951a28 at=2026-10-27T02:45:12Z sig=3acfc07b5b80e4ba2f15807208dce9e1"
}
```

`sig` is the first 32 hex characters of an HMAC-SHA256 with the anchor key (`anchor.key` next to the
audit database, or `SENTRAI_ANCHOR_KEY`). It is missing when there is no key.

### `GET /audit/verify`

Checks a fingerprint line against the trail on disk now. It passes only when the signature matches
and the record it names still has the same hash, which fails if any record up to it was changed or
removed. A shortened `head` (16 hex characters or more, as in alerts) works too.

**Query**

| Name | Type | Meaning |
| --- | --- | --- |
| `fingerprint` | string, required | a `SENTRAI-FP` line from an alert or summary |

```bash
curl -G -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/audit/verify \
  --data-urlencode "fingerprint=SENTRAI-FP v1 seq=79 head=97876778... at=2026-10-27T02:45:12Z sig=3acfc07b..."
```

**Returns** status `200` either way; the answer is in `ok`.

```json
{"ok": true, "reason": "records 1 to 79 are exactly as they were at 2026-10-27T02:45:12Z and the signature matches"}
```

When `ok` is `false`, `reason` is one of:

| `reason` | Meaning |
| --- | --- |
| `not a SentrAI fingerprint line (it starts with 'SENTRAI-FP v1')` | not a fingerprint |
| `the signature does not match: this line was not made by this SentrAI, or was altered` | wrong key, or the line was edited |
| `the chain on disk is broken at record 40, before the fingerprinted record 79` | a record before it was changed |
| `record 79 is missing: the chain on disk is shorter than when the fingerprint was sent` | records were removed |
| `record 79 has a different hash now: records up to it were changed or removed ...` | the trail was rebuilt |

The same check runs on the server with `python -m app.anchor verify "SENTRAI-FP v1 ..."`.

## The off-box copy

### `GET /audit/remote-copy`

Whether every record is also sent to a witness on another machine, and how far it has got. It is on
when `SENTRAI_REMOTE_COPY_URL` is set (with `SENTRAI_REMOTE_COPY_TOKEN`, and `SENTRAI_REMOTE_COPY_CA`
for a certificate of your own).

**Returns** `{"enabled": false}` when it is off. When it is on:

```json
{
  "enabled": true,
  "url": "https://witness.example.com:8600",
  "ok": true,
  "audit_seq": 79,
  "lines_sent": 1204,
  "last_sent_at": "2026-10-27T02:45:12Z",
  "error": null,
  "lines_waiting": 0,
  "lines_dropped": 0
}
```

| Field | Meaning |
| --- | --- |
| `ok` | whether the last send worked (`null` before the first) |
| `audit_seq` | the newest audit record the witness holds |
| `lines_sent` | sealed log lines sent since the core started |
| `error` | why the last send failed |
| `lines_waiting`, `lines_dropped` | lines held while the witness was out of reach, and the oldest ones dropped when more than 100,000 waited |

When the witness refuses a record because it differs from the copy it already holds, the record on
this server was changed after it was sent: that opens a `log_tampering` incident.
