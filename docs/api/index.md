---
title: API reference
nav: api
description: Call SentrAI's core from your own scripts and tools. How to sign in, where it listens, errors, and every endpoint with examples.
---

# API reference

Every part of SentrAI talks to one service, the **core**: the dashboard, the collector that reads
your logs, the notifier that sends alerts, and the agents on other machines. The core takes log
events in, scores the risk, opens incidents, blocks attackers inside your network for a limited
time, and writes everything it does to an audit trail. This reference covers every endpoint it has,
so your own scripts and tools can do the same.

The pages after this one each cover one part of the API. This page covers what they share: where the
core listens, how to sign in, errors and conventions.

Your first two calls, on the machine running SentrAI:

```bash
curl http://127.0.0.1:8000/health
TOKEN=$(python sentrai_config.py token)     # in the mvp folder
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/risk
```

The first answers `{"ok": true}` without a token. The second gives the risk index, from 0 to 100,
and the incidents that make it up.

## Where the core listens

| Listener | Address | Who uses it |
| --- | --- | --- |
| The API | `http://127.0.0.1:8000` | the dashboard, collector and notifier on the same machine, and you |
| The agents' port (central panel only) | `https://<panel>:8443` | agents on other machines, with their machine key |

**The API** listens on this machine only, so nothing on the network can reach it. Change it with
`SENTRAI_CORE_HOST` and `SENTRAI_CORE_PORT`, or when starting SentrAI:

| Started with | Address | Port |
| --- | --- | --- |
| `./run.sh` (Linux, macOS) | `--core-bind 0.0.0.0` | `--core-port 8100` |
| `.\run.ps1` (Windows) | `-CoreBind 0.0.0.0` | `-CorePort 8100` |
| `deploy/install.sh` (server) | `--core-bind 0.0.0.0` | `--core-port 8100` |

The API is plain HTTP. Open it to the network only on a private test network: on a server, reach it
through SSH instead (`ssh -L 8000:127.0.0.1:8000 you@panel.example.com`, then use
`http://127.0.0.1:8000` on your own computer).

**The agents' port** opens on a [central panel](../panel.html) installed with `install.sh --panel`
(`SENTRAI_PANEL_PORT`, 8443; `SENTRAI_PANEL_HOST`, default `0.0.0.0`). It uses HTTPS with the
certificate in `SENTRAI_PANEL_CERT` and `SENTRAI_PANEL_KEY`. The installer makes a self-signed one,
and each agent pins it when it joins, so it does not need to come from a public authority. This port
answers only the endpoints a [machine key](#machine-keys) may call, plus `POST /fleet/enrol` and
`GET /health`, and only when the request carries a machine key. Everything else, the live docs
included, gets:

```json
{"detail": "not on the agents' port"}
```

with status 404. The operator's token and the rest of the API never face the network through it.

`SENTRAI_PUBLIC_URL` is the address the core writes into the links it sends out, such as the report
link in an alert. Set it to the address people open those links from.

## Signing in

Every endpoint needs the API token unless its page says otherwise. The token is
`SENTRAI_API_TOKEN`: a random string the setup wizard makes on the first run and saves in the
settings file. The launchers and the installer hand it to every part of SentrAI, so you only need it
for your own calls.

Print it on a laptop install (in the `mvp` folder):

```bash
python sentrai_config.py token
```

Print it on a server set up with `deploy/install.sh` (the settings file belongs to the `sentrai`
account):

```bash
sudo -u sentrai env SENTRAI_CONFIG=/var/lib/sentrai/config.json python3 /opt/sentrai/mvp/sentrai_config.py token
```

Send it in either header:

```text
Authorization: Bearer <token>
X-SentrAI-Token: <token>
```

`X-CactAI-Token` still works, for scripts written before SentrAI was renamed.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/incidents
```

```powershell
$t = python sentrai_config.py token
Invoke-RestMethod http://127.0.0.1:8000/incidents -Headers @{ Authorization = "Bearer $t" }
```

```python
import os, requests

core = "http://127.0.0.1:8000"
auth = {"Authorization": f"Bearer {os.environ['TOKEN']}"}
print(requests.get(f"{core}/risk", headers=auth, timeout=10).json()["risk_index"])
```

A missing or wrong token gets status 401 with a `WWW-Authenticate: Bearer` header:

```json
{"detail": "missing or wrong API token (python sentrai_config.py token shows it)"}
```

The token opens everything, so treat it like a password. Anyone who has it can approve and undo
blocks, read every incident, and change who gets alerts. To change it, set a new
`SENTRAI_API_TOKEN` in the settings file and restart SentrAI; links signed with the old token stop
working (see [Signed links](#signed-links)).

Signing in to the dashboard, with an email, a password and an authenticator, is a separate thing:
see [Signing in](../sign-in.html). The dashboard then calls this API with the token on your behalf.

## Machine keys

A machine that joins a central panel gets its own **machine key** in exchange for a one-time join
code ([`POST /fleet/enrol`](fleet.html#post-fleetenrol)). The key looks like
`sa_7d21e8c6d783.…`: `sa_`, the machine's 12-character agent id, a dot and a secret. The panel keeps
only a hash of it, and shows it once. The agent sends it as `Authorization: Bearer sa_...`.

A machine key can call these endpoints, and only for its own machine:

| Endpoint | What the agent does with it |
| --- | --- |
| [`POST /events`](events.html#post-events) | sends its log events; the core sets `host` to the machine's own name, whatever the log says |
| [`POST /heartbeat`](events.html#post-heartbeat) | says it is still running; the core uses the machine's own name |
| [`GET /blocklist`](status.html#get-blocklist) | reads the blocks it must put in place |
| [`GET /fleet/me`](fleet.html#get-fleetme) | asks which machine its key belongs to |
| [`POST /fleet/services`](fleet.html#post-fleetservices) | reports the services running on it |
| [`POST /fleet/hardware`](fleet.html#post-fleethardware) | reports how its CPU, memory, disks, network and temperatures are doing |
| [`GET /fleet/jobs/next`](fleet.html#get-fleetjobsnext) | picks up the next job the panel queued for it |
| [`POST /fleet/jobs/result`](fleet.html#post-fleetjobsresult) | reports how that job went |
| [`POST /fleet/offline-report`](fleet.html#post-fleetoffline-report) | reports what it blocked on its own while the panel was out of reach |

Anything else, or a `?host=` naming another machine, gets status 403:

```json
{"detail": "a machine key only sends its own events and reads its own block list"}
```

A key that is unknown, or that was revoked on the panel, gets status 401:

```json
{"detail": "unknown or revoked machine key: join the panel again"}
```

## Open endpoints

These answer without a token:

| Endpoint | Why it is open |
| --- | --- |
| [`GET /health`](status.html#get-health) | the launchers and your monitoring check that the core is up |
| [`GET /blocklist`](status.html#get-blocklist) | a website or proxy in front of your service can poll it to refuse blocked addresses and accounts; it lists nothing else. With `?host=` it needs the token or that machine's key |
| [`POST /fleet/enrol`](fleet.html#post-fleetenrol) | a new machine has no key yet; it proves itself with a one-time join code, and 10 wrong codes in 10 minutes close it to everyone for a while |
| [`GET /docs`](#get-docs) | the page itself holds nothing; it asks for the token before it shows any endpoint |

## Signed links

Alerts carry links that must open in a browser, where nobody can add a header. Two kinds of
document open without the token when the link is signed:

| Link | Example |
| --- | --- |
| an incident's evidence report, as Markdown | `/reports/RSK-2026-081.md?sig=1d69bc85676e35d2a647e3e8dca27e1b` |
| the client summary, as Markdown or PDF | `/summary/weekly.pdf?until=1793069112&sig=a432690e977d955040c8157901532a2c` |

The signature is the first 32 hexadecimal characters of an HMAC-SHA256 of the path, keyed with the
API token. For a summary the signed text is the path plus `?until=` and its value, so a link opens
that one period only. A signature fits one document, works only for `GET`, and reveals nothing about
the token. The core makes these links itself, with `SENTRAI_PUBLIC_URL` in front, and puts them in
each alert's `report_url` (see [What SentrAI sends out](outgoing.html)).

To make one yourself:

```python
import hashlib, hmac

def sign(token: str, path: str) -> str:
    return hmac.new(token.encode(), path.encode(), hashlib.sha256).hexdigest()[:32]

path = "/reports/RSK-2026-081.md"
print(f"http://127.0.0.1:8000{path}?sig={sign(token, path)}")
path = "/summary/weekly.pdf"
until = 1793069112
print(f"http://127.0.0.1:8000{path}?until={until}&sig={sign(token, f'{path}?until={until}')}")
```

The PDF evidence report and the JSON versions always need the token.

## Errors

Every error is JSON with a `detail` that says what went wrong in plain words:

```json
{"detail": "incident RSK-2026-999 not found"}
```

| Status | Means | Example `detail` |
| --- | --- | --- |
| 400 | the core refuses a value, or something it needs is missing | `turning protection off requires a reason` |
| 401 | no token, a wrong token, or an unknown or revoked machine key | `missing or wrong API token (python sentrai_config.py token shows it)` |
| 403 | a machine key outside its endpoints or its own machine; a join code that is wrong, used or expired | `a machine key only sends its own events and reads its own block list` |
| 404 | no such incident, report, job or file; or a path the agents' port does not serve | `incident RSK-2026-999 not found` |
| 409 | the request is fine, but the current state does not allow it | `RSK-2026-082 is already resolved` |
| 422 | the body or a query parameter does not match what the endpoint expects | see below |
| 429 | too many attempts in a short time | `Too many reports in a short time. Please wait 10 minutes, ...` |
| 503 | the core could not save a change to disk | `could not write the routing file: ...` |

Each endpoint's section lists the errors it can give, apart from 401 and 422, which any endpoint can
give.

A 422 comes from the request checks before any SentrAI code runs. Its `detail` is a list, one entry
per problem, with where it is (`loc`) and why (`msg`):

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "decision"],
      "msg": "Field required",
      "input": {"operator": "erick"}
    }
  ]
}
```

## Conventions

- **JSON in and out.** Send bodies as JSON with `Content-Type: application/json`. The `.md` and
  `.pdf` versions of reports and summaries are Markdown and PDF, and `/docs` is a web page.
- **Times** are ISO 8601. The core writes its own times with the machine's offset, such as
  `2026-10-27T02:44:12+00:00` on a server set to UTC. An event keeps the time its log line gave.
  A few times that come from files, such as when a file was quarantined, carry no offset and are the
  machine's local time. `until` on a summary is a Unix time in seconds.
- **The clock.** Durations such as `ttl_hours` and response times run on the core's clock, which is
  real time unless SentrAI was started faster for a demo (`DEMO_SPEED`, shown as `demo_speed` in
  [`GET /risk`](status.html#get-risk)).
- **`operator`** is the name of the person making a change. The core records it on the incident and
  in the audit trail, and does not check it: the token is what grants access. The dashboard sends the
  name of whoever is signed in.
- **Ids** have fixed shapes:

  | Id | Example | Of |
  | --- | --- | --- |
  | `RSK-<year>-<n>` | `RSK-2026-081` | an incident |
  | `act-<n>` | `act-0001` | a protective action (a block, a rate limit) |
  | `ntf-<n>` | `ntf-0001` | an alert |
  | `SR-<year>-<n>` | `SR-2026-001` | a staff report |
  | `ER-<incident>` | `ER-RSK-2026-081` | an evidence report |
  | `j-<hex>` | `j-f7d2dc41` | a job queued for a machine |
  | 12 hex characters | `7d21e8c6d783` | a machine on a central panel (agent id) |
  | `t<n>`, `s<n>`, `s<n>f<n>` | `t1`, `s1f1` | a finding or file in the latest scan; they change with every scan |
  | `q-<time>-<hash>` | `q-20261027024512-41b3ad04` | a quarantined file |
  | `b-<date>-<time>` | `b-20261027-024512` | a backup |

- **Lists** come in the order the core keeps them: incidents and alerts oldest first, the audit trail
  by sequence number, staff reports newest first, machines with the highest risk first.
- **Unknown fields** in a body are ignored, except in events, where they are kept with the event.

## The live docs

The core describes itself too. Both of these are on the API only, not on the agents' port.

### `GET /docs`

A page to browse every endpoint and try it, in your browser. It needs no token to open, because the
page holds nothing: it asks for the token, checks it against `/openapi.json`, and only then shows the
endpoints. Each **Try it out** request carries the token as a header. The token stays in the page's
memory, never in the address bar, a cookie or the browser's storage, and is gone when you close the
tab.

Open `http://127.0.0.1:8000/docs` on the machine running SentrAI, or through the SSH tunnel above.

The page loads its viewer (Swagger UI 5.33.1) from `cdn.jsdelivr.net`, checked against a fixed
SHA-384 hash so a changed file there never runs next to your token. Without internet access the
viewer cannot load and the page says so; this reference and `/openapi.json` still work.

FastAPI's own `/redoc` page is turned off.

### `GET /openapi.json`

The same API as an OpenAPI 3.1 document, for code generators and API tools. It needs the token.
Endpoints are grouped under the names of the pages below, the two ways to send the token are
declared, the open endpoints say they need none, and the ones a machine key may call say so.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/openapi.json -o sentrai-openapi.json
```

## The reference pages

| Page | What it covers |
| --- | --- |
| [Events and log sources](events.html) | What the collectors, agents and other tools send in, and which log files are read |
| [Incidents](incidents.html) | What SentrAI found, what staff reported, and what people decide about it |
| [Reports and summaries](reports.html) | Evidence reports and the one-page client summary |
| [Risk and protection](status.html) | The risk index, each machine, the administrators, the protection switch and the block list |
| [Alerts and routing](alerts.html) | Alerts waiting to go out, who gets them, and personal Telegram chats |
| [Central panel and agents](fleet.html) | Machines joining a central panel, and what their agents may call |
| [Scans, quarantine and backups](scans.html) | Process and threat scans, quarantined files and backups |
| [Chat and AI](chat.html) | Cyanide's chat, the guided setup and the AI model settings |
| [Extensions](integrations.html) | Outside services as extensions: add, remove and test them |
| [Audit trail](audit.html) | The hash-chained record of everything SentrAI did |
| [Web sign-in](auth.html) | Sign-in for the web dashboard: password, authenticator code and a session cookie |
| [Web dashboard pages](ui.html) | Ready-to-draw page data and bulk actions for the web dashboard |
| [What SentrAI sends out](outgoing.html) | The responder webhook, the witness protocol and signed links |

## Keeping this reference true

For anyone changing the core: `mvp/core/tests/test_api_docs.py` fails when an endpoint has no
section here, or when a section names an endpoint that no longer exists. Each endpoint has a heading
`### `METHOD /path`` with the path exactly as in the code, on the page that `GROUPS` in
`mvp/core/app/apidocs.py` gives its first path segment. The test's message names the page.

To add an endpoint, add its section to that page in the same change: what it does, its body and
answer with an example, and its errors. A new first path segment also needs an entry in `GROUPS`.
`mvp/CONTRACT.md` keeps the short one-line form of each endpoint.
