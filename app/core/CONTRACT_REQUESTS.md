# Contract requests from core

These are additions only. Nothing in `CONTRACT.md` is changed.

1. **Collector heartbeat (for Watchdog).** Collectors should send a heartbeat every 10 s. There are two ways to do it:
   - `POST /heartbeat {"collector": "<host>"}`
   - a normal event with `"source": "heartbeat"`

   Watchdog only watches collectors that have sent at least one heartbeat. It flags one when it has been silent for 30 s: it writes an audit record and queues a `watchdog` notification.
2. **Blocked requests.** When the target app refuses a request because of the blocklist, it should log a raw line containing `403` and `blocked`. The rules engine treats such lines as benign, so they do not open new incidents.
3. **Raw formats the rules recognise.** Please use these in the lab so the rules engine catches the events:
   - Failed login: `POST /login 401 user=<u>`
   - SQLi or XSS: put the payload in the raw line. URL-encoded is fine; core decodes it.
   - Export: `GET /export rows=<n>`. With `n >= 100`, or with no rows count, it is classified as data_exfiltration.
   - Simulated command endpoint: include the phrase `shell spawned`.
4. **Notifier.** Poll `GET /notifications/pending`. Each item has `text`, `recipients` and `buttons` (`[{label, action}]`), where `action` is one of `approve`, `reject`, `ack`, `rollback` or `permanent`. Map each action to the matching incident endpoint, then `POST /notifications/{id}/delivered {"channel": "telegram", "message_id": ...}`.
