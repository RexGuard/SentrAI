# Lab — STATUS

Stopped on request. The lab build is **complete**; nothing left half-written.

## Done
- `target_app/` — Flask "Aegis Academy Student Portal" on :5000. Routes `/`,
  `/login`, `/search`, `/export`, `/admin/run` (simulated, never executes),
  `/healthz`. SQLite synthetic `members` table (Member 0001…, @example.com).
  JSON-lines logs (access/auth/db/os). Blocklist poller (core `/blocklist`
  every 2s, fail-open). Styled templates.
- `collector/collector.py` — tails logs, normalizes to contract Event,
  batches to core `/events` every 1s, retries when core down, heartbeat
  every 10s. Handles file creation + rotation/truncation.
- `attacks/` — brute_force, sqli, exfil, shell, benign; `--count/--delay`;
  localhost-only (hard-refuses other hosts via `_common.require_localhost`).
- `replay/simulate.py` — REPLAY MODE, posts scripted incident to core.
- `scenario.py` — live story: benign → brute → pause → sqli.
- `fake_core.py` — tiny core stand-in for self-contained lab runs.
- `tests/` — 30 tests. `README.md` with run commands.

## Not done / deferred
- Nothing outstanding against the task. Not run against the *real* core
  (built by the core agent in parallel) — only against `fake_core.py`.
- No contract deviations.

## Processes / servers
- All stopped. No python.exe running. Demo artifacts (`logs/*.jsonl`,
  `portal.sqlite3`) cleaned.

## Last test result
`.\.venv\Scripts\python.exe -m pytest -q` → **30 passed** (~2s).
End-to-end smoke test passed: attacks → logs → collector → core (risk rose to
~96), and live blocklist set on core produced a 403 at the target app for the
blocked IP while a clean IP got 200.

## How to resume
From `mvp\lab` (venv already created at `.venv`):
1. `.\.venv\Scripts\python.exe fake_core.py`            (or point at real core)
2. `.\.venv\Scripts\python.exe -m target_app`
3. `.\.venv\Scripts\python.exe -m collector.collector`
4. `.\.venv\Scripts\python.exe scenario.py`   (or individual `attacks.*`)
Tests: `.\.venv\Scripts\python.exe -m pytest -q`
