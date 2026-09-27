# core: status (2026-09-27)

## Done
- Every Core API endpoint in `CONTRACT.md` is implemented. Run and test commands are in `README.md`.
- Classification: rules first, then Jev (TypeSafe System One), then a fallback heuristic.
  - `typesafe-sdk` 0.7.2 is installed in the venv and parsed per the SDK: `choices[...].choice/.confidence`, `nouls[...].noul`.
  - Jev is only used when `TYPESAFE_API_KEY` is set. It has a timeout and a circuit breaker.
  - It has never been called against the live API, because no key is available.
- Incident aggregation, the risk engine (curve, bands, inaction penalty, SLA) and a 1 s background tick with risk history.
- Agents: Saguaro, Root, Reservoir, SpineNet, AreoleLinux/AreoleWin, Needle, Watchdog, Scribe and HelpDesk. Each decision goes to the audit chain.
- Hotpatch workflow with snapshot, TTL, verify, rollback and permanent. Operator approve and reject work.
- Notifications with escalation, SLA reminders and delivery receipts.
- SQLite hash-chained audit log. Append-only triggers are in place, and tampering is detected.
- Negligence report as JSON and Markdown. `/demo/reset` archives the old chain.

## Last test result
- `.venv\Scripts\python -m pytest -q`: **19 passed** in about 3 s.
- A live end-to-end run over real HTTP on a temporary port also worked:
  - brute force took the risk to 53 (amber)
  - 1 real minute later it was 57
  - the SQLi event took it to 84, which triggered autonomous containment: IP blocked and `admin` locked
  - after containment the risk fell to 0
  - the report showed "Delivered ..., Ack: none" and chain_valid True

## Not done / caveats
- Port 8000 was occupied by someone else's `fake_core.py` (PID 1856), so the real core has not been run on port 8000 yet. Stop fake_core before starting core.
- My first smoke attempt accidentally sent `/demo/reset` and a few test events to that fake_core.
- State is in memory only; only the audit chain persists.
- Containment has a real effect only for `block_ip` and `lock_user`. The other playbooks are recorded as simulated.
- No Claude-written text; explanations come from templates.

## How to resume
1. `cd mvp\core`
2. `.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`, once port 8000 is free.
3. Point the lab and the dashboard at it.
4. See `CONTRACT_REQUESTS.md` for the heartbeat, the raw-line formats and the notifier button mapping.
