# Integration work: status (stopped on user request)

## Done
- Read `mvp/CONTRACT.md` and surveyed all four components. All exist and each has its own `.venv`:
  - core: `core/app/main.py` (uvicorn `app.main:app`), env `DEMO_SPEED`, `CACTAI_DB` (use a temp DB for tests), `RISK_THRESHOLD`, `TICK_S`, optional `TYPESAFE_API_KEY` (leave unset for offline fallback classifier). Extra endpoint `POST /demo/advance {"demo_hours"}`.
  - lab: target app `python -m target_app` (cwd `mvp/lab`, fixed port 5000, env `CACTAI_CORE_URL`, `CACTAI_LAB_LOGS`, `CACTAI_LAB_DB`); collector `python -m collector.collector --core ... --logs ...`; attacks `python -m attacks.benign|brute_force|sqli` (localhost:5000 only); replay `python -m replay.simulate --core ...`; `python scenario.py`.
  - notifier: `python notifier.py --console` (cwd `mvp/notifier`, `--core`).
  - dashboard: `streamlit run app.py --server.port 8501` (cwd `mvp/dashboard`).
- No processes/servers were started; nothing to clean up.

## Not done
- `mvp/run_demo.ps1`, `mvp/stop_demo.ps1` (not written).
- `mvp/integration/test_e2e.py`, `README.md`, `.venv` (not written; e2e never run).

## Findings so far (static reading only, not yet verified by a run)
- lab target app exposes `/healthz`, not `/health`. `run_demo.ps1` should probe `/healthz` on :5000 (contract does not define a target health route).
- core rules: brute force is detected from access-log lines `POST /login 401` (5 in 60 s per src_ip). The auth-log line `login fail user=admin` does not match any rule and falls through to Jev/fallback classifier (possible extra/odd incidents).
- lab `blocklist.poll_once` keeps the last list when core is unreachable (does not strictly "allow" on core down if a block was active before). Minor contract deviation.
- Autonomous path in core: containment only for incidents that are `open`, not acked, not `needs_review`, and approved by Countersign. Acking an incident before risk >= 80 prevents the autonomous block for it; the e2e test must ack only after the block appears.
- Report `.md` always contains "Ack: ..." ("Ack: none" when unacked).

## How to resume
1. Write `run_demo.ps1` (PS 5.1: no `&&`, no ternary; `Start-Process powershell -ArgumentList '-NoExit','-Command',...` per component, record PIDs in `mvp/.demo_pids.json`; wait for `:8000/health` and `:5000/healthz`).
2. Write `stop_demo.ps1` that only stops PIDs in `.demo_pids.json` (plus their child trees via `Get-CimInstance Win32_Process` ParentProcessId).
3. Write `test_e2e.py`: start core (`core/.venv/Scripts/python -m uvicorn app.main:app --port 8000`, cwd core, `DEMO_SPEED=3600`, `CACTAI_DB=<tmp>`), target app + collector (lab venv, `CACTAI_LAB_LOGS=<tmp>`, `CACTAI_LAB_DB=<tmp>`); skip if a component or port is missing/busy; run benign, brute_force, sqli; assert categories, risk rise, >= 80, `block_ip` in `/blocklist`, 403 for attacker `X-Demo-Src-IP`, `/audit` chain_valid, report `.md` has "Ack", rollback removes block.
4. `python -m venv mvp/integration/.venv` and `pip install pytest requests`, then run `pytest -v`.
