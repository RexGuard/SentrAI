# UI agent status (dashboard + notifier)

Stopped on request, 2026-09-27 ~23:32. All servers I started (fake core :8900, Streamlit :8501) are stopped.

## Done
- `mvp/dashboard/` Streamlit app (`app.py`) with its own `.venv`, `requirements.txt` and `.streamlit/config.toml` (dark theme, port 8501).
  - Features: SentrAI branding; plotly 0-100 gauge colored by band with the threshold line at 80; risk-over-time chart from `/risk` history; KPI row; incident queue table; incident detail with [Acknowledge], [Approve & Patch], [Reject with Justification] (reject requires text), [Rollback] and [Make Permanent] for contained incidents; active containment from `/blocklist`; agent activity feed from `/audit` with a "Chain valid ✅" badge; evidence report viewer (`/reports/{id}.md`) with .md and .json download buttons.
  - Sidebar: core URL, operator name, auto-refresh every 2 s (`st.fragment(run_every=2)`), Reset demo button (`/demo/reset`).
  - When the core is down, a "CORE OFFLINE" panel is shown and the page keeps retrying.
  - Helpers: `cactai_ui/api.py` (HTTP client), `cactai_ui/shaping.py` (pure functions for bands, tables, feed and figures).
  - `dev/fake_core.py`: FastAPI fake of the whole contract API. It defaults to port **8900** so it never collides with the real core. It plays a scripted scenario: brute force, then penalty growth, then SQLi, then autonomous containment and a report. There is also a dev-only `POST /dev/trigger/{category}`.
  - Checked by hand in a browser against the fake core: the gauge, chart, queue, reject validation (shows an error toast), reject with text, Make Permanent (recorded in the audit), the report viewer, and the offline panel.
- `mvp/notifier/` with its own `.venv` and `requirements.txt`: `notifier.py` (Telegram mode with inline Approve/Reject buttons; reject asks for a reply with ForceReply; every button press calls `/ack` first, then `/decision`; containment alerts get Rollback/Make Permanent buttons; only the configured chat may press buttons), `formatting.py`, `core.py`. It switches to CONSOLE mode when `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` is missing, and marks alerts delivered with channel `console`. No tokens are hardcoded.

## Last test results (actual)
- `mvp/dashboard`: `.venv\Scripts\python -m pytest -q` gives **12 passed**. This covers bands and colors, the incident table, containment rows, audit normalization, the feed, figures, report headings, and the client flow against the fake core.
- `mvp/notifier`: `.venv\Scripts\python -m pytest -q` gives **8 passed**. This covers message formatting and escaping, buttons, callback parsing, the console box, console-mode delivery against the fake core (the fake core is started with the dashboard venv's Python), fallback to console when env vars are missing, and survival when the core is down.
- Streamlit started headless against the fake core (HTTP 200, no errors in the log).

## Not done / how to resume
1. **README.md files for both folders are NOT written yet.** Run commands for now:
   - Fake core: `cd mvp\dashboard; .venv\Scripts\python dev\fake_core.py` (serves http://127.0.0.1:8900)
   - Dashboard: `cd mvp\dashboard; $env:CACTAI_CORE_URL="http://127.0.0.1:8000"; .venv\Scripts\streamlit run app.py` (http://127.0.0.1:8501; defaults to core :8000). Run it from `mvp\dashboard` so `.streamlit\config.toml` (the dark theme) is picked up.
   - Notifier: `cd mvp\notifier; .venv\Scripts\python notifier.py` (console mode), or set `$env:TELEGRAM_BOT_TOKEN` and `$env:TELEGRAM_CHAT_ID` first for Telegram mode. `--once` delivers pending alerts once and exits, and `--core URL` overrides the core URL. The README still needs to cover @BotFather: /newbot gives the token; send /start to the bot, and it replies with the chat id.
   - Tests: `.venv\Scripts\python -m pytest -q` in each folder.
2. Telegram mode has not been exercised against a real bot (no token available). The imports and handler wiring were checked, but not a live run.
3. `CONTRACT_REQUESTS.md` is not written. These are the contract gaps I coded around defensively:
   - `/audit` shape: I accept either a bare list or `{"records"|"chain"|"entries": [...], "chain_valid": bool}`. The fake core uses `records`.
   - Agent names in the audit: I read `data.agent` (or `actor`/`by`) and otherwise infer the agent from `type`. **Request:** the core puts `data.agent` ("Saguaro", "Needle", "Scribe", ...) and `data.operator` on operator records.
   - `/notifications/pending` item shape is undefined. I use `id`, `incident_id`, `kind` (`incident_opened`/`reminder`/`autonomous_action`), `text`, `risk_index` and `recommended_action`, and fetch the incident for the rest.
4. Nice-to-have polish that was not done: column widths in the incident queue table (the Status column is a bit narrow).
