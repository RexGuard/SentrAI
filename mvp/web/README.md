# SentrAI web console

The new console (React, Vite, Tailwind, Lucide), next to the Streamlit one. Both talk to the same core and use the
same accounts, so either can be open at the same time. Streamlit stays the fallback until every page has moved.

## Run it

1. Start SentrAI as usual: `..\run.ps1` (Windows) or `../run.sh`.
2. Start the console: `.\run-web.ps1` (Windows) or `./run-web.sh`. Needs Node.js 20 or newer.
3. Open <http://127.0.0.1:5173> and sign in with your Streamlit account (email, password, authenticator code).

The script installs the packages the first time, builds the console whenever its source changed, and passes
`/api` to the core (`-Core http://127.0.0.1:8100` or `./run-web.sh http://127.0.0.1:8100` for another port).
For development, `npm run dev` in `app/` does the same with live reload.

## What is here

| On the new console | Still on Streamlit |
| --- | --- |
| Sign-in, Approvals, Incidents, Who gets what, Staff reports (and the open `/report` page), Chat | |
| Overview canvas, Collector, Classifier, Action taker, Automation guardrails | Scout's proposed log files, the threat, process and package scans |
| Machines, one machine (overview, hardware, incidents, blocks, jobs, agent) | A machine's signed-in, services and packages tabs |
| Review, Reports, Audit trail, Backups, Team, Extensions, Configuration | The visual limits map, the guided "Set up with Cyanide" chat |

## How it fits together

- `API.md`: the endpoints each page uses. The core's `/auth/*` (sign-in with a session cookie) and `/ui/*`
  (each page's data, ready to draw) are documented in `docs/api/auth.md` and `docs/api/ui.md`.
- A signed-in person is the operator on every change: the core takes it from the session, not from the page.
- The overview canvas and the routing editor are the Streamlit console's own `flow_canvas.mjs` and
  `routing_editor.mjs`, unchanged, in `app/src/canvas/`. Their data comes from `core/app/canvas_model.py`, which
  `gen_canvas_model.py` generates from the Streamlit console's `shaping.py`: rerun it after changing one of them.
