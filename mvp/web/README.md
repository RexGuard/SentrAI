# SentrAI web console

The main console (React, Vite, Tailwind, Lucide). Every page of the Streamlit console has moved here. Both talk to the
same core and use the same accounts, so either can be open at the same time; Streamlit stays as the demo fallback.

## Run it

1. Start SentrAI as usual: `..\run.ps1` (Windows) or `../run.sh`.
2. Start the console: `.\run-web.ps1` (Windows) or `./run-web.sh`. Needs Node.js 20 or newer.
3. Open <http://127.0.0.1:5173> and sign in with your account (email, password, authenticator code).

The script installs the packages the first time, builds the console whenever its source changed, and passes
`/api` to the core (`-Core http://127.0.0.1:8100` or `./run-web.sh http://127.0.0.1:8100` for another port).
For development, `npm run dev` in `app/` does the same with live reload.

## What is here

| Pages on the web console |
| --- |
| Command center (what needs a person as Critical / High / Medium bubbles that open a page of risk bubbles, each explained in plain words with a suggested fix, quick actions and a box to talk your own fix through with Cyanide; risk over time, machines and Cyanide; the landing page), Sign-in, Approvals, Incidents, Who gets what, Staff reports, Report something suspicious, Chat (with the guided setup) |
| Overview canvas, Collector (with Scout's proposals and the process, threat and package scans), Classifier, Action taker, Automation guardrails (with the limits map) |
| Machines, one machine (all its tabs, incl. signed in, services, packages) |
| Review, Reports, Audit trail, Backups, Team, Extensions, Configuration |
| On every page: the **Auto mode** switch at the top (Owner/Admin), and the **?** button at the bottom right opens a docked panel with Chat with Cyanide and Report something (both also full pages at `/chat` and `/report`) |

Every table has a filter bar (`src/lib/Filters.tsx`): a search box, a pick list for each column with repeating values, and a date range where rows carry a time.

## How it fits together

- `API.md`: the endpoints each page uses. The core's `/auth/*` (sign-in with a session cookie) and `/ui/*`
  (each page's data, ready to draw) are documented in `docs/api/auth.md` and `docs/api/ui.md`.
- A signed-in person is the operator on every change: the core takes it from the session, not from the page.
- The overview canvas and the routing editor are the Streamlit console's own `flow_canvas.mjs` and
  `routing_editor.mjs`, unchanged, in `app/src/canvas/`. Their data comes from `core/app/canvas_model.py`, which
  `gen_canvas_model.py` generates from the Streamlit console's `shaping.py`: rerun it after changing one of them.
