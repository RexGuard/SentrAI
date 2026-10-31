# SentrAI web dashboard: API list (step 2)

The React dashboard talks only to the core (FastAPI). Streamlit stays as is and keeps working.
No real IPs or hostnames here: the web app reads `VITE_CORE_URL`, default `http://127.0.0.1:8000`.

## A. Already in the core (reuse as is)

The 94 routes in `core/app/main.py`, grouped by page:

- **Overview / Pipeline**: `GET /risk`, `/waves`, `/protection`, `/limits`, `/extensions`, `/ai`, `/log-sources`, `/log-sources/pending`; `POST /protection`, `/extensions/{name}/add|remove|test`, `/extensions/reload`, `/ai/test|reload`, `/log-sources`, `/log-sources/pending/{pid}`
- **Approvals / Incidents**: `GET /incidents`, `/incidents/{iid}`, `/incidents/{iid}/why`; `POST /incidents/{iid}/ack|assign|decision|mine|permanent|resolve|rollback`
- **Staff reports**: `GET/POST /staff-reports`, `/staff-reports/{rid}`
- **Chat**: `GET/POST /chat`, `POST /chat/clear`, `/chat/setup/interpret`
- **Guardrails / Routing**: `GET/POST /routing`, `GET /limits`
- **Machines**: `GET /machines`, `/fleet/agents`, `/fleet/hardware`, `/fleet/jobs`, `/fleet/panel`, `/admins`, `/blocklist`; `POST /fleet/join-codes`, `/fleet/jobs`, `/fleet/jobs/{id}/cancel`, `/fleet/agents/{id}/revoke`, `/admins`
- **Security scans**: `GET /threats`, `/deps`, `/system/scan`, `/quarantine`; `POST /threats/scan`, `/deps/scan`, `/system/scan`, `/threats/{id}/quarantine`, `/quarantine/{id}/restore`
- **Reports / Audit / Backups**: `GET /reports/{iid}(.md|.pdf)`, `/summary/{period}(.md|.pdf)`, `/summary/schedule`, `/audit`, `/audit/verify`, `/audit/fingerprint`, `/backups`; `POST /summary/send|schedule`, `/backups`, `/backups/{id}/verify|restore`

All of them need the shared token (`SENTRAI_API_TOKEN`). A browser must never hold that token.

## B. New core endpoints (logic that lives in Streamlit today)

| # | Endpoint | Replaces (Streamlit) | Notes |
| --- | --- | --- | --- |
| 1 | `POST /auth/register-owner` | `_register_owner` + setup code (`sentrai_accounts.register_owner`) | setup code from `sentrai_config.py admin` |
| 2 | `POST /auth/login` (email, password) | `_password_step`, `check_password` | returns a short-lived "pending" cookie, not a session yet |
| 3 | `POST /auth/totp` (code or recovery code) | `_code_step`, `check_second_factor` | sets the session cookie (HttpOnly, SameSite=Strict) |
| 4 | `POST /auth/authenticator/start` + `/confirm` | `_add_authenticator`, `_show_recovery_codes` | returns QR as SVG + 8 recovery codes once |
| 5 | `POST /auth/invite/accept` | `_accept_invite` | `GET /auth/invite/{code}` to show who it is for |
| 6 | `POST /auth/logout`, `GET /auth/me` | `st.session_state.signed_in`, `ME` | `me` returns `{email, name, role, permissions[]}` |
| 7 | Rate limit on 2-3 | `sentrai_ui/signin.py` (5 tries / 5 min per address) | moves into core, per address |
| 8 | `GET/POST/DELETE /team`, `/team/invites`, `/team/{email}/role`, `/team/{email}/reset` | `page_team`, `acc.invite/set_role/remove/reset` | Owner/Admin only (`people`) |
| 9 | Role check on every write | `can()`, `locked()`, `PERMISSIONS` | **Owner/Admin**: view, act, configure, export, people. **Auditor**: view, export. Server returns 403, UI only greys out |
| 10 | Browser auth on existing routes | static token | accept the session cookie as an alternative to the token; the token path stays for agents and scripts. Operator name comes from the session, not from the request body |
| 11 | `POST /auth/admin-vouch` folded into login | `_vouch_sign_in` | the core already knows who signed in and from where |

## C. New "page summary" endpoints (so React does not re-implement `shaping.py`, 2,465 lines)

Each returns ready-to-render JSON for one page. Same functions as today, moved behind a route.

| Endpoint | From `shaping.py` |
| --- | --- |
| `GET /ui/overview` | `flow_canvas_data`, `pipeline_ribbon`, `risk_breakdown`, `board_counts` |
| `GET /ui/approvals` | `pending_approvals`, `approval_groups`, `group_approvals`, `saved_groups`, `approvals_headline` |
| `POST /ui/approvals/bulk` (verb, ids[], justification) | `bulk_split`, `bulk_result`, run server-side so it is one atomic call with one audit entry |
| `GET/POST /ui/approvals/groups` | `add_to_group`, `suggest_group_name`, saved groups |
| `GET /ui/incidents` | `build_incident_table`, `split_waves`, `attention`, `owner_history` |
| `GET /ui/machines`, `/ui/machines/{host}` | `machine_records`, `hardware_stats`, `service_rows`, `agent_table`, `job_rows`, `undoable_updates` |
| `GET /ui/audit` | `build_activity_feed`, `verify_chain_links`, `normalize_audit` |
| `GET /ui/guardrails` | `limits_map_data`, `check_limits` |
| `GET /ui/routing` | `routing_editor_data`, `routing_from_editor` (validate on save), `my_part` |
| `GET /ui/team` | `session_rows`, `admin_activity_rows` |

## D. Stays in the browser

- Theme (Black/White), Lucide icons, menu state, filters, folded groups, "How this step works" dismissals.
- Overview canvas (`flow_canvas.mjs`), routing editor (`routing_editor.mjs`), incident table (`incident_table.mjs`), limits map: wrapped as React components, fed by section C.

## E. Build order (one page per run; each ends with screenshots in both themes + accessibility scan)

Separate folder `mvp/web/` on its own branch. Streamlit is not touched until these pass.

| Run | Page | Endpoints it uses |
| --- | --- | --- |
| 1 | Sign-in + layout | B1-B7, `GET /auth/me`, `GET /health`, `GET /risk`, `GET /protection`, `POST /protection` |
| 2 | Approvals | `GET /ui/approvals`, `POST /ui/approvals/bulk`, `GET/POST /ui/approvals/groups`, `GET /incidents/{iid}/why`, `POST /incidents/{iid}/decision|ack|mine|assign` |
| 3 | Machines (+ one machine) | `GET /ui/machines`, `GET /ui/machines/{host}`, `/fleet/panel`, `/fleet/agents`, `/fleet/jobs`, `/admins`, `/deps`, `/threats`; `POST /fleet/join-codes`, `/fleet/jobs`, `/fleet/jobs/{id}/cancel`, `/fleet/agents/{id}/revoke`, `/admins`, `/deps/scan`, `/threats/scan`, `/threats/{id}/quarantine`, `/quarantine/{id}/restore` |
| 4 | Chat | `GET/POST /chat`, `POST /chat/clear`, `POST /chat/setup/interpret`, `GET /incidents` |
| 5 | Audit | `GET /ui/audit`, `GET /audit/verify`, `GET /audit/fingerprint` |
| 6 | Settings + Accounts | `GET/POST /protection`, `GET /ai`, `POST /ai/test|reload`, `GET /extensions`, `POST /extensions/{name}/add|remove|test|reload`, `GET /limits`, `GET /ui/guardrails`, `/team*` (B8), `GET/POST /summary/schedule`, `POST /summary/send`, `GET /backups`, `POST /backups*` |
| 7 | Overview canvas + routing editor | `GET /ui/overview`, `GET/POST /ui/routing`, `GET /routing`, `GET /extensions`, `GET /log-sources` |
| later | Incidents, Staff reports, Reports | `GET /ui/incidents`, `/incidents/{iid}`, `POST /incidents/{iid}/resolve|rollback|permanent`, `/staff-reports*`, `/reports/{iid}(.md|.pdf)`, `/summary/{period}(.md|.pdf)` |

Cut-off: whatever is not green by the evening stays on Streamlit for the 2-3 Nov demo.
