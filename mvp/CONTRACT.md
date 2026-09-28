# CactAI MVP: Shared Contract

Every component MUST follow this file. The design source of truth is `../Cybersecurity + AI.md`.

## Environment facts

- Windows 11, PowerShell, Python 3.12 (`python`), Node 24. **No Docker.** WSL Ubuntu exists but do not depend on it.
- Everything runs natively on Windows on one laptop, on localhost.
- Each component has its own `requirements.txt` and its own venv at `mvp/<component>/.venv` (create with `python -m venv`). Never share or modify another component's venv.
- Python only. Type hints, small modules, no frameworks beyond those listed.

## Directory layout (each owner writes ONLY inside its folder)

```
mvp/
  CONTRACT.md            (this file, owned by lead)
  core/                  owner: core agent      FastAPI on http://127.0.0.1:8000
  lab/                   owner: lab agent       target app on http://127.0.0.1:5000, collector, attacks, replay
  dashboard/             owner: ui agent        Streamlit on http://127.0.0.1:8501
  notifier/              owner: ui agent        Telegram bot (optional at runtime)
  run_demo.ps1           owner: lead (integration)
```

## Shared data (JSON over HTTP)

### Event (collector → core, `POST /events`)
```json
{
  "event_id": "evt-...",            // string, unique
  "timestamp": "2026-09-29T14:00:03+08:00",  // ISO 8601
  "host": "web-01",
  "layer": "web" | "db" | "os" | "network" | "cloud",
  "source": "flask_access" | "flask_auth" | "db_query" | "os_process" | "replay" | "...",
  "src_ip": "203.0.113.45" | null,
  "user": "admin" | null,
  "raw": "POST /login 401 user=admin",
  "asset_criticality": 1.0 | 1.5 | 2.0
}
```
`POST /events` also accepts a JSON list of events. Returns `{"accepted": n, "risk_index": int}`.

### Categories (exact strings)
`benign, brute_force, sql_injection, xss, port_scan, privilege_escalation, data_exfiltration, misconfiguration`

### Severity → base points
low 5-10, medium 15-25, high 30-45, critical 50-70. Default mapping:
brute_force=high(30), sql_injection=high(40), xss=medium(20), port_scan=medium(15), privilege_escalation=critical(60), data_exfiltration=critical(70), misconfiguration=medium(20), benign=0.

### Risk index
`risk_index = round(100 * (1 - exp(-raw/60)))`, raw = sum of open incident points (base × ai_confidence × asset_criticality) + inaction penalty (+5 per demo-hour unacknowledged, capped +30 per incident) − resolved incidents.
Bands: green 0-29, amber 30-59, red 60-79, critical 80-100. Autonomous threshold default 80.

### Demo clock
Core exposes a speed factor: `DEMO_SPEED` env var (default 60 → 1 real minute = 1 demo hour). All penalties/SLAs use demo time. SLA default 2 demo hours.

## Core API (owner: core)

| Method | Path | Body / returns |
| --- | --- | --- |
| GET | `/health` | `{"ok": true}` |
| POST | `/events` | Event or [Event] → `{"accepted", "risk_index"}` |
| GET | `/risk` | `{"risk_index", "band", "raw_score", "threshold", "open_incidents": [...ids], "history": [{"t","risk_index"}]}` |
| GET | `/incidents` | list of Incident |
| GET | `/incidents/{id}` | Incident |
| POST | `/incidents/{id}/decision` | `{"operator": "erick", "decision": "approve" \| "reject", "justification": "..."}` |
| POST | `/incidents/{id}/rollback` | `{"operator", "justification"}` |
| POST | `/incidents/{id}/permanent` | `{"operator", "justification"}` |
| POST | `/incidents/{id}/ack` | `{"operator", "channel"}` records acknowledgement |
| GET | `/audit` | hash-chained records `[{"seq","ts","type","data","prev_hash","hash"}]` + `{"chain_valid": bool}` |
| GET | `/reports/{incident_id}` | negligence report JSON |
| GET | `/reports/{incident_id}.md` | same report as Markdown |
| GET | `/blocklist` | `{"ips": [...], "users": [...]}` active (non-expired) containment, polled by target app |
| GET | `/notifications/pending` | alerts not yet delivered (polled by notifier) |
| POST | `/notifications/{id}/delivered` | `{"channel","message_id"}` |
| GET | `/chat` | `{"assistant", "model", "messages": [{"id","role": "operator" \| "assistant","text","ts","incident", ...}]}` |
| POST | `/chat` | `{"operator", "message", "incident": id or null}` → the assistant message, with `"looked_at": [...]` and `"suggestions": [{"incident","decision","label","reason","status"}]`. Read-only: a suggestion changes nothing until the operator confirms it through the decision/rollback/permanent/ack endpoints above. Logged to the audit trail as `operator_chat`. |
| POST | `/chat/clear` | empties the chat history (also cleared by `/demo/reset`) |
| GET | `/ai` | the AI model Cyanide and the chat use now: `{"engine","planner","chat","online","provider","model","key_source","off_reason"}`; `off_reason` says why it is off (no key, missing model, package not installed...) |
| POST | `/ai/reload` | reads the saved AI settings again and switches Cyanide and the chat to them (no restart); returns the same shape as `GET /ai` |
| POST | `/ai/test` | one real request to the provider. Body `{"provider","api_key","base_url","model"}` tests those values (saved or not) without switching anything; no body tests what Cyanide uses now. Returns `{"ok","provider","model","ms","error","hint","tested"}` |
| POST | `/demo/reset` | clears state for a fresh take |

### Incident
```json
{
  "id": "RSK-2026-081",
  "category": "brute_force", "severity": "high",
  "base_points": 30, "ai_confidence": 0.94, "points": 42.3,
  "classified_by": "rules" | "jev" | "fallback",
  "src_ip": "...", "user": "...", "host": "...", "layer": "web",
  "opened_at": "...", "status": "open" | "acknowledged" | "contained" | "resolved" | "rejected",
  "acked": false, "acked_by": null, "acked_at": null,
  "inaction_penalty": 15, "sla_breached": false,
  "recommended_action": "Block 203.0.113.45 for 2 h and rate-limit /login",
  "explanation": "plain English",
  "actions": [Action], "event_ids": [...]
}
```

### Action (containment record)
```json
{ "action_id": "act-0007", "incident": "RSK-2026-081", "type": "block_ip" | "lock_user" | "rate_limit" | "waf_rule" | "kill_process" | "revoke_public_acl",
  "target": "203.0.113.45", "ttl_hours": 2, "expires_at": "...", "mode": "autonomous" | "operator",
  "approved_by": "Needle" | "<operator>", "status": "active" | "expired" | "rolled_back" | "permanent",
  "snapshot_hash": "..." }
```
Containment is enforced by the target app polling `/blocklist` (real effect: blocked IPs/users get HTTP 403). No host firewall changes by default.

## Target app (owner: lab)
- Flask on :5000: `/` , `/login` (POST form user/password), `/search?q=` (deliberately naive, logs SQLi-looking queries; uses SQLite with a fake `members` table of synthetic data), `/export` (bulk export, triggers data_exfiltration events), `/admin/run?cmd=` simulated command endpoint that NEVER executes anything, only logs "shell spawned" style event.
- Writes JSON-lines logs to `mvp/lab/logs/*.jsonl`. Honors core `/blocklist` (poll every 2 s; if core down, allow).
- Cactus spines (off unless `CACTAI_SPINES=1`): honeypot `/admin-legacy`, a planted credential, bait `members` rows and a tarpit. Each touch goes to `mvp/lab/logs/deception.jsonl`; the collector sends it with `"source": "cactus_spine"` and a raw text starting `cactus-spine <kind>:`, and core rules turn it into an incident at confidence 1.0 (only for that source).
- Because clients are local, the attacker IP is taken from header `X-Demo-Src-IP` when present (demo spoofing so different "attackers" can be shown), else remote_addr.

## Rules for all agents
- Do NOT call any `mcp__hearthbot__*` tool. Do not push to git; the lead integrates and pushes.
- Write only inside your own folder. If you need a contract change, write it in `<your folder>/CONTRACT_REQUESTS.md` and code defensively.
- No real attacks against anything but 127.0.0.1. No real command execution from web input.
- Include a `README.md` in your folder with run commands, and smoke tests (`pytest`) where reasonable.
- All synthetic data must be obviously fake (e.g. `Member 0001`).
