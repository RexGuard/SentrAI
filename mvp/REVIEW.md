# CactAI MVP review (PARTIAL)

Status: PARTIAL. The user asked to stop early. When the review stopped, no component had a README.md yet, so none was marked finished.
Reviewed so far: `core/app/*.py` only (main, saguaro, agents, rules, classifier, jev_client, audit, clock, risk, config, part of reports) against `CONTRACT.md`.
Not reviewed: `lab/` (target_app, collector, attacks, replay), `dashboard/`, `notifier/`, and all tests. Cross-component checks (field names and JSON shapes the consumers expect) are still TODO.

Issues are ranked by severity. Line numbers refer to the files as they were when read.

---

## HIGH

### H1. Autonomous containment can block 127.0.0.1 and lock the demo `admin` account (breaks the demo on camera)
- `core/app/config.py:52-54`: `PROTECTED_IPS` is empty by default.
- `core/app/agents.py:358` is the only place protected IPs are checked, and it covers only `block_ip`.
- `core/app/agents.py:176,180,181`: the playbooks for brute_force, privilege_escalation and data_exfiltration also `lock_user @user`.
- **Failure:** if any attack script or the presenter's browser sends traffic without `X-Demo-Src-IP`, `src_ip` is `127.0.0.1`. When risk reaches 80, Needle approves `block_ip 127.0.0.1`. The target app then returns 403 to every local request, including the presenter's browser and the benign traffic generator, for the TTL (2 demo hours, which is 2 real minutes at DEMO_SPEED=60). Brute force against `admin` also locks `admin`, so the presenter cannot log in to show "normal" use afterwards.
- **Fix:** make the default `PROTECTED_IPS` `127.0.0.1,::1,localhost`. Add a `protected_users` set (for example `PROTECTED_USERS` env, default empty or `admin` as the demo needs) and check `lock_user` targets against it in `Needle.review`. The lab attack scripts should always send `X-Demo-Src-IP` with a 203.0.113.x / 198.51.100.x address.

### H2. Jev is called synchronously for every event the rules cannot classify (on-camera latency)
- `core/app/saguaro.py:190-191`, `core/app/classifier.py:426`, `core/app/jev_client.py:322-323`.
- **Failure:** when `TYPESAFE_API_KEY` is set, every event the rules miss (for example `POST /login 200` variants that `BENIGN_FAST` misses, or DB and OS lines) blocks the `POST /events` request for up to 3.5 s, one event after another. A 50-event batch from the collector can take minutes. The dashboard risk gauge then lags visibly, and the collector may time out and re-send. The circuit breaker opens only after 3 consecutive *failures*, so slow successes never trip it.
- **Fix:** put a total time budget on each `/events` request (for example 2 s; after that, use `fallback_classify` for the rest), or classify in a background thread pool. Also skip Jev for events already known to be low-signal (`source == "flask_access"` with a 2xx or 3xx status).

### H3. `/audit` response shape differs from the contract
- `core/app/main.py:147-157` returns `{"chain_valid", "first_invalid_seq", "count", "head_hash", "records": [...]}`.
- `CONTRACT.md:69` says "records `[{seq,ts,type,data,prev_hash,hash}]` + `{"chain_valid": bool}`". That wording is ambiguous, and a consumer might iterate over the response as a list.
- **Fix:** have the lead clarify the shape in CONTRACT.md as the object form that core returns. Then check that `dashboard/cactai_ui/api.py` reads `resp["records"]` and `resp["chain_valid"]`. (This consumer check was not done.)

---

## MEDIUM

### M1. `/demo/reset` swaps the audit DB file while other threads may be using it (Windows)
- `core/app/audit.py:107-119`, `core/app/saguaro.py:836-845`.
- The swap is protected by the audit lock and the connection is closed before `Path.replace`, so it is safe inside the process. On Windows, however, `replace` fails with `PermissionError` (WinError 32) if any other process has `data/cactai.db` open. Examples are a DB browser or a second uvicorn started by mistake with `--reload` or a stale window. The reset then returns 500 and leaves `self._conn` as `None`, so every later append fails with an `AssertionError`.
- **Fix:** wrap the call in try/except. On failure, reopen the original DB and start a new chain in a fresh file named with a timestamp (for example `cactai-<stamp>.db`) instead of renaming. Never leave `_conn` as `None`.

### M2. Fallback classifier keywords produce false positives
- `core/app/classifier.py:385-391`: the substrings `"acl"`, `"scan"`, `"copy "`, `"dump"` and `"select "` are matched against the whole raw line. For example, `/search?q=oracle` matches `acl`, and a search containing "select " matches too.
- **Failure:** with Jev disabled (the default when there is no key), a benign search can open a misconfiguration or SQLi incident on camera.
- **Fix:** use word-boundary regexes (`\bacl\b`, `\bport scan\b`), or run the fallback only for `layer in (os, network, cloud)`.

### M3. Notification text contains emoji (U+26A0 U+FE0F, U+1F335)
- `core/app/saguaro.py:444,623`.
- **Failure:** any consumer that `print()`s these strings on a Windows console using cp1252 (the notifier's console fallback, or collector logs) raises `UnicodeEncodeError` and may crash its polling loop. Telegram itself is fine.
- **Fix:** consumers should call `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` at startup, or `run_demo.ps1` should set `$env:PYTHONIOENCODING="utf-8"` and `PYTHONUTF8=1`. Notifier console output has not been checked yet.

### M4. Report and notification links are relative paths
- `core/app/saguaro.py:424,625` sets `report_url` to `/reports/{id}.md` with no host.
- **Failure:** in Telegram this is not a clickable link, and a dashboard that renders it as a link resolves it against :8501, which gives a 404.
- **Fix:** add a `CORE_PUBLIC_URL` setting (default `http://127.0.0.1:8000`) and emit absolute URLs, or have consumers prefix the core base URL.

---

## LOW

- **L1.** `core/app/main.py:204-207` `/heartbeat`, and `/demo/advance`, `/agents`, `/incidents/{id}/why`, `/helpdesk/why`, `/notifications` are extra endpoints not in the contract. They are harmless, but the lead should add them to CONTRACT.md so that dashboard, notifier and lab do not invent their own variants.
- **L2.** `core/app/saguaro.py:219,226`: incidents are merged by `src_ip or user or host`. If the brute force and the later exfil come from the same spoofed IP, they are separate incidents (by category), which is fine. But two different attackers without `X-Demo-Src-IP` both become `127.0.0.1` and merge into one incident (see H1).
- **L3.** `core/app/risk.py:184` gives benign severity `"info"`. The contract lists only low/medium/high/critical. This is harmless because benign never opens an incident.
- **L4.** The contract's risk formula says "− resolved incidents". Core instead excludes contained, resolved and rejected incidents from raw (`RISK_STATUSES`, `saguaro.py:37`). This is equivalent in effect, but contained incidents drop to 0 immediately, so the gauge falls sharply right after autonomous action. That is good on camera, but it should be noted in the pitch.
- **L5.** No security issues found in core: there is no subprocess, shell or network call except the optional TypeSafe SDK; all containment is app-level blocklist records (`agents.py:289-325`); there are no hardcoded secrets (the key comes from `TYPESAFE_API_KEY`). Not yet checked: `lab/seed/admin_password.txt` (a committed password file, which needs to be confirmed as a fake demo value) and `lab/target_app` `/admin/run` (which must never execute anything).

---

## TODO (not done because of the early stop)
1. `lab/target_app`: confirm `/admin/run` never executes, that the SQLite `/search` is not injectable beyond the fake table, that the blocklist is polled every 2 s and fails open, that `X-Demo-Src-IP` is used, and that log lines include `rows=N` for `/export` (core `rules.py:61` needs `rows=` or `rows:`) and the word `blocked` on 403 (core `rules.py:64`).
2. `lab/collector`: POST target `http://127.0.0.1:8000/events`, field names, heartbeat via `POST /heartbeat {"collector": ...}`, Windows file tailing (encoding and file-sharing locks while Flask writes the `.jsonl`).
3. `lab/attacks`: confirm every request targets 127.0.0.1 only.
4. `dashboard`: check that the fields it reads match core (`risk_index`, `band`, `history[].t`, incident `timeline`, `actions[].status`, audit `records`), and the decision/rollback/permanent/ack bodies.
5. `notifier`: check that it uses `id` (not `notification_id`) from `/notifications/pending`, sends a `channel` field on delivered, uses callback button `action` values `approve|reject|ack|rollback|permanent`, and that reject sends a justification (core returns 400 without one, `saguaro.py:681`). Also check that the Telegram token comes from env and is not hardcoded.
6. Run each component's pytest.
