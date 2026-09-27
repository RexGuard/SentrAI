---
title: Docs work status
---

# Docs task status (stopped on user request)

## Done
- Read inputs: `Cybersecurity + AI.md`, `mvp/CONTRACT.md`, `mvp/research/SOURCES.md`, `_config.yml`, `README.md`.
- Surveyed `mvp/` code: core routes in `mvp/core/app/main.py` (contract endpoints plus extras: `/incidents/{id}/why`, `/notifications`, `/agents`, `/helpdesk/why`, `/heartbeat`, `/demo/advance`).
- Env vars found: core `DEMO_SPEED` (60), `RISK_THRESHOLD` (80), `SLA_HOURS`, `HOTPATCH_TTL_HOURS`, `ON_DUTY`, `TEAM_LEAD`, `IT_MANAGER`, `CXO`, `CACTAI_DB`, `PROTECTED_IPS`, `JEV_TIMEOUT_S`; `TYPESAFE_API_KEY` (core Jev client, optional); notifier `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `CACTAI_OPERATOR`, `NOTIFIER_POLL_SECONDS`; all components `CACTAI_CORE_URL`.
- Created `docs/` (this file only).

## Not done
- `docs/setup.md`, `run-demo.md`, `architecture.md`, `api.md`, `ethics.md`, `sources.md` not written.
- `README.md` Documentation section not updated.
- `_config.yml` not edited (needs `exclude:` for `mvp/**/.venv`, `**/__pycache__`, `mvp/**/data`, `mvp/**/logs`; also `.pytest_cache`).
- `mvp/pitch/*` and component internals not read; no link lint / Jekyll build run.
- Note: `mvp/run_demo.ps1` and per-component `README.md` files did not exist yet.

## How to resume
Re-run the original docs task; the facts above save re-reading config. Each page needs front matter `title:` and a nav line `[Home](../)`; link docs from README as `docs/setup.html` etc.; embed the diagram as `../mvp/pitch/architecture.svg`.
