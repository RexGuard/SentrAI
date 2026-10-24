# Lab — STATUS

The demo parts of the lab (the fake "Aegis Academy" portal, attack scripts, scripted replay,
`scenario.py`, seed data and `fake_core.py`) were removed on 24 Oct 2026 so SentrAI can be
tested on real logs. They are still in the git history before that date.

## What is here
- `collector/` — tails the JSON-lines logs and approved server logs (nginx, sshd, journald),
  normalizes them to contract Events and ships them to core `/events`.
- `scout/` — finds the security logs on a new system.
- `tests/` — `.\.venv\Scripts\python.exe -m pytest -q`.
