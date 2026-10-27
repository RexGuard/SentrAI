# Extensions

Outside services SentrAI works with, one folder each. SentrAI runs with none of them, and each one
can be added or removed on the dashboard's Extensions page while SentrAI runs.

| Folder | What it does | Parts |
| --- | --- | --- |
| `cloudflare/` | Blocks attackers at Cloudflare's edge, and takes the blocks out again | core |
| `typesafe/` | Jev (TypeSafe System One), an AI classifier step | core |
| `telegram/` | Alerts with buttons in Telegram, and personal chats | core (links), notifier (the bot) |
| `slack/` | A copy of every alert in a Slack channel | core (test), notifier |
| `abuseipdb/` | Reputation of each attacking address on its incident | core |

Each folder has `extension.json` (what it is, its settings), `core.py` and/or `notifier.py`, and
`tests/`. `mvp/sentrai_extensions.py` finds them; `python sentrai_extensions.py` lists them.

Tests, from this folder (`Scripts/python.exe` on Windows):

```bash
../core/.venv/bin/python -m pytest -q --ignore-glob='*_notifier.py'
../notifier/.venv/bin/python -m pytest -q --ignore-glob='*_core.py'
```

How to write one: [docs/extensions.md](../../docs/extensions.md#write-your-own).
