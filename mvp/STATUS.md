# SentrAI MVP status (27 Sep 2026)

**The MVP is complete and verified end to end.** See [README.md](README.md) to run it.

| Part | State | Tests |
| --- | --- | --- |
| `core/` | Done. Review fixes applied: loopback never blocked, protected users, Jev time budget, whole-word fallback rules, routine DB queries benign, robust reset, absolute report links, threshold peak kept on the chart | 23 passed |
| `lab/` | Done | 30 passed |
| `dashboard/`, `notifier/` | Done; verified against the real core in the browser (Make Permanent, report, audit feed) | 12 + 8 passed |
| `run_demo.ps1` / `stop_demo.ps1` | Done; starts and stops all five components | manual run OK |
| `integration/test_e2e.py` | Done; full story on real components | 1 passed |
| `pitch/`, `research/` | Done | n/a |
| `deck/`, `assets/` | Not built (scripts started; see their STATUS.md) | n/a |
| `../docs/` site pages | Not built (see `../docs/STATUS.md`) | n/a |

Still open (not needed for the MVP): a TypeSafe API key to try Jev live, a Telegram bot token to try Telegram mode, the PowerPoint deck and video images.
