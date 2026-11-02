# Demo copy of the web console

A copy of the web console that anyone can open without signing in, so people and screen-recording tools
(for the demo video) can look around every page:

**https://rexguard.github.io/SentrAI/demo-copy/**

- It is the real console code, built with `VITE_DEMO_COPY=1`. There is no core behind it: every page reads
  `snapshot.json`, which holds made-up demo data (the demo lab's test attacks against the fake "aegis-web" portal,
  attacker addresses only from the documentation ranges, the account `owner@example.com`).
- Nothing can be changed. Every button that would save something answers "This is a demo copy with made-up data, so
  changes are not saved", and Sentry chat does not answer new questions. Download links (PDF/Markdown) do not work.
- A small note at the bottom says it is a demo copy; its X closes it for a clean recording.
- Page addresses use `#` (for example `.../demo-copy/#/machines/aegis-web`), so it runs as plain files on any host.

## Live attack from the attacker window

The one-button demo's attacker page (RexGuard/SentrAI-demo, `demo-site/attack.html`, online at
https://rexguard.github.io/SentrAI-demo/demo-site/attack.html) can attack this demo copy. Open both in the same
browser, or on two devices, and press its **Launch simulated attack**: after a burst of wrong passwords a Critical **Brute Force** risk
(`RSK-2026-099`) appears on the Command Center, the Critical list and the bell. Every risk card starts at 0 (the recorded open risks are left out of the risk lists and the bell; the
"Already handled" ones stay). SentrAI does not block it on its own
here, so a manager can open it and press **Do the suggested fix** (or **Not a threat**); those two answers are the
only writes the demo copy accepts, and they live in the page only (a reload starts clean). In one browser the pages
talk through a BroadcastChannel with a localStorage fallback; between devices through the public ntfy.sh relay, topic
`sentrai-demo-<room>` (room `solid10`, or `?room=...` in the URL). Only a few state messages go over the relay per
run; the attacker page plays the individual tries itself. Code: the "Live attack" part of
`app/src/lib/demo.ts`.

A normal build never sets the flag, so the real console is unchanged.

## Rebuild it

```bash
./build.sh            # writes the site to demo-copy/ at the repo root; commit that folder
```

`DEMO_COPY_BASE=/other/path/ ./build.sh` builds it for another address.

## Record fresh data

1. Start the demo lab (RexGuard/SentrAI-demo) with this checkout: `./demo.sh --sentrai <this repo> --tripwires --speed 60`.
2. Create the Owner account: `python record/owner.py <setup code>` (writes `acct.json` with the session cookie).
3. Run some attacks: `python scenario.py --tripwires` in the demo lab.
4. Serve the normal console against that core (`VITE_CORE_URL=http://127.0.0.1:8000 npx vite preview` in `../app`),
   then `node record/crawl.mjs` opens every page and tab with Playwright and saves each answer to `snapshot.json`.
5. Check it holds nothing real (no real IPs, host names or folder paths), copy it here and run `./build.sh`.
