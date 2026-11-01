# Performance check of the web console

Re-run it after big changes:

```bash
# 1. a throwaway core (own database, nothing real in it)
cd mvp/core && SENTRAI_DB=/tmp/perf/s.db SENTRAI_CONFIG=/tmp/perf/c.json SENTRAI_BACKGROUND=0 SENTRAI_MIGRATE=off \
  SENTRAI_API_TOKEN=t CYANIDE_ENABLED=0 python -m uvicorn app.main:app --port 8100 &
# 2. fake traffic (100 events per batch, 20 machines), then time every page's data
python ../web/perf/seed.py 40 && python ../web/perf/bench.py
# 3. page loads in a real browser (build + preview first: ../run-web.sh); needs a signed-in-capable account
SIGNIN_EMAIL=... SIGNIN_PASSWORD=... node ../web/perf/pages.js <authenticator code>
```

`bench.py` asks each page's endpoint 40 times in a row (p50, p95), then 40 more with 20 at once.
`pages.js` signs in, opens all 20 pages and prints how long each takes to go quiet, how many calls it made and any
console errors.

## Faster loading (1 Nov 2026)

The panel felt slow on a real network with machines connected because of how much it sent, not how long the core
took. Opening the Command center downloaded about 1.9 MB (the whole console as one 883 KB file, every incident with
its full timeline for the chat box, 2.2 MB uncompressed, plus the full Incidents and Approvals lists to show eight
rows each), and the 10 s refresh downloaded about 1 MB again. Now:

- `serve.py` compresses the console's files and the core's answers (gzip, 10 to 50 times smaller for JSON) and
  answers a refresh whose data did not change with "304, nothing changed" and no body (ETag).
- The console is split per page (`React.lazy`): the first load fetches the shell and the page asked for, the rest
  is fetched quietly a few seconds later. Chat and its Markdown renderer load when first used.
- The Command center asks `/ui/incidents?brief=8` and `/ui/approvals?brief=8`; the chat and Manager view ask
  `/incidents?fields=...` for the few keys they use.

`load.js` (Chromium, 914 incidents, the Command center, before → after):

| | First load, local | First load, 20 Mbit/s and 60 ms | Data per 10 s refresh |
| --- | --- | --- | --- |
| Before | 0.45 s, 4.1 MB | 1.59 s, 1.9 MB | 939 KB |
| After | 0.5 s, 0.27 MB | 0.71 s, 0.27 MB | 3 KB |

### Long tables (1 Nov 2026, later)

Approvals and Incidents drew every row: about 14,000 page elements with 914 items, redrawn on each refresh that
changed anything. They now draw 50 rows with Show more / Show all (`useShowMore` in `lib/Filters.tsx`); search and
filters still cover every row. The audit chain's once-a-minute full re-check (Overview, Audit trail) now runs in
the background (`verify_recent(wait=False)`), a chunk at a time, so it never holds up a page or new records.

| Page (914 items, CPU slowed 4x like a laptop) | Before | After |
| --- | --- | --- |
| Approvals | 3.1 s, 13,900 elements | 1.0 s, 1,300 elements |
| Incidents | 2.9 s, 12,800 elements | 0.8 s, 1,000 elements |

## Results (31 Oct 2026, one core process, 1 vCPU sandbox, Chromium headless)

**Browser, 20 pages, 4,000 events in the core:** zero console errors on all 20 pages. First paint of the sign-in
page 0.6 s cold. Each page is ready (network quiet, incl. a 500 ms idle wait) in 0.55 to 0.95 s; the real work is
under 0.4 s. Slowest pages: Approvals 0.94 s, Reports 0.93 s, Overview 0.82 s. A page makes 2 to 11 calls (Collector 11).

**Bundle:** one JS file of 774 KB (227 KB gzipped) and one CSS file of 20 KB (5 KB gzipped). Vite warns about the
500 KB limit. Splitting the canvases and the charts into their own files would cut the first load by about half.

**Core, answer time per page (one request at a time, p50 / p95):**

| Endpoint | 2.3k audit records | 14k audit records | Size at 14k |
| --- | --- | --- | --- |
| `/ui/overview` | 82 / 124 ms | **433 / 483 ms** | 14 KB |
| `/ui/audit` | 70 / 118 ms | **439 / 600 ms** | 11 KB |
| `/ui/incidents` | 33 / 39 ms | 51 / 66 ms | 286 KB |
| `/ui/approvals` | 20 / 33 ms | 57 / 111 ms | 159 KB |
| `/ui/machines` | 3 / 6 ms | 7 / 12 ms | 0.5 KB |
| `/risk` | 4 / 5 ms | 7 / 10 ms | 35 KB |
| other pages (limits, routing, settings, report, setup, backups, admins, ...) | 2 to 4 ms | not re-run | under 20 KB |

Ingest: about 1,000 events per second on this machine (4,000 events in 3.7 s; 30,000 in 47 s).

## What it shows

1. **Overview and Audit trail get slower with the size of the record, about 30 ms per 1,000 audit records.**
   Each load re-checks the whole tamper-evident chain (`audit.verify()` re-reads and re-hashes every record). At
   14k records that is 0.4 s per page load, and with 20 people or tabs at once the same call takes about 10 s.
   Everything else stays under 120 ms. This is the one thing worth fixing: check the new records on each load and
   the full chain every minute or so, and keep showing the last full result in between. That changes how soon a
   quietly edited old record shows up on these two pages (up to a minute), so it is a call for Erick, not made here.
2. **Incidents and Approvals send everything** (286 KB and 159 KB at 260 incidents). Fine for a demo, worth
   paging or trimming once a machine has thousands.
3. **Single core process:** requests run one after another, so 20 at once is the sum of the single times.
   Cheap pages stay fast (200 to 600 requests per second).
