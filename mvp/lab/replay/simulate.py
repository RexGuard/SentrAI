"""REPLAY MODE: post a scripted incident directly to core /events.

Use this when the live attack is flaky during recording. It posts a fixed,
realistic sequence of contract Events (benign baseline -> brute force ->
SQL injection -> simulated shell) straight to core, bypassing the target app
and collector. Say on camera that this is a replay.

    python -m replay.simulate                 (post to core, real-time-ish)
    python -m replay.simulate --dump           (print events, do not post)
    python -m replay.simulate --core http://127.0.0.1:8000 --speed 4
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SGT = timezone(timedelta(hours=8))
HOST = "web-01"

BRUTE_IP = "203.0.113.45"
SQLI_IP = "198.51.100.23"
SHELL_IP = "198.51.100.77"
STAFF_IP = "192.0.2.10"


def _ev(offset_s: int, layer: str, source: str, src_ip, user, raw, crit):
    ts = (datetime.now(SGT) + timedelta(seconds=offset_s)).isoformat(timespec="seconds")
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": ts,
        "host": HOST,
        "layer": layer,
        "source": source,
        "src_ip": src_ip,
        "user": user,
        "raw": raw,
        "asset_criticality": crit,
    }


def build_sequence() -> list[dict]:
    seq: list[dict] = []
    off = 0
    # 1) Benign baseline
    for _ in range(3):
        seq.append(_ev(off, "web", "flask_access", STAFF_IP, "admin",
                       "POST /login 200 user=admin", 1.0))
        off += 1
    # 2) Brute force burst. Same line the portal's access log writes for a wrong
    #    password; the rules count these toward the brute-force threshold.
    for _ in range(10):
        seq.append(_ev(off, "web", "flask_access", BRUTE_IP, "admin",
                       "POST /login 401 user=admin", 1.0))
        off += 1
    # 3) SQL injection on /search
    for payload in ["' OR '1'='1", "' UNION SELECT username, password FROM users --",
                    "1; DROP TABLE members; --"]:
        seq.append(_ev(off, "db", "db_query", SQLI_IP, None,
                       f"SELECT rows=0 q={payload!r}", 1.5))
        off += 1
    # 4) Simulated web shell
    seq.append(_ev(off, "os", "os_process", SHELL_IP, None,
                   "web server spawned shell: whoami", 1.0))
    return seq


def main() -> None:
    ap = argparse.ArgumentParser(description="CactAI replay simulator")
    ap.add_argument("--core", default=os.environ.get("CACTAI_CORE_URL",
                                                      "http://127.0.0.1:8000"))
    ap.add_argument("--speed", type=float, default=6.0,
                    help="events per second when posting")
    ap.add_argument("--dump", action="store_true",
                    help="print the sequence as JSON and exit (no posting)")
    args = ap.parse_args()

    seq = build_sequence()

    print("#" * 62)
    print("#  REPLAY MODE — scripted incident (not a live attack)")
    print(f"#  {len(seq)} events -> {args.core}/events")
    print("#" * 62)

    if args.dump:
        print(json.dumps(seq, indent=2))
        return

    delay = 1.0 / args.speed if args.speed > 0 else 0.0
    sent = 0
    for ev in seq:
        try:
            r = requests.post(f"{args.core.rstrip('/')}/events", json=ev, timeout=3)
            body = r.json() if r.ok else {}
            sent += 1
            print(f"  [{sent:>2}/{len(seq)}] {ev['source']:<12} {ev['raw'][:44]:<44} "
                  f"-> risk={body.get('risk_index', '?')}")
        except Exception as exc:
            print(f"  [!] failed to post event: {exc}")
        time.sleep(delay)
    print(f"REPLAY complete: {sent}/{len(seq)} events posted.")


if __name__ == "__main__":
    main()
