"""Full CactAI demo story against the LIVE target app.

Order: benign baseline -> brute force -> pause -> SQL injection.
Prints narration between phases so it can drive the recording.

Prerequisites (separate terminals):
    1. python -m target_app          (target app on :5000)
    2. python -m collector.collector (collector -> core :8000)
    3. core running on :8000

Run:
    python scenario.py
    python scenario.py --pause 6 --host 127.0.0.1
"""
from __future__ import annotations

import argparse
import time

from attacks import benign, brute_force, sqli


def narrate(text: str) -> None:
    print()
    print("~" * 62)
    print(f"  {text}")
    print("~" * 62)


def countdown(seconds: float, why: str) -> None:
    print(f"\n  [pause] {why} ({seconds:.0f}s)…")
    time.sleep(seconds)


def main() -> None:
    ap = argparse.ArgumentParser(description="CactAI live demo scenario")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--pause", type=float, default=6.0,
                    help="seconds to wait after brute force (operator 'ignores' it)")
    args = ap.parse_args()
    h, p = args.host, args.port

    narrate("PHASE 1 — Baseline. Normal staff traffic. Dashboard should stay green.")
    benign.run(h, p, count=6, delay=0.5, src_ip="192.0.2.10")

    narrate("PHASE 2 — Brute force on the admin login (attacker 203.0.113.45). "
            "Risk should jump to Amber and an incident should open.")
    brute_force.run(h, p, count=12, delay=0.3, src_ip="203.0.113.45")

    narrate("PHASE 3 — Operator IGNORES the alert. The inaction penalty ticks the "
            "gauge upward while nobody acts.")
    countdown(args.pause, "letting the inaction penalty accrue")

    narrate("PHASE 4 — SQL injection on /search (attacker 198.51.100.23). "
            "Risk should cross into Red/Critical and trigger containment.")
    sqli.run(h, p, count=6, delay=0.4, src_ip="198.51.100.23")

    narrate("SCENARIO COMPLETE — check the dashboard for the incident queue, the "
            "risk gauge, the negligence report and the audit chain.")


if __name__ == "__main__":
    main()
