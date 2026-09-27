"""Data-exfiltration style traffic: repeated bulk /export calls (off-hours).

Attacker IP defaults to 203.0.113.77. Localhost-only. Sends an
``X-Demo-Hour`` header set to an off-hours value so the demo narration can
say "bulk export at 03:00".

    python -m attacks.exfil --count 4 --delay 0.6
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402

OFF_HOURS = "03"


def run(host: str, port: int, count: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("data_exfiltration (/export, off-hours)", base, src_ip, count, delay)
    sess = _common.make_session(src_ip)
    sess.headers.update({"X-Demo-Hour": OFF_HOURS})
    for i in range(count):
        try:
            r = sess.get(f"{base}/export", timeout=5)
            size = len(r.content)
            print(f"  [{i+1:>3}/{count}] GET /export (off-hours {OFF_HOURS}:00) "
                  f"-> {r.status_code}, {size} bytes")
        except Exception as exc:
            print(f"  [{i+1:>3}/{count}] request failed: {exc}")
        time.sleep(delay)
    print("exfil done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=4, default_delay=0.6,
                              default_src="203.0.113.77")
    a = ap.parse_args()
    run(a.host, a.port, a.count, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
