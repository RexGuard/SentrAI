"""SQL-injection-style payloads against /search?q=

Attacker IP defaults to 198.51.100.23. Localhost-only.
The target app is parameter-safe; these payloads exist to be *logged* and
classified, not to actually breach the DB.

    python -m attacks.sqli --count 6 --delay 0.4
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402

PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT username, password FROM users --",
    "1; DROP TABLE members; --",
    "' OR 1=1 LIMIT 50 --",
    "admin'--",
    "%' UNION SELECT email, program FROM members --",
]


def run(host: str, port: int, count: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("sql_injection (/search)", base, src_ip, count, delay)
    sess = _common.make_session(src_ip)
    for i in range(count):
        payload = PAYLOADS[i % len(PAYLOADS)]
        try:
            r = sess.get(f"{base}/search", params={"q": payload}, timeout=3)
            print(f"  [{i+1:>3}/{count}] GET /search q={payload!r} -> {r.status_code}")
        except Exception as exc:
            print(f"  [{i+1:>3}/{count}] request failed: {exc}")
        time.sleep(delay)
    print("sqli done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=6, default_delay=0.4,
                              default_src="198.51.100.23")
    a = ap.parse_args()
    run(a.host, a.port, a.count, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
