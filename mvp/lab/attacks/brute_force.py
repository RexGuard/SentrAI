"""Brute-force attack: N wrong admin passwords against /login.

Attacker IP defaults to 203.0.113.45 (a documentation/test range).
Localhost-only; refuses any other target.

    python -m attacks.brute_force --count 12 --delay 0.3
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402

WRONG_PASSWORDS = [
    "password", "admin123", "letmein", "qwerty", "P@ssw0rd", "welcome1",
    "aegis2024", "changeme", "root", "12345678", "student", "admin",
]


def run(host: str, port: int, count: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("brute_force (admin login)", base, src_ip, count, delay)
    sess = _common.make_session(src_ip)
    for i in range(count):
        pw = WRONG_PASSWORDS[i % len(WRONG_PASSWORDS)]
        try:
            r = sess.post(f"{base}/login", data={"user": "admin", "password": pw},
                          timeout=3)
            print(f"  [{i+1:>3}/{count}] POST /login user=admin pw={pw!r:<12} -> {r.status_code}")
        except Exception as exc:
            print(f"  [{i+1:>3}/{count}] request failed: {exc}")
        time.sleep(delay)
    print("brute_force done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=12, default_delay=0.3,
                              default_src="203.0.113.45")
    a = ap.parse_args()
    run(a.host, a.port, a.count, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
