"""Benign traffic noise: normal logins and searches from a staff IP.

Used to establish a green baseline before an attack. Localhost-only.
Attacker/actor IP defaults to 192.0.2.10 (a normal internal-looking client).

    python -m attacks.benign --count 8 --delay 0.5
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402
from target_app import paths  # noqa: E402


def _admin_password() -> str:
    try:
        return (paths.seed_dir() / "admin_password.txt").read_text(
            encoding="utf-8").strip()
    except Exception:
        return "CactusDemo!2026"


SEARCH_TERMS = ["Member 0001", "member0002", "Member", "example.com"]


def run(host: str, port: int, count: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("benign (normal staff traffic)", base, src_ip, count, delay)
    sess = _common.make_session(src_ip)
    pw = _admin_password()
    for i in range(count):
        try:
            if i % 3 == 0:
                r = sess.get(f"{base}/", timeout=3)
                print(f"  [{i+1:>3}/{count}] GET / -> {r.status_code}")
            elif i % 3 == 1:
                r = sess.post(f"{base}/login",
                              data={"user": "admin", "password": pw}, timeout=3)
                print(f"  [{i+1:>3}/{count}] POST /login (valid) -> {r.status_code}")
            else:
                term = SEARCH_TERMS[i % len(SEARCH_TERMS)]
                r = sess.get(f"{base}/search", params={"q": term}, timeout=3)
                print(f"  [{i+1:>3}/{count}] GET /search q={term!r} -> {r.status_code}")
        except Exception as exc:
            print(f"  [{i+1:>3}/{count}] request failed: {exc}")
        time.sleep(delay)
    print("benign done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=8, default_delay=0.5,
                              default_src="192.0.2.10")
    a = ap.parse_args()
    run(a.host, a.port, a.count, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
