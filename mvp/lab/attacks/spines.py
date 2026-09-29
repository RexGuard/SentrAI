"""An intruder walks into the tripwires (needs the portal started with tripwires on).

Reads robots.txt, opens the decoy admin page it lists, tries a login there, reuses the
credential planted in that page's source on the real /login, then dumps /export (which
carries the bait rows). Each step prints how long the portal took to answer, so the
tarpit is visible once the first tripwire is touched. Localhost-only.

    python -m attacks.spines
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402

CREDENTIAL = re.compile(r"login\s+(\S+)\s*/\s*(\S+)\s*-->")


def run(host: str, port: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("tripwires (honeypot, honeytokens, tarpit)", base, src_ip, 5, delay)
    sess = _common.make_session(src_ip)

    def step(label: str, method: str, path: str, **kw):
        t0 = time.monotonic()
        try:
            r = sess.request(method, f"{base}{path}", timeout=60, **kw)
        except Exception as exc:
            print(f"  {label:<44} request failed: {exc}")
            return None
        print(f"  {label:<44} -> {r.status_code}  ({time.monotonic() - t0:.1f}s)")
        time.sleep(delay)
        return r

    robots = step("GET /robots.txt", "GET", "/robots.txt")
    if robots is None or robots.status_code != 200:
        print("Tripwires are off. Start the portal with CACTAI_SPINES=1 (run_demo -Tripwires / --tripwires).")
        return
    decoy = next((line.split(":", 1)[1].strip() for line in robots.text.splitlines()
                  if line.lower().startswith("disallow:")), "/admin-legacy")
    page = step(f"GET {decoy} (decoy page)", "GET", decoy)
    step(f"POST {decoy} user=admin", "POST", decoy, data={"user": "admin", "password": "admin123"})
    m = CREDENTIAL.search(page.text if page is not None else "")
    if m:
        step(f"POST /login with planted '{m.group(1)}'", "POST", "/login",
             data={"user": m.group(1), "password": m.group(2)})
    step("GET /export (carries the bait rows)", "GET", "/export")
    print("tripwires done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=5, default_delay=0.3, default_src="203.0.113.99")
    a = ap.parse_args()
    run(a.host, a.port, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
