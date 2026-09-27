"""Simulated web-shell attempt: /admin/run?cmd=whoami

The target app NEVER executes the command; it only logs an OS-layer
"web server spawned shell" event. Localhost-only.
Attacker IP defaults to 198.51.100.77.

    python -m attacks.shell --count 3 --delay 0.5
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from attacks import _common  # noqa: E402

COMMANDS = ["whoami", "id", "cat /etc/passwd", "uname -a"]


def run(host: str, port: int, count: int, delay: float, src_ip: str) -> None:
    base = _common.guard_or_exit(host, port)
    _common.banner("privilege_escalation (simulated web shell)", base, src_ip, count, delay)
    print("  NOTE: the target app logs these but never executes them.")
    sess = _common.make_session(src_ip)
    for i in range(count):
        cmd = COMMANDS[i % len(COMMANDS)]
        try:
            r = sess.get(f"{base}/admin/run", params={"cmd": cmd}, timeout=3)
            print(f"  [{i+1:>3}/{count}] GET /admin/run?cmd={cmd!r} -> {r.status_code} (simulated)")
        except Exception as exc:
            print(f"  [{i+1:>3}/{count}] request failed: {exc}")
        time.sleep(delay)
    print("shell done.")


def main() -> None:
    ap = _common.build_parser(__doc__, default_count=3, default_delay=0.5,
                              default_src="198.51.100.77")
    a = ap.parse_args()
    run(a.host, a.port, a.count, a.delay, a.src_ip)


if __name__ == "__main__":
    main()
