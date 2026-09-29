"""Cactus spines (design doc section 11): deception and tarpit inside our own portal.

Nothing here touches the attacker's machine. The spines only sit and wait:

* **Honeypot login** ``/admin-legacy``: an old-looking staff sign-in page that no real
  user is ever sent to. It is listed only in ``robots.txt`` as "Disallow", which is
  exactly where scanners look. Opening it is reconnaissance; posting to it is an attack.
  It never logs anyone in.
* **Honeytoken credential**: the honeypot page source carries a "forgotten" service
  account in an HTML comment. The account does not exist anywhere; using it on the
  real ``/login`` proves someone read the page source and is trying to get in.
* **Honeytoken rows**: two bait records in the ``members`` table. Normal staff searches
  never match them (different member number and email domain), but a bulk dump does.
  They catch a quiet export that stays under the volume threshold.
* **Tarpit**: every request to a decoy, and every later request from an IP that touched
  one, is answered only after a delay, so automated attacks become slow and expensive.

Each touch is written to ``deception.jsonl``; the collector ships it to core, where the
rules classify it with confidence 1.0.

Off by default. Turn on with ``CACTAI_SPINES=1`` (``run_demo.ps1 -Spines`` /
``run_demo.sh --spines``). Tarpit delay: ``CACTAI_TARPIT_S`` (default 3 seconds, max 30).
"""
from __future__ import annotations

import os
import threading
import time

HONEYPOT_PATH = "/admin-legacy"

# The "forgotten" service account planted in the honeypot page source.
DECOY_USER = "svc_backup"
DECOY_PASSWORD = "Backup#Aegis2019"

# Bait member rows. Staff search by "Member NNNN" or "@example.com"; these match neither.
HONEYTOKEN_ROWS: tuple[dict[str, str], ...] = (
    {"member_no": "STF-0007", "name": "Registrar (Finance)", "email": "registrar.finance@aegis-academy.example",
     "program": "Staff account"},
    {"member_no": "STF-0012", "name": "Bursar Office", "email": "bursar.office@aegis-academy.example",
     "program": "Staff account"},
)
HONEYTOKEN_IDS = (9001, 9002)
HONEYTOKEN_MEMBER_NOS = frozenset(r["member_no"] for r in HONEYTOKEN_ROWS)

# Kinds written to the deception log. The core rules map each one to a category.
HONEYPOT_PAGE = "honeypot_page"
HONEYPOT_LOGIN = "honeypot_login"
HONEYTOKEN_CREDENTIAL = "honeytoken_credential"
HONEYTOKEN_ROW = "honeytoken_row"

_TRUE = {"1", "true", "yes", "on"}


def enabled_from_env() -> bool:
    return os.environ.get("CACTAI_SPINES", "").strip().lower() in _TRUE


def tarpit_delay_from_env(default: float = 3.0) -> float:
    try:
        value = float(os.environ.get("CACTAI_TARPIT_S", default))
    except ValueError:
        value = default
    return max(0.0, min(30.0, value))


def honeytoken_hits(rows: list[dict]) -> list[str]:
    """Member numbers of the bait rows present in a result set."""
    return [r["member_no"] for r in rows if r.get("member_no") in HONEYTOKEN_MEMBER_NOS]


class Tarpit:
    """Remembers which source IPs touched a spine and slows their requests down."""

    def __init__(self, delay_s: float) -> None:
        self.delay_s = delay_s
        self._pricked: set[str] = set()
        self._lock = threading.Lock()

    def prick(self, ip: str) -> bool:
        """Mark an IP; returns True the first time (the tarpit engages now)."""
        with self._lock:
            if ip in self._pricked:
                return False
            self._pricked.add(ip)
            return True

    def is_pricked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._pricked

    def reset(self) -> None:
        with self._lock:
            self._pricked.clear()

    def hold(self) -> None:
        # Sleep until the monotonic deadline: on Windows one time.sleep() can wake a few ms early.
        end = time.monotonic() + self.delay_s
        while (left := end - time.monotonic()) > 0:
            time.sleep(left)
