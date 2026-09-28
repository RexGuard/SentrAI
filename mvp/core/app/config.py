"""Runtime settings, read from environment variables once per engine instance.

Values saved by the setup wizard (``mvp/cactai_config.py``) fill in any variable not set.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(CORE_DIR.parent))
import cactai_config  # noqa: E402

cactai_config.load()
DEFAULT_DB = CORE_DIR / "data" / "cactai.db"


def sign(token: str, path: str) -> str:
    """A signature for one read-only path (a report link in an alert), so it opens in a browser
    without the API token. It reveals nothing about the token and works for that path only."""
    return hmac.new(token.encode(), path.encode(), hashlib.sha256).hexdigest()[:32]


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    demo_speed: float = field(default_factory=lambda: _f("DEMO_SPEED", 60.0))
    threshold: int = field(default_factory=lambda: _i("RISK_THRESHOLD", 80))
    sla_hours: float = field(default_factory=lambda: _f("SLA_HOURS", 2.0))
    ttl_hours: float = field(default_factory=lambda: _f("HOTPATCH_TTL_HOURS", 2.0))
    penalty_per_hour: float = 5.0
    penalty_cap: float = 30.0
    max_reminders: int = 6
    on_duty: str = field(default_factory=lambda: os.getenv("ON_DUTY", "John Doe (SEC-409) / Shift Bravo"))
    team_lead: str = field(default_factory=lambda: os.getenv("TEAM_LEAD", "Team lead"))
    it_manager: str = field(default_factory=lambda: os.getenv("IT_MANAGER", "IT manager"))
    cxo: str = field(default_factory=lambda: os.getenv("CXO", "CXO"))
    db_path: Path = field(default_factory=lambda: Path(os.getenv("CACTAI_DB", str(DEFAULT_DB))))
    brute_force_count: int = field(default_factory=lambda: _i("BRUTE_FORCE_COUNT", 5))
    brute_force_window_s: float = field(default_factory=lambda: _f("BRUTE_FORCE_WINDOW_S", 60.0))
    export_rows_threshold: int = field(default_factory=lambda: _i("EXPORT_ROWS_THRESHOLD", 100))
    # Real public-server traffic: SSH guesses are slower than the demo's web brute force.
    ssh_brute_force_count: int = field(default_factory=lambda: _i("SSH_BRUTE_FORCE_COUNT", 5))
    ssh_brute_force_window_s: float = field(default_factory=lambda: _f("SSH_BRUTE_FORCE_WINDOW_S", 600.0))
    web_scan_4xx_count: int = field(default_factory=lambda: _i("WEB_SCAN_4XX_COUNT", 10))
    web_scan_window_s: float = field(default_factory=lambda: _f("WEB_SCAN_WINDOW_S", 120.0))
    # Close scan / brute-force incidents that have had no new event for this many real minutes (0 = never).
    auto_close_quiet_min: float = field(default_factory=lambda: _f("AUTO_CLOSE_QUIET_MIN", 60.0))
    auto_close_categories: set[str] = field(
        default_factory=lambda: {x.strip() for x in os.getenv("AUTO_CLOSE_CATEGORIES", "port_scan,brute_force").split(",") if x.strip()}
    )
    watchdog_silence_s: float = field(default_factory=lambda: _f("WATCHDOG_SILENCE_S", 30.0))
    tick_s: float = field(default_factory=lambda: _f("TICK_S", 1.0))
    id_year: int = field(default_factory=lambda: _i("ID_YEAR", 2026))
    id_start: int = field(default_factory=lambda: _i("ID_START", 81))
    history_len: int = 3600
    jev_timeout_s: float = field(default_factory=lambda: _f("JEV_TIMEOUT_S", 3.0))
    needle_min_confidence: float = field(default_factory=lambda: _f("NEEDLE_MIN_CONFIDENCE", 0.6))
    # Never auto-block the demo machine itself (loopback) or protected accounts.
    protected_ips: set[str] = field(
        default_factory=lambda: {x.strip() for x in os.getenv("PROTECTED_IPS", "127.0.0.1,::1,localhost").split(",") if x.strip()}
    )
    protected_users: set[str] = field(
        default_factory=lambda: {x.strip() for x in os.getenv("PROTECTED_USERS", "").split(",") if x.strip()}
    )
    # Host firewall for block_ip (app/firewall.py): off keeps blocking portal-only; enforce=False is a dry run.
    firewall: str = field(default_factory=lambda: os.getenv("CACTAI_FIREWALL", "off"))
    firewall_enforce: bool = field(
        default_factory=lambda: os.getenv("CACTAI_FIREWALL_ENFORCE", "0").strip().lower() in ("1", "true", "yes", "on")
    )
    jev_budget_s: float = field(default_factory=lambda: _f("JEV_BUDGET_S", 2.0))
    public_url: str = field(default_factory=lambda: os.getenv("CACTAI_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"))
    background: bool = field(default_factory=lambda: os.getenv("CACTAI_BACKGROUND", "1") != "0")
    # Every endpoint but /health and /blocklist needs it (see main.py). Made and saved on first use.
    api_token: str = field(default_factory=cactai_config.api_token, repr=False)
