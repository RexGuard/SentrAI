"""Runtime settings, read from environment variables once per engine instance.

Values saved by the setup wizard (``mvp/cactai_config.py``) fill in any variable not set.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(CORE_DIR.parent))
import cactai_config  # noqa: E402

cactai_config.load()
DEFAULT_DB = CORE_DIR / "data" / "cactai.db"


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
    jev_budget_s: float = field(default_factory=lambda: _f("JEV_BUDGET_S", 2.0))
    public_url: str = field(default_factory=lambda: os.getenv("CACTAI_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"))
    background: bool = field(default_factory=lambda: os.getenv("CACTAI_BACKGROUND", "1") != "0")
    # Monitor-only ("protection off") at start: "1" or "0" wins over the last switch saved in
    # data/protection.json; unset keeps whatever the operator last chose (protection on for a new install).
    monitor_only: str | None = field(default_factory=lambda: os.getenv("CACTAI_MONITOR_ONLY"))
