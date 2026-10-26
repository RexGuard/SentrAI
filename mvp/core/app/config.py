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

from . import protect  # noqa: E402

cactai_config.load()
DEFAULT_DB = CORE_DIR / "data" / "cactai.db"


def sign(token: str, path: str) -> str:
    """A signature for one read-only path (a report link in an alert), so it opens in a browser
    without the API token. It reveals nothing about the token and works for that path only."""
    return hmac.new(token.encode(), path.encode(), hashlib.sha256).hexdigest()[:32]


def _secret(name: str) -> str:
    """NAME, or the contents of the file named by NAME_FILE (kept where only this service reads it)."""
    path = os.getenv(f"{name}_FILE", "").strip()
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return os.getenv(name, "").strip()


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


def _set(name: str, default: str) -> set[str]:
    return {x.strip() for x in os.getenv(name, default).split(",") if x.strip()}


def _type_hours(text: str) -> dict[str, float]:
    """'lock_user=1, block_ip=4' -> {'lock_user': 1.0, 'block_ip': 4.0}; bad entries are skipped."""
    out: dict[str, float] = {}
    for part in text.split(","):
        key, _, value = part.partition("=")
        try:
            if key.strip():
                out[key.strip()] = float(value)
        except ValueError:
            pass
    return out


@dataclass
class Settings:
    demo_speed: float = field(default_factory=lambda: _f("DEMO_SPEED", 1.0))  # real time; above 1 speeds the timers up for testing
    threshold: int = field(default_factory=lambda: _i("RISK_THRESHOLD", 80))
    sla_hours: float = field(default_factory=lambda: _f("SLA_HOURS", 2.0))
    # How the risk index is kept: "fleet" (default) adds every machine's incidents into one score, as on a
    # single server; "host" scores each machine on its own, so a central panel never blocks a quiet machine
    # because another one is under attack. The headline index is then the worst machine's.
    risk_scope: str = field(default_factory=lambda: "host" if os.getenv("CACTAI_RISK_SCOPE", "fleet").strip().lower()
                            in ("host", "machine", "per-host") else "fleet")
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
    # Slow brute force: failed logins from one IP (web, Windows and SSH together) over a long window.
    slow_brute_force_count: int = field(default_factory=lambda: _i("SLOW_BRUTE_FORCE_COUNT", 20))
    slow_brute_force_window_s: float = field(default_factory=lambda: _f("SLOW_BRUTE_FORCE_WINDOW_S", 86400.0))
    ssh_slow_brute_force_count: int = field(default_factory=lambda: _i("SSH_SLOW_BRUTE_FORCE_COUNT", 10))
    web_scan_4xx_count: int = field(default_factory=lambda: _i("WEB_SCAN_4XX_COUNT", 10))
    web_scan_window_s: float = field(default_factory=lambda: _f("WEB_SCAN_WINDOW_S", 120.0))
    # Close scan / brute-force incidents that have had no new event for this many real minutes (0 = never).
    auto_close_quiet_min: float = field(default_factory=lambda: _f("AUTO_CLOSE_QUIET_MIN", 60.0))
    auto_close_categories: set[str] = field(
        default_factory=lambda: {x.strip() for x in os.getenv("AUTO_CLOSE_CATEGORIES", "port_scan,brute_force").split(",") if x.strip()}
    )
    watchdog_silence_s: float = field(default_factory=lambda: _f("WATCHDOG_SILENCE_S", 30.0))
    tick_s: float = field(default_factory=lambda: _f("TICK_S", 1.0))
    # Integrity guard (integrity.py): how often the audit chain is re-checked, and how big a clock
    # jump (seconds) counts as tampering.
    integrity_check_s: float = field(default_factory=lambda: _f("INTEGRITY_CHECK_S", 30.0))
    clock_jump_s: float = field(default_factory=lambda: _f("CLOCK_JUMP_S", 120.0))
    # Send the signed audit fingerprint to the alert channels this often, in real minutes (0 = never; anchor.py).
    anchor_every_min: float = field(default_factory=lambda: _f("ANCHOR_EVERY_MIN", 60.0))
    # Off-box copy (remote_copy.py): a SentrAI witness on another machine that keeps every audit
    # record and log line where this server's root cannot change them. Empty URL = off.
    remote_copy_url: str = field(default_factory=lambda: os.getenv("CACTAI_REMOTE_COPY_URL", "").strip().rstrip("/"))
    remote_copy_token: str = field(default_factory=lambda: _secret("CACTAI_REMOTE_COPY_TOKEN"))
    remote_copy_ca: str = field(default_factory=lambda: os.getenv("CACTAI_REMOTE_COPY_CA", "").strip())
    id_year: int = field(default_factory=lambda: _i("ID_YEAR", 2026))
    id_start: int = field(default_factory=lambda: _i("ID_START", 81))
    history_len: int = 3600
    jev_timeout_s: float = field(default_factory=lambda: _f("JEV_TIMEOUT_S", 3.0))
    # Jev answers kept per log template (IPs, times and ids stripped); 0 turns the cache off.
    jev_cache_size: int = field(default_factory=lambda: _i("JEV_CACHE_SIZE", 2048))
    jev_cache_ttl_s: float = field(default_factory=lambda: _f("JEV_CACHE_TTL_S", 3600.0))
    needle_min_confidence: float = field(default_factory=lambda: _f("NEEDLE_MIN_CONFIDENCE", 0.6))
    # Never auto-block the demo machine itself (loopback), this machine's DNS servers and gateway
    # (INFRA_AUTODETECT=0 turns that off) or anything in INFRA_ALLOWLIST. Entries may be networks (10.0.0.0/24).
    protected_ips: set[str] = field(
        default_factory=lambda: protect.split(os.getenv("PROTECTED_IPS", "127.0.0.1,::1,localhost"))
        | protect.split(os.getenv("INFRA_ALLOWLIST", ""))
        | (protect.detect_infra() if os.getenv("INFRA_AUTODETECT", "1").strip().lower() not in protect.OFF else set())
    )
    # Private networks: an autonomous block of these waits for a person (an operator can still approve it).
    protected_nets: set[str] = field(default_factory=lambda: protect.nets(os.getenv("PROTECTED_NETS", protect.PRIVATE_NETS)))
    # Admin and service accounts are always protected; PROTECTED_USERS adds more.
    protected_users: set[str] = field(
        default_factory=lambda: protect.split(protect.DEFAULT_USERS) | protect.split(os.getenv("PROTECTED_USERS", ""))
    )
    # Autonomous containment also needs the incident itself to be serious, not only the overall index:
    # its own severity at least CONTAIN_MIN_SEVERITY and its own points at least CONTAIN_MIN_POINTS.
    contain_min_severity: str = field(default_factory=lambda: os.getenv("CONTAIN_MIN_SEVERITY", "high").strip().lower())
    contain_min_points: float = field(default_factory=lambda: _f("CONTAIN_MIN_POINTS", 20.0))
    # Host firewall for block_ip (app/firewall.py): off keeps blocking portal-only; enforce=False is a dry run.
    firewall: str = field(default_factory=lambda: os.getenv("CACTAI_FIREWALL", "off"))
    firewall_enforce: bool = field(
        default_factory=lambda: os.getenv("CACTAI_FIREWALL_ENFORCE", "0").strip().lower() in ("1", "true", "yes", "on")
    )
    # Responder webhook (responders.WebhookResponder): hand these action types to another system by URL.
    responder_webhook_url: str = field(default_factory=lambda: os.getenv("CACTAI_RESPONDER_WEBHOOK_URL", "").strip())
    responder_webhook_actions: tuple[str, ...] = field(default_factory=lambda: tuple(
        x.strip() for x in os.getenv("CACTAI_RESPONDER_WEBHOOK_ACTIONS",
                                     "block_ip,lock_user,rate_limit,waf_rule,kill_process,revoke_public_acl").split(",")
        if x.strip()))
    responder_webhook_secret: str = field(default_factory=lambda: _secret("CACTAI_RESPONDER_WEBHOOK_SECRET"), repr=False)
    responder_webhook_timeout_s: float = field(default_factory=lambda: _f("CACTAI_RESPONDER_WEBHOOK_TIMEOUT_S", 3.0))
    jev_budget_s: float = field(default_factory=lambda: _f("JEV_BUDGET_S", 2.0))
    # Protection switch override at start: "1"/"0", or unset to use the last choice saved in protection.json.
    monitor_only: str | None = field(default_factory=lambda: os.getenv("CACTAI_MONITOR_ONLY"))
    public_url: str = field(default_factory=lambda: os.getenv("CACTAI_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/"))
    background: bool = field(default_factory=lambda: os.getenv("CACTAI_BACKGROUND", "1") != "0")
    # Every endpoint but /health and /blocklist needs it (see main.py). Made and saved on first use.
    api_token: str = field(default_factory=cactai_config.api_token, repr=False)
    # Business limits on protective actions (Countersign and Warden apply them).
    # Action types SentrAI may take on its own; any other type waits for a person to approve it.
    auto_actions: set[str] = field(default_factory=lambda: _set("AUTO_ACTIONS", "block_ip,rate_limit,waf_rule"))
    # Longest any temporary action may last, in hours; HOTPATCH_TTL_HOURS and ACTION_TTL_HOURS are capped to it.
    max_ttl_hours: float = field(default_factory=lambda: _f("MAX_TTL_HOURS", 24.0))
    # Per-type expiry, e.g. "lock_user=1,block_ip=4" (hours). Types not listed use HOTPATCH_TTL_HOURS.
    action_ttl_hours: dict[str, float] = field(default_factory=lambda: _type_hours(os.getenv("ACTION_TTL_HOURS", "")))
    # At most this many automatic actions in any rolling hour (0 = none on its own); past it a person decides.
    max_auto_actions_per_hour: int = field(default_factory=lambda: _i("MAX_AUTO_ACTIONS_PER_HOUR", 10))
    # After-action check: this many timer minutes after an action starts, check it worked and did no harm.
    check_after_min: float = field(default_factory=lambda: _f("CHECK_AFTER_MIN", 10.0))
    # A page that should keep answering while SentrAI blocks things (your site's home page), blank = not probed.
    health_url: str = field(default_factory=lambda: os.getenv("CACTAI_HEALTH_URL", "").strip())
    # A failed undo is retried this often (real seconds), up to this many times, then left to a person.
    undo_retry_s: float = field(default_factory=lambda: _f("UNDO_RETRY_S", 60.0))
    undo_retries: int = field(default_factory=lambda: _i("UNDO_RETRIES", 3))

    def ttl_for(self, action_type: str) -> float:
        """Hours a temporary action of this type lasts, within the business limit."""
        hours = self.action_ttl_hours.get(action_type, self.ttl_hours)
        return max(0.0, min(hours, self.max_ttl_hours)) if self.max_ttl_hours > 0 else max(0.0, hours)
    # One-page client summary (summary.py): daily | weekly | off, local time HH:MM, weekday for weekly,
    # and the name it is addressed to. A choice saved from the dashboard (summary.json) wins over these.
    summary_every: str = field(default_factory=lambda: os.getenv("CACTAI_SUMMARY", "daily"))
    summary_at: str = field(default_factory=lambda: os.getenv("CACTAI_SUMMARY_AT", "08:00"))
    summary_day: str = field(default_factory=lambda: os.getenv("CACTAI_SUMMARY_DAY", "mon"))
    summary_to: str = field(default_factory=lambda: os.getenv("CACTAI_SUMMARY_TO", "Client"))
