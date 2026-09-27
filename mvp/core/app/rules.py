"""Stage 1: deterministic rules engine (signatures + thresholds). Confidence is always 1.0.

Returns None when the rules cannot settle an event (it then goes to Jev / fallback).
Failed logins below the brute-force threshold are held as benign and remembered, so
that when the threshold is hit the whole window is attached to the incident.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import unquote_plus


@dataclass
class RuleHit:
    category: str
    reason: str
    related_event_ids: list[str] = field(default_factory=list)


SQLI = [
    re.compile(r"('|\")\s*(or|and)\s+('?\w+'?)\s*=\s*('?\w+'?)", re.I),  # ' OR 1=1 / ' or 'a'='a
    re.compile(r"\bunion\s+(all\s+)?select\b", re.I),
    re.compile(r"('|\")\s*(;\s*)?--"),  # quote followed by SQL comment
    re.compile(r";\s*(drop|delete|insert|update)\s+\w+", re.I),
    re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d+", re.I),
    re.compile(r"\binformation_schema\b", re.I),
]
XSS = [
    re.compile(r"<\s*script", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"\bon(error|load|mouseover)\s*=", re.I),
    re.compile(r"<\s*(img|svg|iframe)[^>]*\bsrc\s*=", re.I),
]
PRIV_ESC = [
    re.compile(r"shell\s+spawned", re.I),
    re.compile(r"spawn(ed|s)?\s+(a\s+)?(shell|/bin/(ba)?sh|cmd\.exe|powershell)", re.I),
    re.compile(r"\b(www-data|apache|nginx|w3wp)\b.*\b(/bin/(ba)?sh|cmd\.exe)", re.I),
    re.compile(r"\bnew\s+suid\b", re.I),
]
PORT_SCAN = [
    re.compile(r"\bport\s*scan", re.I),
    re.compile(r"\b(nmap|masscan)\b", re.I),
]
MISCONFIG = [
    re.compile(r"\bpublic-read(-write)?\b", re.I),
    re.compile(r"0\.0\.0\.0/0.*\b(22|3389|3306|5432)\b", re.I),
    re.compile(r"\bdefault\s+password\b", re.I),
]
FAILED_LOGIN = [
    re.compile(r"/login\S*\s+401\b", re.I),
    re.compile(r"\b(failed\s+login|login\s+failed|authentication\s+failure|failed\s+password)\b", re.I),
    re.compile(r"\b4625\b"),  # Windows failed logon
]
EXPORT = re.compile(r"/export\b", re.I)
ROWS = re.compile(r"\brows?\s*[=:]\s*(\d+)", re.I)
BULK_DB = re.compile(r"\b(copy\s+\w+\s+to|select\s+\*\s+from\s+members)\b", re.I)
BENIGN_FAST = re.compile(r"^(GET|HEAD)\s+/\S*\s+[23]\d\d\b|^POST\s+/login\S*\s+(200|302)\b", re.I)
BLOCKED = re.compile(r"\s403\b.*\bblocked\b|\bblocked\b.*\s403\b", re.I)


def _event_ts(event: dict[str, Any], fallback: float) -> float:
    ts = event.get("timestamp")
    if isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.astimezone()
            return dt.timestamp()
        except ValueError:
            pass
    return fallback


class RulesEngine:
    def __init__(self, brute_force_count: int = 5, window_s: float = 60.0, export_rows_threshold: int = 100) -> None:
        self.brute_force_count = brute_force_count
        self.window_s = window_s
        self.export_rows_threshold = export_rows_threshold
        self._failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._lock = threading.Lock()

    def reset(self) -> None:
        with self._lock:
            self._failed.clear()

    def check(self, event: dict[str, Any], now: float) -> RuleHit | None:
        raw = str(event.get("raw") or "")
        text = unquote_plus(raw)
        source = str(event.get("source") or "")

        if source == "heartbeat":
            return RuleHit("benign", "collector heartbeat")
        if BLOCKED.search(text):
            return RuleHit("benign", "request already refused by CactAI blocklist (403)")

        for rx in SQLI:
            if rx.search(text):
                return RuleHit("sql_injection", f"SQL injection signature matched: /{rx.pattern}/")
        for rx in XSS:
            if rx.search(text):
                return RuleHit("xss", f"XSS signature matched: /{rx.pattern}/")
        for rx in PRIV_ESC:
            if rx.search(text):
                return RuleHit("privilege_escalation", "web/app process spawned a shell (simulated endpoint, nothing executed)")
        if EXPORT.search(text) or BULK_DB.search(text):
            m = ROWS.search(text)
            rows = int(m.group(1)) if m else None
            if rows is None or rows >= self.export_rows_threshold:
                detail = f"{rows} rows" if rows is not None else "bulk export"
                return RuleHit("data_exfiltration", f"bulk data export detected ({detail})")
            return RuleHit("benign", f"small export ({rows} rows) below threshold {self.export_rows_threshold}")
        for rx in PORT_SCAN:
            if rx.search(text):
                return RuleHit("port_scan", "port-scan signature matched")
        for rx in MISCONFIG:
            if rx.search(text):
                return RuleHit("misconfiguration", "insecure configuration signature matched")
        if any(rx.search(text) for rx in FAILED_LOGIN):
            return self._failed_login(event, now)
        if BENIGN_FAST.search(text.strip()):
            return RuleHit("benign", "normal successful request")
        if source == "db_query":
            return RuleHit("benign", "routine database query (no injection signature, below bulk-export threshold)")
        return None

    def _failed_login(self, event: dict[str, Any], now: float) -> RuleHit:
        key = event.get("src_ip") or event.get("user") or event.get("host") or "unknown"
        ts = _event_ts(event, now)
        eid = str(event.get("event_id"))
        with self._lock:
            dq = self._failed[key]
            dq.append((ts, eid))
            while dq and ts - dq[0][0] > self.window_s:
                dq.popleft()
            count = len(dq)
            ids = [e for _, e in dq]
        if count >= self.brute_force_count:
            return RuleHit(
                "brute_force",
                f"{count} failed logins from {key} within {int(self.window_s)} s (threshold {self.brute_force_count})",
                related_event_ids=ids,
            )
        return RuleHit("benign", f"failed login {count}/{self.brute_force_count} from {key}; below brute-force threshold")
