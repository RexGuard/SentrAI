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
from urllib.parse import unquote, unquote_plus

from .netlogs import SSH_FAILURES, HttpLine, parse_http, parse_sshd


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

# --- real public-server traffic (nginx access lines, sshd) --------------------------------
# Paths no normal visitor asks for: secrets, VCS folders, backups, exploit targets.
PROBE_ALWAYS = re.compile(
    r"(/\.(env|git|svn|hg|aws|ssh|docker|htpasswd|htaccess|DS_Store|vscode|idea)\b"
    r"|/\.env\.|/wp-config\.php|/config\.(php|json|ya?ml)\b|/(web|app)\.config\b"
    r"|/phpinfo\.php|/info\.php|/(shell|cmd|c99|r57|wso|alfa)\.php|/eval-stdin\.php|/vendor/phpunit"
    r"|/boaform/|/HNAP1|/GponForm|/setup\.cgi|/goform/"
    r"|/(backup|dump|db|database|site|www|wwwroot)\.(sql|zip|tar|tgz|tar\.gz|bak|7z|rar)\b|\.(sql|bak|old|swp)$"
    r"|/etc/passwd|/proc/self/|\.\./|\?XDEBUG_SESSION_START|allow_url_include|auto_prepend_file)",
    re.I,
)
# Admin panels and CMS paths: a probe only when the server does not have them (4xx).
PROBE_IF_MISSING = re.compile(
    r"^/(wp-(login|admin|content|includes)|xmlrpc\.php|wordpress/|wp/|blog/wp-|phpmyadmin|pma|myadmin|mysqladmin"
    r"|adminer|administrator/|admin\.php|admin/config|user/login|login\.action|console/|api/v1/pods|druid/"
    r"|geoserver/|webui/|hudson|jenkins|cgi-bin/|actuator|jolokia|_ignition/|telescope/|solr/|manager/html"
    r"|owa/|ecp/|autodiscover/|remote/login|sdk\b|evox/|server-status|server-info|\.well-known/(?!acme-challenge|security\.txt|openid|apple-app|assetlinks|change-password|mta-sts))",
    re.I,
)
EXPLOIT_TEXT = re.compile(
    r"\$\{jndi:|\(\)\s*\{\s*:;\s*\};|\b(wget|curl)\s+(-\S+\s+)*https?://|;\s*(wget|curl|chmod|sh)\b|\|\s*(ba)?sh\b"
    r"|\bbase64_decode\(|<\?php|invokefunction|call_user_func_array",
    re.I,
)
SCANNER_UA = re.compile(
    r"\b(zgrab|masscan|nmap|nikto|nuclei|gobuster|dirbuster|dirb|ffuf|feroxbuster|wpscan|whatweb|wfuzz|hydra"
    r"|l9explore|l9tcpid|censysinspect|expanse|internet-measurement|odin\.io|netcraft|zmap|httpx|fuzz faster|xpanse)\b",
    re.I,
)
SQLMAP_UA = re.compile(r"\bsqlmap\b", re.I)
# Crawlers that legitimately hit many dead links; they do not count toward a 404 burst.
GOOD_BOT_UA = re.compile(r"\b(googlebot|bingbot|applebot|duckduckbot|yandexbot|baiduspider|uptimerobot|pingdom|statuscake|better ?uptime)\b", re.I)
HARMLESS_PATH = re.compile(
    r"^/(favicon\.ico|robots\.txt|sitemap[^/]*\.xml|apple-touch-icon[^/]*\.png|ads\.txt|humans\.txt"
    r"|\.well-known/(acme-challenge/|security\.txt|change-password|openid|apple-app|assetlinks|mta-sts))",
    re.I,
)
LOGIN_PATH = re.compile(r"^/(login|signin|sign-in|user/login|users/sign_in|admin/login|auth/login|wp-login\.php|xmlrpc\.php)\b", re.I)


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


def _window_add(dq: deque[tuple[float, str]], ts: float, eid: str, window_s: float) -> list[str]:
    dq.append((ts, eid))
    while dq and ts - dq[0][0] > window_s:
        dq.popleft()
    return [e for _, e in dq]


class RulesEngine:
    def __init__(self, brute_force_count: int = 5, window_s: float = 60.0, export_rows_threshold: int = 100,
                 ssh_count: int = 5, ssh_window_s: float = 600.0,
                 scan_4xx_count: int = 10, scan_window_s: float = 120.0, ssh_probe_count: int = 3) -> None:
        self.brute_force_count = brute_force_count
        self.window_s = window_s
        self.export_rows_threshold = export_rows_threshold
        self.ssh_count = ssh_count
        self.ssh_window_s = ssh_window_s
        self.scan_4xx_count = scan_4xx_count
        self.scan_window_s = scan_window_s
        self.ssh_probe_count = ssh_probe_count
        self._failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._ssh_failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._ssh_attempts: dict[str, dict[str, str]] = defaultdict(dict)  # ip -> {"pid/user": state}
        self._ssh_probes: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._http_4xx: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._checks = 0

    def _prune(self, ts: float) -> None:
        """Forget sources that have been quiet for longer than their window (a server runs for months)."""
        for store, window in ((self._failed, self.window_s), (self._ssh_failed, self.ssh_window_s),
                              (self._ssh_probes, self.ssh_window_s), (self._http_4xx, self.scan_window_s)):
            for key in [k for k, dq in store.items() if not dq or ts - dq[-1][0] > window]:
                del store[key]
                if store is self._ssh_failed:
                    self._ssh_attempts.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            for d in (self._failed, self._ssh_failed, self._ssh_attempts, self._ssh_probes, self._http_4xx):
                d.clear()

    def check(self, event: dict[str, Any], now: float) -> RuleHit | None:
        self._checks += 1
        if self._checks % 2000 == 0:
            with self._lock:
                self._prune(_event_ts(event, now))
        raw = str(event.get("raw") or "")
        text = unquote_plus(raw)
        source = str(event.get("source") or "")

        if source == "heartbeat":
            return RuleHit("benign", "collector heartbeat")
        if BLOCKED.search(text):
            return RuleHit("benign", "request already refused by CactAI blocklist (403)")
        ssh = parse_sshd(event)
        if ssh is not None:
            return self._sshd(event, ssh, now)
        http = parse_http(event)

        for rx in SQLI:
            if rx.search(text):
                return RuleHit("sql_injection", f"SQL injection signature matched: /{rx.pattern}/")
        for rx in XSS:
            if rx.search(text):
                return RuleHit("xss", f"XSS signature matched: /{rx.pattern}/")
        for rx in PRIV_ESC:
            if rx.search(text):
                return RuleHit("privilege_escalation", "web/app process spawned a shell (simulated endpoint, nothing executed)")
        if http is not None:
            hit = self._http(event, http, text, now)
            if hit is not None:
                return hit
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
        if http is not None:
            return self._http_tail(event, http, now)
        if BENIGN_FAST.search(text.strip()):
            return RuleHit("benign", "normal successful request")
        if source == "db_query":
            return RuleHit("benign", "routine database query (no injection signature, below bulk-export threshold)")
        return None

    def _failed_login(self, event: dict[str, Any], now: float, src_ip: str | None = None) -> RuleHit:
        key = src_ip or event.get("src_ip") or event.get("user") or event.get("host") or "unknown"
        ts = _event_ts(event, now)
        eid = str(event.get("event_id"))
        with self._lock:
            ids = _window_add(self._failed[key], ts, eid, self.window_s)
            count = len(ids)
        if count >= self.brute_force_count:
            return RuleHit(
                "brute_force",
                f"{count} failed logins from {key} within {int(self.window_s)} s (threshold {self.brute_force_count})",
                related_event_ids=ids,
            )
        return RuleHit("benign", f"failed login {count}/{self.brute_force_count} from {key}; below brute-force threshold")

    # ------------------------------------------------------------------ web access lines
    def _http(self, event: dict[str, Any], http: HttpLine, text: str, now: float) -> RuleHit | None:
        """Signatures of a real web access line. None lets the older demo rules look at it."""
        path = unquote(http.path)
        status = http.status
        missing = status is not None and 400 <= status < 500
        ip = http.src_ip or event.get("src_ip")
        src = ip or "unknown"
        if SQLMAP_UA.search(http.user_agent):
            return RuleHit("sql_injection", f"SQL injection tool (sqlmap) user agent from {src}")
        if http.malformed:
            return RuleHit("port_scan", f"malformed request line from {src} (binary or non-HTTP probe, status {status})")
        if SCANNER_UA.search(http.user_agent):
            name = SCANNER_UA.search(http.user_agent).group(0)
            return RuleHit("port_scan", f"known scanner user agent '{name}' from {src} requesting {path[:80]}")
        if http.method == "CONNECT" or re.match(r"^https?://", path, re.I):
            return RuleHit("port_scan", f"open-proxy probe from {src}: {http.method} {path[:80]} ({status})")
        if EXPLOIT_TEXT.search(path) or EXPLOIT_TEXT.search(http.user_agent):
            return RuleHit("port_scan", f"exploit probe from {src}: {path[:80]} (status {status})")
        if LOGIN_PATH.match(path) and http.method == "POST" and status is not None and (
                status in (401, 403, 429) or (status == 200 and re.match(r"^/(wp-login\.php|xmlrpc\.php)", path, re.I))):
            # WordPress answers a wrong password with 200 (a success redirects with 302).
            return self._failed_login(event, now, ip)
        if PROBE_ALWAYS.search(path) and not HARMLESS_PATH.match(path):
            exposed = " and the server answered 200: check the file is not exposed" if status == 200 else ""
            return RuleHit("port_scan", f"probe for a sensitive path {path[:80]} from {src} (status {status}){exposed}")
        if missing and PROBE_IF_MISSING.match(path):
            return RuleHit("port_scan", f"probe for an admin/CMS path this server does not have: {path[:80]} from {src} ({status})")
        if EXPORT.search(path) and status is not None and status >= 400:
            return self._http_tail(event, http, now)  # refused or not found: nothing was exported
        return None

    def _http_tail(self, event: dict[str, Any], http: HttpLine, now: float) -> RuleHit:
        """An access line no signature matched: benign, unless one IP collects a burst of 4xx."""
        status = http.status or 0
        src = http.src_ip or event.get("src_ip")
        if 400 <= status < 500 and status != 401 and src and not HARMLESS_PATH.match(http.path) \
                and not GOOD_BOT_UA.search(http.user_agent):
            ts = _event_ts(event, now)
            with self._lock:
                ids = _window_add(self._http_4xx[src], ts, str(event.get("event_id")), self.scan_window_s)
            if len(ids) >= self.scan_4xx_count:
                return RuleHit("port_scan", f"{len(ids)} not-found/refused requests from {src} within "
                                            f"{int(self.scan_window_s)} s (threshold {self.scan_4xx_count}): path scanning",
                               related_event_ids=ids)
            return RuleHit("benign", f"{status} from {src} ({len(ids)}/{self.scan_4xx_count} toward a scan burst)")
        if status >= 500:
            return RuleHit("benign", f"server error {status}, no attack signature")
        return RuleHit("benign", f"normal request ({http.method} {status or 'no status'})")

    # ------------------------------------------------------------------ sshd
    def _sshd(self, event: dict[str, Any], ssh: Any, now: float) -> RuleHit:
        ip = ssh.src_ip or event.get("src_ip")
        ts = _event_ts(event, now)
        eid = str(event.get("event_id"))
        if ssh.event in SSH_FAILURES and ip:
            # One connection writes several lines per guess ("Invalid user X", then "Failed password for
            # invalid user X", then "Connection closed by invalid user X [preauth]"). Count guesses, not lines:
            # every Failed password is a guess, except the one that follows its own "Invalid user" line;
            # the closing lines count only for a connection that logged nothing else (key-only servers).
            key = f"{ssh.pid}/{ssh.user or '?'}" if ssh.pid else None
            with self._lock:
                dq = self._ssh_failed[ip]
                seen = self._ssh_attempts[ip]  # key -> "pending" (Invalid user not yet paired) or "counted"
                state = seen.get(key) if key else None
                if key is None:
                    count_it = ssh.event != "pam_failure"
                elif ssh.event == "invalid_user":
                    count_it = True
                    seen[key] = "pending"
                elif ssh.event == "failed_password":
                    count_it = state != "pending"
                    seen[key] = "counted"
                elif ssh.event in ("preauth_close", "max_attempts"):
                    count_it = state is None
                    seen.setdefault(key, "counted")
                else:  # pam lines always accompany a Failed password line
                    count_it = False
                if count_it:
                    ids = _window_add(dq, ts, eid, self.ssh_window_s)
                else:
                    while dq and ts - dq[0][0] > self.ssh_window_s:
                        dq.popleft()
                    ids = [e for _, e in dq]
                    if eid not in ids:
                        ids.append(eid)
                if not dq or len(seen) > 5000:
                    seen.clear()
                count = len(dq)
            if count >= self.ssh_count:
                return RuleHit("brute_force", f"{count} failed SSH login attempts from {ip} within "
                                              f"{int(self.ssh_window_s)} s (threshold {self.ssh_count}); last user "
                                              f"'{ssh.user or '?'}'", related_event_ids=ids)
            return RuleHit("benign", f"failed SSH login {count}/{self.ssh_count} from {ip}; below brute-force threshold")
        if ssh.event == "accepted" and ip:
            with self._lock:
                dq = self._ssh_failed.get(ip)
                while dq and ts - dq[0][0] > self.ssh_window_s:
                    dq.popleft()
                failures = len(dq) if dq else 0
                ids = [e for _, e in dq] if dq else []
            if failures >= self.ssh_count:
                return RuleHit("brute_force", f"SSH login for '{ssh.user}' from {ip} SUCCEEDED after {failures} failed "
                                              f"attempts: the password may have been guessed", related_event_ids=ids)
            return RuleHit("benign", f"SSH login for '{ssh.user}' from {ip}")
        if ssh.event == "probe" and ip:
            with self._lock:
                ids = _window_add(self._ssh_probes[ip], ts, eid, self.ssh_window_s)
            if len(ids) >= self.ssh_probe_count:
                return RuleHit("port_scan", f"{len(ids)} SSH banner grabs / protocol probes from {ip} within "
                                            f"{int(self.ssh_window_s)} s: scanning", related_event_ids=ids)
            return RuleHit("benign", f"SSH connection from {ip} dropped before login ({len(ids)}/{self.ssh_probe_count})")
        if ip and ssh.event == "disconnect":
            with self._lock:
                dq = self._ssh_failed.get(ip)
                active = bool(dq) and ts - dq[-1][0] <= self.ssh_window_s and len(dq) >= self.ssh_count
            if active:
                return RuleHit("brute_force", f"disconnect during SSH brute force from {ip}")
        return RuleHit("benign", f"sshd: {ssh.event}")
