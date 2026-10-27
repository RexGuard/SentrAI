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

from .netlogs import SSH_FAILURES, AuthLine, HttpLine, NetworkAlert, parse_auth, parse_http, parse_network_alert, parse_sshd


@dataclass
class RuleHit:
    category: str
    reason: str
    related_event_ids: list[str] = field(default_factory=list)
    malicious: float | None = None  # None: 1.0 for an attack, 0.0 for benign


SQLI = [
    re.compile(r"('|\")\s*(or|and)\s+('?\w+'?)\s*=\s*('?\w+'?)", re.I),  # ' OR 1=1 / ' or 'a'='a
    re.compile(r"\bunion\s+(all\s+)?select\b", re.I),
    re.compile(r"('|\")\s*(;\s*)?--"),  # quote followed by SQL comment
    re.compile(r";\s*(drop|delete|insert|update)\s+\w+", re.I),
    re.compile(r"\b(sleep|benchmark|pg_sleep)\s*\(\s*\d+", re.I),
    re.compile(r"\binformation_schema\b", re.I),
    re.compile(r"\b(and|or)\s+(\d+)\s*=\s*\2\b", re.I),  # 1 AND 1=1 (numeric tautology, no quote)
    re.compile(r"\w['\"]\s*#\s*(['\"]|$)"),  # admin' #  (quote closed, rest commented out with MySQL #)
    re.compile(r"\b(extractvalue|updatexml)\s*\(|\bconcat\s*\(\s*0x[0-9a-f]+|@@version\b", re.I),  # error-based
]
SQL_COMMENT = re.compile(r"/\*.*?\*/")


def sql_normal(text: str) -> str:
    """Text as the database would read it: inline /**/ comments become spaces, runs of spaces one space."""
    return re.sub(r"\s+", " ", SQL_COMMENT.sub(" ", text))
XSS = [
    re.compile(r"<\s*script", re.I),
    re.compile(r"javascript\s*:", re.I),
    re.compile(r"\bon(error|load|mouseover)\s*=", re.I),
    re.compile(r"<\s*(img|svg|iframe)[^>]*\bsrc\s*=", re.I),
]
# Text aimed at an AI model, not at the web app: someone trying to talk the classifier (or any
# AI reading the logs) into a wrong answer. Checked on web requests only.
PROMPT_INJECTION = [
    re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+|your\s+)*"
               r"(previous|prior|above|earlier|preceding|system)\s+(instructions?|prompts?|rules|messages?|context)", re.I),
    re.compile(r"\b(classify|label|mark|treat|report)\s+(this|it|me|the\s+(request|event|log))\s+as\s+"
               r"(benign|safe|harmless|normal|not\s+malicious)", re.I),
    re.compile(r"\b(this|the)\s+(request|event|log|line)\s+is\s+(benign|safe|harmless)\b.{0,40}\b(ai|model|assistant|classifier)\b", re.I),
    re.compile(r"\b(reveal|print|show|repeat)\s+(me\s+)?(your|the)\s+(system\s+prompt|instructions)", re.I),
    re.compile(r"\byou\s+are\s+now\s+(a|an|in|the|dan)\b", re.I),
    re.compile(r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<</?SYS>>", re.I),
    re.compile(r"(^|[\s\"'])(###\s*)?(system|assistant)\s*(prompt)?\s*:\s*(you|ignore|from\s+now)", re.I),
]
PRIV_ESC = [
    re.compile(r"shell\s+spawned", re.I),
    re.compile(r"spawn(ed|s)?\s+(a\s+)?(shell|/bin/(ba)?sh|cmd\.exe|powershell)", re.I),
    re.compile(r"\b(www-data|apache|nginx|w3wp)\b.*\b(/bin/(ba)?sh|cmd\.exe)", re.I),
    re.compile(r"\bnew\s+suid\b", re.I),
    # A service account trying sudo, or anyone trying sudo straight into a shell, without the right.
    re.compile(r"sudo:\s+(www-data|apache|nginx|nobody|w3wp|tomcat|postgres|mysql|daemon)\s*:.*\bNOT\s+in\s+sudoers\b"
               r"|\bNOT\s+in\s+sudoers\b.*COMMAND=\S*/(ba|z|da)?sh\b", re.I),
]
PORT_SCAN = [
    re.compile(r"\bport\s*scan", re.I),
    re.compile(r"\b(nmap|masscan)\b", re.I),
]
DISTINCT_PORTS = re.compile(r"\b(\d+)\s+distinct\s+ports\b", re.I)
PORT_LIST = re.compile(r"\b(?:closed|blocked|refused|filtered)\s+ports?\s+((?:\d{1,5}\s*,\s*){4,}\d{1,5})\b", re.I)
MISCONFIG = [
    re.compile(r"\bpublic-read(-write)?\b", re.I),
    re.compile(r"0\.0\.0\.0/0.*\b(22|3389|3306|5432)\b", re.I),
    re.compile(r"\bdefault\s+password\b", re.I),
    re.compile(r"\baccess\s+level\s+changed\s+to\s+public\b|\banonymous\s+(read|write|access)\b"
               r"|\bpublic\s+access\s+(enabled|allowed|granted)\b", re.I),
]
# The same words, but the change closes access instead of opening it: a fix, not a misconfiguration.
NARROWED = re.compile(
    r"\b(ingress|allow)\s+rule\s+(removed|deleted|revoked)\b|\brule\s+(removed|deleted|revoked):?\s+(ingress|allow)\b|\bRevoke\w*Ingress\b|\bacl\s*=\s*private\b"
    r"|\baccess\s+level\s+changed\s+to\s+private\b|\bblock\s*public\s*access\s+(enabled|turned\s+on)\b", re.I)
FAILED_LOGIN = [
    re.compile(r"/login\S*\s+401\b", re.I),
    re.compile(r"\b(failed\s+login|login\s+failed|authentication\s+failure|failed\s+password)\b", re.I),
    re.compile(r"\b4625\b"),  # Windows failed logon
]
# Tripwires (lab portal spines.py, design doc section 11; once called "cactus spines"): decoys
# no real user touches, so one touch is enough. kind -> (category, reason).
# The older "cactus_spine" source and "cactus-spine" log prefix are still accepted.
TRIPWIRE_SOURCES = ("tripwire", "cactus_spine")
TRIPWIRE_REASONS = ("Tripwire:", "Cactus spine:")  # classification_reason prefixes, new and old
SPINE = re.compile(r"^(?:tripwire|cactus-spine) (\w+):")
SPINE_KINDS: dict[str, tuple[str, str]] = {
    "honeypot_page": ("port_scan", "reconnaissance: opened a decoy page that is only listed in robots.txt"),
    "honeypot_login": ("brute_force", "sign-in attempted on a decoy login page no real user is sent to"),
    "honeytoken_credential": ("brute_force", "used a planted credential that exists only in a decoy page"),
    "honeytoken_row": ("data_exfiltration", "bait database rows were read (no legitimate query returns them)"),
}
EXPORT = re.compile(r"/export\b", re.I)
REFUSED = re.compile(r"/export\S*\s+403\b", re.I)
ROWS = re.compile(r"\brows?\s*[=:]\s*(\d+)", re.I)
# A whole sensitive table read in one go (no WHERE, no LIMIT): a dump whatever the row count, since a
# small school's members table can be smaller than the bulk-export threshold.
FULL_TABLE = re.compile(r"\bselect\s+\*\s+from\s+[`\"]?(?:\w+\.)?(?P<table>\w+)[`\"]?(?P<rest>[^'\"]*)", re.I)
SENSITIVE_TABLES = {"members", "users", "students", "customers", "accounts", "staff", "employees", "payments",
                    "orders", "patients", "parents", "credentials", "passwords", "cards", "invoices"}
CLOUD_BULK = re.compile(r"\bGetObject\s*x\s*(?P<n>\d+)\b|\b(GetObject|download\w*|egress)\b.*\((?P<gb>\d+(?:\.\d+)?)\s*GB\)", re.I)
BULK_DB = re.compile(r"\b(copy\s+\w+\s+to|select\s+\*\s+from\s+members)\b", re.I)
BENIGN_FAST = re.compile(r"^(GET|HEAD)\s+/[^\n]*?\s[23]\d\d(\s|$)|^POST\s+/login\S*\s+(200|302)\b", re.I)
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
# --- log tampering: wiping, editing or silencing the record (an attacker covering tracks) ----
# Notices from SentrAI itself: the collector saw a log shrink or vanish with no rotated copy, the
# core found its audit chain broken, or a clock jumped. One is enough.
INTEGRITY_SOURCES = ("log_integrity", "audit_integrity")
# --- malware: SentrAI's own threat scan found a web shell, miner, reverse shell etc. (threats.py)
THREAT_SOURCE = "threat_scan"
# --- staff_report: a person at the business reported something (staff_reports.py). Always needs review.
STAFF_SOURCE = "staff_report"
# Paths that hold the record: system logs, shell history, login records, SentrAI's own data.
_LOG_PATH = (r"(?P<path>/var/log/\S*|\S*/\.(bash|zsh|sh|python)_history\b|\S*/\.history\b|/var/run/utmp\b"
             r"|\S*/(\.cactai|\.sentrai|cactai|sentrai)/\S*)")
# Groups that read the record: adm and systemd-journal (logs), cactai/sentrai (SentrAI's own data).
_LOG_GROUP = r"(adm|systemd-journal|cactai|sentrai)"
# Old rotated archives (auth.log.2.gz, syslog-20261001) are routinely deleted to free disk space.
ROTATED_ARCHIVE = re.compile(r"(\.\d+|\.(gz|xz|bz2|zst)|-\d{8})$|\*\.(gz|xz|bz2|zst)$", re.I)
LOG_WIPE = [
    (re.compile(r"\bhistory\s+-[cw]\b|\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHISTSIZE=0\b|\bset\s+\+o\s+history\b"),
     "shell history was cleared or switched off"),
    (re.compile(r"\b(shred|wipe|srm)\b[^\n]*?" + _LOG_PATH, re.I), "log or history file shredded"),
    (re.compile(r"\brm\b[^\n]*?" + _LOG_PATH, re.I), "log or history file deleted"),
    (re.compile(r"\btruncate\b[^\n]*-s\s*0\b[^\n]*?" + _LOG_PATH, re.I), "log file truncated to zero"),
    (re.compile(r"(^|[;&|]\s*|\b(cat\s+/dev/null|echo(\s+-n)?(\s+(''|\"\"))?|true)\s*|(^|\s):\s*)(?<![>\d&])>(?!>)\s*" + _LOG_PATH, re.I),
     "log file emptied by redirection"),
    (re.compile(r"\bsed\s+(-\S+\s+)*-i\S*\s[^\n]*?" + _LOG_PATH, re.I), "log file edited in place"),
    (re.compile(r"\bjournalctl\b[^\n]*--vacuum-(time|size|files)\b", re.I), "systemd journal vacuumed (old entries deleted)"),
    (re.compile(r"\bchattr\s+-[ai]+\b", re.I), "append-only/immutable protection removed from a file"),
    (re.compile(r"\b(systemctl\s+(stop|disable|mask|kill)|service)\s+(\S+\s+)?(r?syslog|rsyslogd?|syslog-ng|auditd"
                r"|systemd-journald|journald|cactai\S*|sentrai\S*)(\.service)?(\s+stop)?\b", re.I),
     "logging or auditing service stopped"),
    (re.compile(r"\b(pkill|killall|kill\s+-9)\b[^\n]*\b(rsyslogd|syslog-ng|auditd|systemd-journald)\b", re.I),
     "logging or auditing process killed"),
    (re.compile(r"\bauditctl\s+(-D\b|-e\s*0\b)", re.I), "audit rules deleted or auditing switched off"),
    (re.compile(r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|\b(Clear|Remove)-EventLog\b", re.I), "Windows event log cleared"),
    (re.compile(r"\b(audit|security|system|event)\s+log\s+was\s+cleared\b", re.I), "Windows event log cleared"),
    # Least privilege undone: someone widens who can read or change the record, or what SentrAI may do.
    (re.compile(r"\busermod\b[^\n]*\s-\w*G\s*(\S*,)?" + _LOG_GROUP + r"(,|\s|$)"
                r"|\bgpasswd\s+-a\s+\S+\s+" + _LOG_GROUP + r"\b"
                r"|\badduser\s+[a-z_][\w.-]*\s+" + _LOG_GROUP + r"\b", re.I),
     "an account was given the groups that read the logs or SentrAI's data"),
    (re.compile(r"\bchmod\s+(-\S+\s+)*([0-7]?[0-7]{2}[2367]|\S*[ao]\+\w*w)\s[^\n]*?" + _LOG_PATH, re.I),
     "a log or SentrAI file was made writable by everyone"),
    (re.compile(r"\bsetfacl\b[^\n]*\s-\w*m\b[^\n]*?" + _LOG_PATH, re.I), "extra access granted on a log or SentrAI file"),
    (re.compile(r"\bsetcap\b[^\n]*\b(cactai|sentrai)", re.I), "extra powers given to a SentrAI program"),
    (re.compile(r"\bsystemctl\s+(edit|set-property|revert)\s+(\S+\s+)?(cactai|sentrai)\S*", re.I),
     "SentrAI's service limits were changed"),
    (re.compile(r"\b(Seal\s*=\s*(no|false|0)|Storage\s*=\s*(none|volatile))\b[^\n]*journald|journald\S*[^\n]*"
                r"\b(Seal\s*=\s*(no|false|0)|Storage\s*=\s*(none|volatile))\b", re.I),
     "journal sealing or saving to disk switched off"),
]


def log_wipe(text: str) -> str | None:
    """Why ``text`` (a command seen on a host) wipes, edits or silences a log; None when it does not."""
    for rx, why in LOG_WIPE:
        for m in rx.finditer(text):
            path = m.groupdict().get("path")
            if path and ROTATED_ARCHIVE.search(path.rstrip("'\";,)")):
                continue
            return why
    return None


# --- sign-ins to other services, Suricata alerts and Windows events (collector `parsed` objects) ---
SERVICE_NAMES = {"windows_logon": "Windows", "rdp": "Remote Desktop", "kerberos": "Windows (Kerberos)",
                 "ntlm": "Windows (NTLM)", "mssql": "SQL Server", "mysql": "MySQL", "postgres": "PostgreSQL",
                 "mongodb": "MongoDB"}
# Suricata signature + classtype text -> category. First match wins; the specific words come first.
SURICATA_CATEGORIES: list[tuple[re.Pattern[str], str]] = [(re.compile(rx, re.I), cat) for rx, cat in [
    (r"sql.?injection|\bsqli\b", "sql_injection"),
    (r"\bxss\b|cross.?site.?script", "xss"),
    (r"\b(malware|trojan|cnc|c2|botnet|ransomware|coin.?miner|cryptominer|mining pool|stratum|backdoor|web.?shell"
     r"|exploit kit|phishing|dropper)\b|command and control", "malware"),
    (r"brute.?forc|password.?guess|excessive (failed )?(login|auth)|login attempts", "brute_force"),
    (r"privilege gain|privilege escalation", "privilege_escalation"),
    (r"exfiltrat|data (leak|theft)", "data_exfiltration"),
    (r"\bscan|network scan|information leak|reconnaissance|\brecon\b|\b(nmap|masscan|zmap)\b|\bsweep\b"
     r"|web application attack|exploit|shellcode", "port_scan"),
]]
# Classtypes and signature families that are notices, not attacks (decoder events, policy, info).
SURICATA_LOW = re.compile(r"not suspicious|unknown traffic|generic protocol command decode|misc activity"
                          r"|corporate privacy violation|non-standard protocol|external ip address"
                          r"|^(ET INFO|ET POLICY|SURICATA) ", re.I)
# Groups whose members can run the machine or the domain (Windows events 4728, 4732, 4756).
PRIVILEGED_GROUPS = re.compile(
    r"^(\S+\\)?(administrators|domain admins|enterprise admins|schema admins|account operators|backup operators"
    r"|server operators|print operators|dnsadmins|group policy creator owners|hyper-v administrators"
    r"|remote desktop users|remote management users|key admins|enterprise key admins)$", re.I)
# A new Windows service that runs a script host, an encoded command or a file from a temp folder.
BAD_SERVICE = re.compile(
    r"\b(powershell|pwsh|mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)(\.exe)?\b|cmd(\.exe)?\s+/[ck]\b"
    r"|\s-(e|en|enc|encodedcommand)\s|frombase64string|%comspec%|\\(temp|tmp|appdata|users\\public|perflogs)\\"
    r"|\\\\[^\\]+\\(admin|c)\$\\|\bpsexesvc\b", re.I)

# The lab portal writes each failed sign-in twice: "POST /login 401" (access log) and "login fail" (auth log).
# The access line is counted; the auth line joins the same burst without counting again.
AUTH_COMPANION = re.compile(r"^login\s+fail\b", re.I)
COMPANION_SOURCES = ("flask_auth",)

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
                 scan_4xx_count: int = 10, scan_window_s: float = 120.0, ssh_probe_count: int = 3,
                 slow_count: int = 20, slow_window_s: float = 86400.0, ssh_slow_count: int = 10) -> None:
        self.brute_force_count = brute_force_count
        self.window_s = window_s
        self.export_rows_threshold = export_rows_threshold
        self.ssh_count = ssh_count
        self.ssh_window_s = ssh_window_s
        self.scan_4xx_count = scan_4xx_count
        self.scan_window_s = scan_window_s
        self.ssh_probe_count = ssh_probe_count
        self.slow_count = slow_count
        self.slow_window_s = slow_window_s
        self.ssh_slow_count = ssh_slow_count  # a public SSH port: nobody legitimate fails this often in a day
        self._failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._ssh_failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._ssh_attempts: dict[str, dict[str, str]] = defaultdict(dict)  # ip -> {"pid/user": state}
        self._ssh_probes: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._http_4xx: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._companions: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self._svc_failed: dict[str, deque[tuple[float, str]]] = defaultdict(deque)  # Windows, RDP, databases
        # Every counted guess from one IP, any source; capped so a day-long flood cannot grow without limit.
        self._slow: dict[str, deque[tuple[float, str]]] = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.Lock()
        self._checks = 0

    def _prune(self, ts: float) -> None:
        """Forget sources that have been quiet for longer than their window (a server runs for months)."""
        for store, window in ((self._failed, self.window_s), (self._ssh_failed, self.ssh_window_s),
                              (self._ssh_probes, self.ssh_window_s), (self._http_4xx, self.scan_window_s),
                              (self._companions, self.window_s), (self._slow, self.slow_window_s),
                              (self._svc_failed, self.ssh_window_s)):
            for key in [k for k, dq in store.items() if not dq or ts - dq[-1][0] > window]:
                del store[key]
                if store is self._ssh_failed:
                    self._ssh_attempts.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            for d in (self._failed, self._ssh_failed, self._ssh_attempts, self._ssh_probes, self._http_4xx,
                      self._companions, self._slow, self._svc_failed):
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
        if source == THREAT_SOURCE:
            return RuleHit("malware", f"Threat scan: {raw.removeprefix('threat-scan ')[:300]}")
        if source == STAFF_SOURCE:
            return RuleHit("staff_report", f"Staff report: {raw.removeprefix('staff-report ')[:300]}", malicious=0.5)
        if source in TRIPWIRE_SOURCES and (m := SPINE.match(raw)) and m.group(1) in SPINE_KINDS:
            category, why = SPINE_KINDS[m.group(1)]
            return RuleHit(category, f"Tripwire: {why}")
        if BLOCKED.search(text):
            return RuleHit("benign", "request already refused by SentrAI blocklist (403)")
        ssh = parse_sshd(event)
        if ssh is not None:
            return self._sshd(event, ssh, now)
        auth = parse_auth(event)
        if auth is not None:
            return self._service_auth(event, auth, now)
        alert = parse_network_alert(event)
        if alert is not None:
            return self._network_alert(alert)
        parsed = event.get("parsed") if isinstance(event.get("parsed"), dict) else {}
        if parsed.get("kind") == "windows_event" and (hit := self._windows(event, parsed)) is not None:
            return hit
        if source in INTEGRITY_SOURCES:
            return RuleHit("log_tampering", f"Log integrity: {raw[:300]}")
        http = parse_http(event)
        if http is None:
            # Only commands seen on the host itself (sudo/auth lines, process scans, shell or audit
            # logs). The same words inside a web request are an exploit probe, not a wiped log.
            if why := log_wipe(raw) or log_wipe(text):  # raw too: decoding turns "o+w" into "o w"
                return RuleHit("log_tampering", f"Log tampering: {why} ({raw.strip()[:200]})")

        if http is not None or event.get("layer") == "web":
            for rx in PROMPT_INJECTION:
                if rx.search(text):
                    return RuleHit("prompt_injection", f"Prompt injection aimed at the AI classifier: /{rx.pattern[:80]}/")
        sql = sql_normal(text)
        for rx in SQLI:
            if rx.search(text) or rx.search(sql):
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
        if http is None and (m := FULL_TABLE.search(sql)) and m.group("table").lower() in SENSITIVE_TABLES \
                and not re.search(r"\b(where|limit|top|fetch\s+first)\b", m.group("rest"), re.I):
            rows = ROWS.search(text)
            detail = f", {rows.group(1)} rows" if rows else ""
            return RuleHit("data_exfiltration", f"whole sensitive table read in one query: {m.group('table')}{detail}")
        if (m := CLOUD_BULK.search(text)) and (int(m.group("n") or 0) >= 500 or float(m.group("gb") or 0) >= 1.0):
            return RuleHit("data_exfiltration", f"mass cloud download ({m.group(0).strip()})")
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
        if (m := DISTINCT_PORTS.search(text)) and int(m.group(1)) >= 20:
            return RuleHit("port_scan", f"one source tried {m.group(1)} different ports")
        if (m := PORT_LIST.search(text)) and (n := len(set(re.findall(r"\d+", m.group(1))))) >= 5:
            return RuleHit("port_scan", f"connections to {n} different ports")
        if NARROWED.search(text):
            return RuleHit("benign", "configuration change that closes access (a fix, not an exposure)")
        for rx in MISCONFIG:
            if rx.search(text):
                return RuleHit("misconfiguration", "insecure configuration signature matched")
        if source in COMPANION_SOURCES and AUTH_COMPANION.search(text.strip()):
            return self._failed_login(event, now, companion=True)
        if any(rx.search(text) for rx in FAILED_LOGIN):
            return self._failed_login(event, now)
        if http is not None:
            return self._http_tail(event, http, now)
        if BENIGN_FAST.search(text.strip()):
            return RuleHit("benign", "normal successful request")
        if source == "db_query" or parsed.get("kind") == "db_query":
            return RuleHit("benign", "routine database query (no injection signature, below bulk-export threshold)")
        if parsed.get("kind") == "windows_event":
            return RuleHit("benign", f"Windows event {parsed.get('event_id')} ({parsed.get('win_event')}), no attack sign")
        if parsed.get("format") in ("mysql", "postgres", "mongodb"):
            return RuleHit("benign", f"{parsed['format']} {parsed.get('level') or 'log'} line, no sign-in or attack sign")
        return None

    def _failed_login(self, event: dict[str, Any], now: float, src_ip: str | None = None,
                      companion: bool = False) -> RuleHit:
        key = src_ip or event.get("src_ip") or event.get("user") or event.get("host") or "unknown"
        ts = _event_ts(event, now)
        eid = str(event.get("event_id"))
        with self._lock:
            if companion:
                _window_add(self._companions[key], ts, eid, self.window_s)
                dq = self._failed[key]
                while dq and ts - dq[0][0] > self.window_s:
                    dq.popleft()
                ids = [e for _, e in dq]
            else:
                ids = _window_add(self._failed[key], ts, eid, self.window_s)
            count = len(ids)
            extra = [e for t, e in self._companions[key] if ts - t <= self.window_s]
            slow = self._slow_add(key, ts, eid, count=not companion)
        if count >= self.brute_force_count:
            return RuleHit(
                "brute_force",
                f"{count} failed logins from {key} within {int(self.window_s)} s (threshold {self.brute_force_count})",
                related_event_ids=list(dict.fromkeys([*ids, *extra, eid])),
            )
        if slow is not None:
            return slow
        what = "second log line of" if companion else ""
        return RuleHit("benign", f"{what} failed login {count}/{self.brute_force_count} from {key}; "
                                 f"below brute-force threshold".strip())

    def _slow_add(self, key: str, ts: float, eid: str, count: bool = True, threshold: int | None = None) -> RuleHit | None:
        """Adds a guess to the long window (caller holds the lock). A hit once one IP passes slow_count."""
        dq = self._slow[key]
        if count:
            ids = _window_add(dq, ts, eid, self.slow_window_s)
        else:
            while dq and ts - dq[0][0] > self.slow_window_s:
                dq.popleft()
            ids = [e for _, e in dq]
        threshold = self.slow_count if threshold is None else threshold
        if threshold and len(ids) >= threshold:
            hours = self.slow_window_s / 3600
            return RuleHit("brute_force", f"slow brute force: {len(ids)} failed logins from {key} within "
                                          f"{hours:g} h (threshold {threshold})",
                           related_event_ids=list(dict.fromkeys([*ids[-50:], eid])))
        return None

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

    # ------------------------------------------------------------------ other services
    def _service_auth(self, event: dict[str, Any], auth: AuthLine, now: float) -> RuleHit:
        """A sign-in to Windows, RDP, SQL Server, MySQL, PostgreSQL or MongoDB. Failures from one address
        (or for one account, when the log has no address) count like SSH guesses: ssh_count within
        ssh_window_s, or ssh_slow_count in a day; a success after that many failures is a guessed password."""
        name = SERVICE_NAMES.get(auth.service, auth.service)
        key = auth.src_ip or (f"{auth.user}@{event.get('host') or 'unknown'}" if auth.user else None)
        ts = _event_ts(event, now)
        eid = str(event.get("event_id"))
        if auth.outcome == "failure" and key:
            with self._lock:
                ids = _window_add(self._svc_failed[key], ts, eid, self.ssh_window_s)
                slow = self._slow_add(key, ts, eid, threshold=self.ssh_slow_count)
            if len(ids) >= self.ssh_count:
                return RuleHit("brute_force", f"{len(ids)} failed {name} sign-ins from {key} within "
                                              f"{int(self.ssh_window_s)} s (threshold {self.ssh_count}); last user "
                                              f"'{auth.user or '?'}'", related_event_ids=ids)
            if slow is not None:
                return slow
            return RuleHit("benign", f"failed {name} sign-in {len(ids)}/{self.ssh_count} from {key}; "
                                     f"below brute-force threshold")
        if auth.outcome == "success" and key:
            with self._lock:
                dq = self._svc_failed.get(key)
                while dq and ts - dq[0][0] > self.ssh_window_s:
                    dq.popleft()
                ids = [e for _, e in dq] if dq else []
            if len(ids) >= self.ssh_count:
                return RuleHit("brute_force", f"{name} sign-in for '{auth.user or '?'}' from {key} SUCCEEDED after "
                                              f"{len(ids)} failed attempts: the password may have been guessed",
                               related_event_ids=ids)
            return RuleHit("benign", f"{name} sign-in for '{auth.user or '?'}' from {key}")
        return RuleHit("benign", f"{name}: {auth.event or 'connection'}")

    @staticmethod
    def _network_alert(alert: NetworkAlert) -> RuleHit | None:
        """A Suricata alert, mapped from its signature and classtype. None (Jev decides) for a serious
        alert no word here explains."""
        where = f"{'to' if alert.outbound else 'from'} {alert.remote_ip or 'unknown'}"
        done = "; Suricata already dropped it" if alert.action == "blocked" else ""
        text = f"{alert.signature} | {alert.category}"
        for rx, category in SURICATA_CATEGORIES:
            if rx.search(text):
                return RuleHit(category, f"Suricata: {alert.signature} ({alert.category or 'no category'}, "
                                         f"severity {alert.severity}) {where}{done}")
        if (alert.severity or 0) >= 3 or SURICATA_LOW.search(alert.category) or SURICATA_LOW.search(alert.signature):
            return RuleHit("benign", f"Suricata notice: {alert.signature} (severity {alert.severity}) {where}")
        return None

    @staticmethod
    def _windows(event: dict[str, Any], p: dict[str, Any]) -> RuleHit | None:
        """Windows events that are an incident on their own. None lets the text rules read the
        rest (a 4688 command line can be a cleared log or a web server starting cmd.exe)."""
        what, user = p.get("win_event"), event.get("user") or "?"
        if what == "log_cleared":
            return RuleHit("log_tampering", f"Windows {p.get('log') or p.get('channel') or 'event'} log was cleared "
                                            f"(event {p.get('event_id')}) by '{user}'")
        if what == "group_member_added":
            group = str(p.get("group") or "")
            if PRIVILEGED_GROUPS.match(group):
                return RuleHit("privilege_escalation", f"'{p.get('member') or '?'}' was added to the Windows group "
                                                       f"'{group}' by '{p.get('by') or '?'}': check this was planned")
            return RuleHit("benign", f"account added to the Windows group '{group}'")
        if what == "malware_detected":
            return RuleHit("malware", f"Microsoft Defender found {p.get('threat') or 'a threat'} in "
                                      f"{p.get('path') or '?'} (severity {p.get('severity') or '?'}, "
                                      f"action {p.get('action') or '?'})")
        if what == "malware_action":
            return RuleHit("benign", f"Microsoft Defender acted on {p.get('threat') or 'a threat'}: {p.get('action') or '?'}")
        if what == "service_installed":
            image = str(p.get("image_path") or "")
            if BAD_SERVICE.search(image):
                return RuleHit("malware", f"new Windows service '{p.get('service_name') or '?'}' runs {image[:200]}: "
                                          f"script hosts, encoded commands and temp folders are how attackers stay on a machine")
            return RuleHit("benign", f"new Windows service '{p.get('service_name') or '?'}' ({image[:120]})")
        if what == "account_created":
            return RuleHit("benign", f"Windows account '{user}' created by '{p.get('by') or '?'}'")
        return None

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
                slow = self._slow_add(ip, ts, eid, count=count_it, threshold=self.ssh_slow_count)
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
            if slow is not None:
                return slow
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
