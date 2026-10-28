"""Reading real web-server and sshd log lines inside core.

The collector sends a `parsed` object when it understands a line (CONTRACT.md, "Parsed fields").
These helpers read `parsed` first and parse `raw` when it is missing, so the rules also work on
events from an older collector or a replay:

- nginx / Apache "combined" access lines, and the lab portal's short "GET /path 200" form;
- OpenSSH lines as written to auth.log / secure, or as bare journald messages;
- sign-ins to other services (Windows logons and RDP, SQL Server, MySQL/MariaDB, PostgreSQL,
  MongoDB) and Suricata network alerts, which only come as a collector `parsed` object;
- who becomes root and how: sudo and su lines (the command, the account that ran it, its terminal),
  the sessions systemd-logind opens, and the sessions the collector sees with ``who`` (admins.py
  ties a root command to the sign-in it came from).

`enrich()` only fills fields that are missing; it never overwrites what the collector sent.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)"

# 203.0.113.9 - - [28/Sep/2026:14:01:02 +0800] "GET /.env HTTP/1.1" 404 153 "-" "zgrab/0.x"
COMBINED = re.compile(
    r"^" + IP + r"\s+\S+\s+\S+\s+\[[^\]]+\]\s+"
    r"\"(?P<request>[^\"]*)\"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)"
    r"(?:\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
)
REQUEST = re.compile(r"^(?P<method>[A-Z]{3,10})\s+(?P<path>\S+)(?:\s+HTTP/\d(?:\.\d)?)?$")
# Lab portal / replay form: "POST /login 401 user=admin"
SHORT = re.compile(r"^(?P<method>GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)\s+(?P<path>/\S*)\s+(?P<status>\d{3})\b")

# "... port 51234 ssh2: ED25519 SHA256:AbC..." : the key a publickey sign-in used (OpenSSH 6.8 and later).
KEY = r"(?: port \d+)?(?: ssh2(?:: (?P<key_type>[\w-]+) (?P<key_fingerprint>(?:SHA256|MD5):\S+))?)?"
SSHD_PID = re.compile(r"\bsshd(?:-session)?\[(?P<pid>\d+)\]")
SSHD_TAG = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")

# (ssh_event, pattern). First match wins. "user" and "ip" groups where the line has them.
SSH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("accepted", re.compile(r"\bAccepted (?P<method>password|publickey|keyboard-interactive/pam|hostbased) for (?P<user>\S+) from "
                            + IP + KEY)),
    ("failed_password", re.compile(r"\bFailed (?P<method>password|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S*) from "
                                   + IP + KEY)),
    ("invalid_user", re.compile(r"\bInvalid user (?P<user>\S*) from " + IP)),
    ("max_attempts", re.compile(r"\bmaximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from " + IP)),
    ("preauth_close", re.compile(r"\b(?:Connection (?:closed|reset) by|Disconnected from|Disconnecting) (?:invalid|authenticating) user (?P<user>\S*) " + IP + r"\b.*\[preauth\]")),
    ("pam_failure", re.compile(r"\bpam_unix\(sshd:auth\): authentication failure;.*\brhost=" + IP + r"(?:\s+user=(?P<user>\S+))?")),
    ("pam_failure", re.compile(r"\bPAM \d+ more authentication failures?;.*\brhost=" + IP + r"(?:\s+user=(?P<user>\S+))?")),
    ("probe", re.compile(r"\bDid not receive identification string from " + IP)),
    ("probe", re.compile(r"\bbanner exchange: Connection from " + IP + r".*invalid format")),
    ("probe", re.compile(r"\bUnable to negotiate with " + IP)),
    ("probe", re.compile(r"\b(?:kex_exchange_identification|Bad protocol version identification|Protocol major versions differ)\b.*?(?:from )?" + IP)),
    ("probe", re.compile(r"\bConnection (?:closed|reset) by " + IP + r" port \d+ \[preauth\]")),
    ("disconnect", re.compile(r"\b(?:Received disconnect|Disconnected) from (?:user \S+ )?" + IP)),
]
SSH_FAILURES = {"failed_password", "invalid_user", "max_attempts", "preauth_close", "pam_failure"}


# The collector's ssh_event names (CONTRACT.md) -> the ones the rules use.
PARSED_SSH = {
    "accepted": "accepted", "failed_auth": "failed_password", "invalid_user": "invalid_user",
    "user_not_allowed": "invalid_user", "max_auth_exceeded": "max_attempts",
    "auth_failure_pam": "pam_failure", "auth_failures_more": "pam_failure", "pam_check_pass": "pam_failure",
    "no_identification": "probe", "banner_error": "probe", "negotiation_failed": "probe", "bad_protocol": "probe",
    "timeout_preauth": "probe", "received_disconnect": "disconnect", "disconnecting": "disconnect",
}


@dataclass
class HttpLine:
    method: str
    path: str
    status: int | None
    user_agent: str
    src_ip: str | None
    bytes: int | None
    malformed: bool = False  # request line that is not "METHOD /path HTTP/x" (binary, empty, TLS on :80)


@dataclass
class SshLine:
    event: str  # accepted, failed_password, invalid_user, max_attempts, preauth_close, pam_failure, probe, disconnect, other
    src_ip: str | None
    user: str | None
    pid: str | None
    method: str | None = None  # password, publickey, keyboard-interactive/pam, hostbased (accepted and failed lines)
    key_type: str | None = None  # ED25519, RSA, ECDSA ... when sshd logged the key
    key_fingerprint: str | None = None  # "SHA256:..." of the key the sign-in used


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


DEMO_FORMATS = ("sentrai_demo", "cactai_demo")  # the lab portal's lines (cactai_demo: saved before the rename)


def parse_http(event: dict[str, Any]) -> HttpLine | None:
    """The request in an access-log event, or None when the event is not an HTTP access line."""
    raw = str(event.get("raw") or "").strip()
    parsed = event.get("parsed")
    if isinstance(parsed, dict) and parsed.get("kind") == "http_request" and parsed.get("format") not in DEMO_FORMATS:
        path = str(parsed.get("path") or "")
        if parsed.get("query"):
            path += "?" + str(parsed["query"])
        return HttpLine(str(parsed.get("method") or "").upper(), path or str(parsed.get("request") or ""),
                        _int(parsed.get("status")), str(parsed.get("user_agent") or ""), event.get("src_ip"),
                        _int(parsed.get("bytes")), malformed=bool(parsed.get("malformed_request")))
    if event.get("path") and (event.get("http_method") or event.get("method")):
        return HttpLine(str(event.get("http_method") or event.get("method")).upper(), str(event["path"]),
                        _int(event.get("status")), str(event.get("user_agent") or ""), event.get("src_ip"),
                        _int(event.get("bytes")))
    m = COMBINED.match(raw)
    if m:
        req = REQUEST.match(m.group("request"))
        return HttpLine(
            req.group("method") if req else "",
            req.group("path") if req else m.group("request"),
            int(m.group("status")),
            m.group("ua") or "",
            m.group("ip"),
            _int(m.group("bytes")),
            malformed=req is None,
        )
    m = SHORT.match(raw)
    if m:
        return HttpLine(m.group("method"), m.group("path"), int(m.group("status")),
                        str(event.get("user_agent") or ""), event.get("src_ip"), None)
    return None


def is_sshd(event: dict[str, Any]) -> bool:
    parsed = event.get("parsed")
    if isinstance(parsed, dict) and parsed.get("kind") == "ssh":
        return True
    if str(event.get("source") or "").lower() in ("sshd", "ssh", "auth_ssh"):
        return True
    if event.get("ssh_event"):
        return True
    return bool(SSHD_TAG.search(str(event.get("raw") or "")))


def parse_sshd(event: dict[str, Any]) -> SshLine | None:
    """The sshd message in an event, or None when it is not an sshd line."""
    if not is_sshd(event):
        return None
    raw = str(event.get("raw") or "")
    parsed = event.get("parsed") if isinstance(event.get("parsed"), dict) else {}
    m = SSHD_PID.search(raw)
    pid = m.group("pid") if m else next((str(v) for v in (parsed.get("pid"), event.get("pid")) if v), None)
    if parsed.get("kind") == "ssh" and parsed.get("ssh_event"):
        ev = str(parsed["ssh_event"])
        kind = PARSED_SSH.get(ev)
        if ev == "failed_auth" and str(parsed.get("auth_method") or "") == "publickey":
            kind = "other"  # a rejected key before the right one is normal for people with several keys
        elif ev in ("connection_closed", "disconnected", "connection_reset"):
            if parsed.get("preauth"):
                kind = "preauth_close" if event.get("user") or parsed.get("invalid_user") else "probe"
            else:
                kind = "disconnect"
        if kind is not None:
            return SshLine(kind, event.get("src_ip"), event.get("user"), pid, _str(parsed.get("auth_method")),
                           _str(parsed.get("key_type")), _str(parsed.get("key_fingerprint")))
    for kind, rx in SSH_PATTERNS:
        m = rx.search(raw)
        if m:
            gd = m.groupdict()
            return SshLine(kind, gd.get("ip") or event.get("src_ip"), gd.get("user") or event.get("user"), pid,
                           gd.get("method"), gd.get("key_type"), gd.get("key_fingerprint"))
    return SshLine(str(event.get("ssh_event") or "other"), event.get("src_ip"), event.get("user"), pid)


def _str(v: Any) -> str | None:
    return str(v) if v not in (None, "") else None


# ---------------------------------------------------------------- sudo, su, login sessions

SERVICE_ACCOUNTS = {"www-data", "apache", "apache2", "httpd", "nginx", "nobody", "w3wp", "tomcat", "postgres", "mysql",
                    "mariadb", "mongodb", "redis", "daemon", "ftp", "git", "jenkins", "node", "php-fpm", "caddy",
                    "iusr", "network service", "local service"}

# "azureuser : TTY=pts/0 ; PWD=/home/azureuser ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx"
# A refused one carries its reason first: "www-data : user NOT in sudoers ; TTY=... ; COMMAND=/bin/bash",
# "alice : 3 incorrect password attempts ; TTY=... ; COMMAND=...". PWD and USER are not always written.
SUDO_COMMAND = re.compile(
    r"(?P<user>[^\s:]+) : (?:(?P<message>[^;]*?) ; )?TTY=(?P<tty>[^;]*?) ;(?: PWD=(?P<pwd>[^;]*?) ;)?"
    r"(?: USER=(?P<target>[^;]*?) ;)?(?: GROUP=[^;]*? ;)?(?: ENV=[^;]*? ;)? COMMAND=(?P<command>.*)$")
# "pam_unix(sudo:session): session opened for user root(uid=0) by azureuser(uid=1000)" (sudo, su, su-l)
PAM_SESSION = re.compile(
    r"pam_unix\((?P<program>sudo|sudo-i|su|su-l):session\): session (?P<what>opened|closed) for user "
    r"(?P<target>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<user>[^\s(]*)\(uid=(?P<uid>\d+)\))?")
# "pam_unix(sudo:auth): authentication failure; logname=azureuser uid=1000 euid=0 tty=/dev/pts/0 ruser=azureuser rhost=  user=azureuser"
PAM_AUTH_FAILURE = re.compile(
    r"pam_unix\((?P<program>sudo|sudo-i|su|su-l):auth\): authentication failure;.*?\btty=(?P<tty>\S*)"
    r".*?\bruser=(?P<ruser>\S*).*?\buser=(?P<target>\S*)")
SUDO_TAG = re.compile(r"\bsudo(?:\[\d+\])?:\s")
SU_TAG = re.compile(r"\bsu(?:-l)?(?:\[\d+\])?:\s")
# "su: (to root) azureuser on pts/0" / "su: FAILED SU (to root) azureuser on pts/0"
SU_SWITCH = re.compile(r"(?P<failed>FAILED SU )?\(to (?P<target>[^)\s]+)\) (?P<user>\S*) on (?P<tty>\S+)")
LOGIND_TAG = re.compile(r"\bsystemd-logind(?:\[\d+\])?:\s")
LOGIND_NEW = re.compile(r"\bNew session (?P<sid>\S+) of user (?P<user>\S+?)\.?$")
LOGIND_GONE = re.compile(r"\b(?:Removed session (?P<sid>\S+?)\.?|Session (?P<sid2>\S+) logged out\b)")
# The collector's session source ("who" / "quser"): "session started: azureuser on pts/0 from 203.0.113.9 since 2026-10-28 10:01"
WHO_LINE = re.compile(r"^session (?P<what>existing|started|ended): (?P<user>\S+) on (?P<tty>\S+)"
                      r"(?: from (?P<origin>\S+))?(?: since (?P<since>.+))?$")
SUDO_FAILURES = {"not_in_sudoers", "not_allowed", "wrong_password", "auth_failure", "refused"}


@dataclass
class SudoLine:
    """One sudo line: a command run as another user, a refusal, or the session PAM opens around it."""
    event: str  # command, not_in_sudoers, not_allowed, wrong_password, auth_failure, refused, session_opened, session_closed, other
    user: str | None  # the account that ran sudo
    target: str | None  # the account it ran as (root, mostly)
    tty: str | None
    command: str | None
    outcome: str  # success, failure, info
    count: int = 1  # "3 incorrect password attempts"


@dataclass
class SuLine:
    """One su line: a switch to another account, a failed one, or its PAM session."""
    event: str  # switched, failed, auth_failure, session_opened, session_closed, other
    user: str | None
    target: str | None
    tty: str | None
    outcome: str


@dataclass
class LoginSession:
    """A session as logind or the collector's `who` poll reports it."""
    event: str  # existing, started, ended
    user: str | None
    tty: str | None
    origin: str | None  # the address or host name the person came from; None on the console
    sid: str | None  # logind's session number
    since: str | None


def _program(event: dict[str, Any]) -> str:
    p = _parsed(event)
    return str(p.get("program") or "").lower()


def _message(event: dict[str, Any]) -> str:
    """The program's message: parsed.message when the collector split the line, else the raw line."""
    p = _parsed(event)
    return str(p.get("message") or event.get("raw") or "")


def _tty(value: str | None) -> str | None:
    if not value:
        return None
    v = str(value).strip()
    return v.removeprefix("/dev/") if v not in ("", "unknown", "?") else None


def parse_sudo(event: dict[str, Any]) -> SudoLine | None:
    """The sudo line in an event, or None. Reads the collector's `parsed` object first (kind "sudo"),
    then the raw syslog line ("host sudo: user : TTY=..."), then a bare journald message."""
    p = _parsed(event)
    if p.get("kind") == "sudo":
        return SudoLine(str(p.get("sudo_event") or "other"), _str(p.get("by")) or _str(event.get("user")),
                        _str(p.get("target_user")), _tty(_str(p.get("tty"))), _str(p.get("command")),
                        str(p.get("outcome") or "info"), int(p.get("count") or 1))
    raw = str(event.get("raw") or "")
    msg = _message(event)
    if not (_program(event) == "sudo" or SUDO_TAG.search(raw) or ("pam_unix(sudo" in msg)
            or (" ; TTY=" in msg and " COMMAND=" in msg)):
        return None
    if m := PAM_SESSION.search(msg):
        if m.group("program") not in ("sudo", "sudo-i"):
            return None
        return SudoLine(f"session_{m.group('what')}", m.group("user") or None, m.group("target"), None, None, "info")
    if m := PAM_AUTH_FAILURE.search(msg):
        if m.group("program") not in ("sudo", "sudo-i"):
            return None
        return SudoLine("auth_failure", m.group("ruser") or None, m.group("target") or None, _tty(m.group("tty")),
                        None, "failure")
    if m := SUDO_COMMAND.search(msg):
        message = (m.group("message") or "").strip()
        event_name, outcome, count = "command", "success", 1
        if message:
            low = message.lower()
            if "not in sudoers" in low:
                event_name = "not_in_sudoers"
            elif "command not allowed" in low:
                event_name = "not_allowed"
            elif "incorrect password" in low:
                event_name = "wrong_password"
                if n := re.match(r"(\d+) ", message):
                    count = int(n.group(1))
            else:
                event_name = "refused"
            outcome = "failure"
        return SudoLine(event_name, m.group("user"), m.group("target") or None, _tty(m.group("tty")),
                        m.group("command").strip() or None, outcome, count)
    if _program(event) == "sudo" or SUDO_TAG.search(raw):
        return SudoLine("other", _str(event.get("user")), None, None, None, "info")
    return None


def parse_su(event: dict[str, Any]) -> SuLine | None:
    """The su line in an event, or None."""
    p = _parsed(event)
    if p.get("kind") == "su":
        return SuLine(str(p.get("su_event") or "other"), _str(p.get("by")) or _str(event.get("user")),
                      _str(p.get("target_user")), _tty(_str(p.get("tty"))), str(p.get("outcome") or "info"))
    raw = str(event.get("raw") or "")
    msg = _message(event)
    if not (_program(event) in ("su", "su-l") or SU_TAG.search(raw) or "pam_unix(su" in msg):
        return None
    if m := PAM_SESSION.search(msg):
        if m.group("program") not in ("su", "su-l"):
            return None
        return SuLine(f"session_{m.group('what')}", m.group("user") or None, m.group("target"), None, "info")
    if m := PAM_AUTH_FAILURE.search(msg):
        if m.group("program") not in ("su", "su-l"):
            return None
        return SuLine("auth_failure", m.group("ruser") or None, m.group("target") or None, _tty(m.group("tty")), "failure")
    if m := SU_SWITCH.search(msg):
        failed = bool(m.group("failed"))
        return SuLine("failed" if failed else "switched", m.group("user") or None, m.group("target"), _tty(m.group("tty")),
                      "failure" if failed else "success")
    if _program(event) in ("su", "su-l") or SU_TAG.search(raw):
        return SuLine("other", _str(event.get("user")), None, None, "info")
    return None


def parse_login_session(event: dict[str, Any]) -> LoginSession | None:
    """A session the collector saw with `who` (parsed.kind "login_session"), or one systemd-logind
    opened or removed; None for anything else."""
    p = _parsed(event)
    if p.get("kind") == "login_session":
        return LoginSession(str(p.get("session_event") or "existing"), _str(p.get("user")) or _str(event.get("user")),
                            _tty(_str(p.get("tty"))), _str(p.get("origin")), _str(p.get("session_id")), _str(p.get("since")))
    raw = str(event.get("raw") or "")
    msg = _message(event)
    if m := WHO_LINE.match(msg.strip()):
        return LoginSession(m.group("what"), m.group("user"), _tty(m.group("tty")), m.group("origin"), None, m.group("since"))
    if _program(event) == "systemd-logind" or LOGIND_TAG.search(raw):
        if m := LOGIND_NEW.search(msg):
            return LoginSession("started", m.group("user"), None, None, m.group("sid"), None)
        if m := LOGIND_GONE.search(msg):
            return LoginSession("ended", None, None, None, m.group("sid") or m.group("sid2"), None)
    return None


def is_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
        return True
    except ValueError:
        return False


@dataclass
class AuthLine:
    """A sign-in to a service other than sshd (``parsed.kind == "auth"``)."""
    service: str  # windows_logon, rdp, kerberos, ntlm, mssql, mysql, postgres, mongodb
    outcome: str  # success, failure, info
    event: str    # the format's own name: logon_failed, access_denied, password_failed, ...
    src_ip: str | None
    user: str | None


@dataclass
class NetworkAlert:
    """An IDS alert (``parsed.kind == "network_alert"``, Suricata eve.json)."""
    signature: str
    category: str
    severity: int | None
    action: str
    remote_ip: str | None
    dest_port: int | None
    outbound: bool


def _parsed(event: dict[str, Any]) -> dict[str, Any]:
    p = event.get("parsed")
    return p if isinstance(p, dict) else {}


def parse_auth(event: dict[str, Any]) -> AuthLine | None:
    p = _parsed(event)
    if p.get("kind") != "auth":
        return None
    return AuthLine(str(p.get("service") or p.get("program") or p.get("format") or "service"),
                    str(p.get("outcome") or "info"), str(p.get("auth_event") or p.get("win_event") or ""),
                    event.get("src_ip"), event.get("user"))


def parse_network_alert(event: dict[str, Any]) -> NetworkAlert | None:
    p = _parsed(event)
    if p.get("kind") != "network_alert":
        return None
    return NetworkAlert(str(p.get("signature") or ""), str(p.get("alert_category") or ""), _int(p.get("severity")),
                        str(p.get("action") or "allowed"), event.get("src_ip"), _int(p.get("dest_port")),
                        p.get("direction") == "outbound")


def enrich(event: dict[str, Any]) -> dict[str, Any]:
    """Fill src_ip / user / layer / HTTP fields from `raw` when the collector left them out."""
    ssh = parse_sshd(event)
    if ssh is not None:
        if not event.get("src_ip") and ssh.src_ip:
            event["src_ip"] = ssh.src_ip
        if not event.get("user") and ssh.user and ssh.event != "probe":
            event["user"] = ssh.user
        event.setdefault("ssh_event", ssh.event)
        if not event.get("layer") or event.get("layer") == "web":
            event["layer"] = "os"
        return event
    sudo, su = parse_sudo(event), None
    if sudo is None:
        su = parse_su(event)
    who = (sudo or su)
    if who is not None:
        # The person is the account that ran sudo or su, not the one it ran as: an older collector
        # guessed "root" from "USER=root", so that guess gives way to the real account.
        if who.user and (not event.get("user") or event.get("user") == who.target):
            event["user"] = who.user
        if not event.get("layer") or event.get("layer") == "web":
            event["layer"] = "os"
        return event
    session = parse_login_session(event)
    if session is not None:
        if not event.get("user") and session.user:
            event["user"] = session.user
        if not event.get("src_ip") and is_ip(session.origin):
            event["src_ip"] = str(session.origin).strip("[]")
        if not event.get("layer") or event.get("layer") == "web":
            event["layer"] = "os"
        return event
    http = parse_http(event)
    if http is not None:
        if not event.get("src_ip") and http.src_ip:
            event["src_ip"] = http.src_ip
        event.setdefault("http_method", http.method)
        event.setdefault("path", http.path)
        if http.status is not None:
            event.setdefault("status", http.status)
        if http.user_agent:
            event.setdefault("user_agent", http.user_agent)
    return event
