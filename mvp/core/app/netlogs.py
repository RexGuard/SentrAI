"""Reading real web-server and sshd log lines inside core.

The collector sends a `parsed` object when it understands a line (CONTRACT.md, "Parsed fields").
These helpers read `parsed` first and parse `raw` when it is missing, so the rules also work on
events from an older collector or a replay:

- nginx / Apache "combined" access lines, and the lab portal's short "GET /path 200" form;
- OpenSSH lines as written to auth.log / secure, or as bare journald messages.

`enrich()` only fills fields that are missing; it never overwrites what the collector sent.
"""

from __future__ import annotations

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

SSHD_PID = re.compile(r"\bsshd(?:-session)?\[(?P<pid>\d+)\]")
SSHD_TAG = re.compile(r"\bsshd(?:-session)?(?:\[\d+\])?:")

# (ssh_event, pattern). First match wins. "user" and "ip" groups where the line has them.
SSH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("accepted", re.compile(r"\bAccepted (?:password|publickey|keyboard-interactive/pam|hostbased) for (?P<user>\S+) from " + IP)),
    ("failed_password", re.compile(r"\bFailed (?:password|keyboard-interactive/pam|none) for (?:invalid user )?(?P<user>\S*) from " + IP)),
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


def _int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def parse_http(event: dict[str, Any]) -> HttpLine | None:
    """The request in an access-log event, or None when the event is not an HTTP access line."""
    raw = str(event.get("raw") or "").strip()
    parsed = event.get("parsed")
    if isinstance(parsed, dict) and parsed.get("kind") == "http_request" and parsed.get("format") != "cactai_demo":
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
            return SshLine(kind, event.get("src_ip"), event.get("user"), pid)
    for kind, rx in SSH_PATTERNS:
        m = rx.search(raw)
        if m:
            gd = m.groupdict()
            return SshLine(kind, gd.get("ip") or event.get("src_ip"), gd.get("user") or event.get("user"), pid)
    return SshLine(str(event.get("ssh_event") or "other"), event.get("src_ip"), event.get("user"), pid)


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
