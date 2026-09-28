"""Parsers for real server log lines: nginx access/error logs, syslog (sshd and friends), journald JSON.

``parse_line(line, fmt)`` returns a ``Parsed`` (the log's own timestamp, host, source IP and user,
plus a ``fields`` dict that becomes the Event's ``parsed`` object), or None when the line is not in
a format we know. ``fmt`` is the format recorded in ``scout/sources.json``: "nginx", "syslog",
"journald", "jsonl", or "text"/"auto" (try each parser in turn). The field names are listed in
``mvp/CONTRACT.md`` under "Parsed fields".

Stdlib only. Lines without a time zone (classic syslog, nginx error log) are read in the log
machine's zone: ``CACTAI_LOG_TZ`` (an IANA name such as "Asia/Singapore", or "+08:00"), otherwise
this computer's local zone.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any
from urllib.parse import unquote

MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}


@dataclass
class Parsed:
    fields: dict[str, Any]
    ts: str | None = None           # ISO 8601 with offset, from the log line itself
    host: str | None = None         # host name written in the line (syslog/journald), if any
    src_ip: str | None = None
    user: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)  # parser-private (journald cursor)


# ---------------------------------------------------------------- time zones

_OFFSET = re.compile(r"^(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})?$")


def log_tz(name: str | None = None) -> tzinfo:
    """The zone for log lines that carry none: CACTAI_LOG_TZ, else this computer's local zone."""
    name = name if name is not None else os.environ.get("CACTAI_LOG_TZ", "").strip()
    if name:
        if name.upper() in ("UTC", "Z", "GMT"):
            return timezone.utc
        if m := _OFFSET.match(name):
            sign = -1 if m.group(1) == "-" else 1
            return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0)))
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except Exception:  # unknown name or no tz database (Windows without tzdata)
            pass
    return datetime.now().astimezone().tzinfo or timezone.utc


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _local(dt: datetime, tz: tzinfo | None) -> datetime:
    """Attach the log machine's zone to a naive time (handles DST via zoneinfo)."""
    return dt.replace(tzinfo=tz or log_tz())


def _syslog_time(mon: str, day: str, hms: str, tz: tzinfo | None, now: datetime | None) -> str | None:
    """'Sep  8 14:02:11' has no year: take this year, or last year if that lands in the future
    (a December line read in January)."""
    month = MONTHS.get(mon[:3].title())
    if month is None:
        return None
    zone = tz or log_tz()
    now = now or datetime.now(zone)
    try:
        h, mi, s = (int(x) for x in hms.split(":"))
        dt = datetime(now.year, month, int(day), h, mi, s, tzinfo=zone)
    except ValueError:  # Feb 29 in a non-leap year, bad numbers
        return None
    if dt - now > timedelta(days=2):
        dt = dt.replace(year=dt.year - 1)
    return _iso(dt)


# ---------------------------------------------------------------- nginx

# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
# Anything after the user agent (custom log_format extras) is ignored.
NGINX_ACCESS = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<ruser>\S+) \[(?P<time>[^\]]+)\] "(?P<request>(?:[^"\\]|\\.)*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-)(?: "(?P<referrer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
    r'(?P<rest>.*)$')
NGINX_TIME = "%d/%b/%Y:%H:%M:%S %z"
REQUEST = re.compile(r"^(?P<method>[A-Z][A-Z_-]{1,15}) (?P<target>\S+)(?: (?P<proto>[A-Z]+/[\d.]+))?$")
# 2026/09/28 14:02:11 [error] 1234#1234: *5 open() "/var/www/html/.env" failed (2: ...), client: 203.0.113.9, ...
NGINX_ERROR = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<pid>\d+)#\d+: "
    r"(?:\*\d+ )?(?P<msg>.*)$")
ERR_KV = re.compile(r', (client|server|request|upstream|host|referrer): "?((?:[^",]|\\")*)"?')


def _unescape(s: str | None) -> str | None:
    if s is None or s == "-":
        return None
    return s.replace('\\"', '"').replace("\\\\", "\\")


def _split_target(target: str) -> tuple[str, str | None]:
    path, _, query = target.partition("?")
    return path, (query or None)


def parse_nginx_access(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    m = NGINX_ACCESS.match(line)
    if not m:
        return None
    try:
        ts = _iso(datetime.strptime(m["time"], NGINX_TIME))
    except ValueError:
        return None
    request = _unescape(m["request"]) or ""
    f: dict[str, Any] = {"format": "nginx_access", "kind": "http_request", "request": request or None,
                         "method": None, "path": None, "query": None, "protocol": None,
                         "status": int(m["status"]), "bytes": int(m["bytes"]) if m["bytes"] != "-" else 0,
                         "referrer": _unescape(m["referrer"]), "user_agent": _unescape(m["ua"]),
                         "malformed_request": False}
    if r := REQUEST.match(request):
        path, query = _split_target(r["target"])
        f.update(method=r["method"], path=unquote(path), query=query, protocol=r["proto"])
    else:
        # Empty request, TLS handshake bytes sent to port 80, raw junk: a scanner, not a browser.
        f["malformed_request"] = True
    ruser = None if m["ruser"] == "-" else m["ruser"]
    return Parsed(f, ts=ts, src_ip=m["ip"], user=ruser)


def parse_nginx_error(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    m = NGINX_ERROR.match(line)
    if not m:
        return None
    try:
        dt = datetime.strptime(f'{m["date"]} {m["time"]}', "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    kv = {k: _unescape(v) for k, v in ERR_KV.findall(m["msg"])}
    message = ERR_KV.split(m["msg"], maxsplit=1)[0] if kv else m["msg"]
    f: dict[str, Any] = {"format": "nginx_error", "kind": "http_error", "level": m["level"], "pid": int(m["pid"]),
                         "message": message, "request": kv.get("request"), "method": None, "path": None,
                         "query": None, "server": kv.get("server"), "vhost": kv.get("host")}
    if kv.get("request") and (r := REQUEST.match(kv["request"])):
        path, query = _split_target(r["target"])
        f.update(method=r["method"], path=unquote(path), query=query)
    return Parsed(f, ts=_iso(_local(dt, tz)), src_ip=kv.get("client"))


# ---------------------------------------------------------------- syslog + sshd

# "Sep 28 14:02:11 host prog[123]: msg"  (RFC 3164, Debian/Ubuntu/RHEL default)
SYSLOG_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<hms>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")
# "2026-09-28T14:02:11.123456+08:00 host prog[123]: msg"  (rsyslog high-precision, Debian 12+/Ubuntu 24.04)
SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) "
    r"(?P<prog>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$")

SSHD_PROGRAMS = {"sshd", "sshd-session", "sshd-auth"}  # OpenSSH 9.8+ splits sshd into sshd-session
IP = r"(?P<ip>[0-9a-fA-F:.]+(?:%\w+)?)"
PORT = r"port (?P<port>\d+)"
USER = r"(?P<user>\S*)"  # may be empty: "Invalid user  from ..."

# Order matters: first match wins. Each entry: (ssh_event, regex, outcome).
# outcome: "success", "failure" (an authentication attempt that failed), or "info".
SSHD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [(ev, re.compile(rx), out) for ev, rx, out in [
    ("accepted", rf"^Accepted (?P<method>[\w-]+) for {USER} from {IP}(?: {PORT})?", "success"),
    ("failed_auth", rf"^Failed (?P<method>[\w-]+) for (?P<invalid>invalid user )?{USER} from {IP}(?: {PORT})?",
     "failure"),
    ("invalid_user", rf"^Invalid user {USER} from {IP}(?: {PORT})?", "failure"),
    ("max_auth_exceeded",
     rf"^(?:error: )?maximum authentication attempts exceeded for (?P<invalid>invalid user )?{USER} from {IP} {PORT}",
     "failure"),
    ("auth_failure_pam",
     r"^pam_unix\(sshd:auth\): authentication failure;.*?\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?", "failure"),
    ("auth_failures_more",
     r"^PAM (?P<count>\d+) more authentication failures?;.*?\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?", "failure"),
    ("pam_check_pass", r"^pam_unix\(sshd:auth\): check pass; user unknown", "failure"),
    ("user_not_allowed",
     rf"^User {USER} from {IP} not allowed because (?P<reason>.+)$", "failure"),
    ("connection_closed",
     rf"^Connection closed by (?:(?P<phase>invalid|authenticating) user {USER} )?{IP} {PORT}", "info"),
    ("disconnected",
     rf"^Disconnected from (?:(?P<phase>invalid|authenticating) user {USER} |user (?P<user2>\S+) )?{IP} {PORT}",
     "info"),
    ("disconnecting",
     rf"^Disconnecting (?:(?P<phase>invalid|authenticating) user {USER} )?{IP} {PORT}: (?P<reason>.*?)(?: \[preauth\])?$",
     "info"),
    ("received_disconnect", rf"^Received disconnect from {IP} {PORT}:(?P<code>\d+): (?P<reason>.*?)(?: \[preauth\])?$",
     "info"),
    ("connection_reset", rf"^Connection reset by (?:(?P<phase>invalid|authenticating) user {USER} )?{IP} {PORT}",
     "info"),
    ("no_identification", rf"^Did not receive identification string from {IP}(?: {PORT})?", "info"),
    ("banner_error",
     rf"^(?:error: )?(?:kex_exchange_identification|banner exchange): (?:Connection from {IP} {PORT}: )?(?P<reason>.*)$",
     "info"),
    ("negotiation_failed", rf"^Unable to negotiate with {IP} {PORT}: (?P<reason>.*)$", "info"),
    ("timeout_preauth", rf"^Timeout before authentication for (?:connection from )?{IP}(?: to \S+)?(?:,? {PORT})?",
     "info"),
    ("bad_protocol", rf"^Bad protocol version identification .*? from {IP}(?: {PORT})?", "info"),
    ("connection_from", rf"^Connection from {IP} {PORT} on \S+ port \d+", "info"),
    ("session_opened", r"^pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)", "success"),
    ("session_closed", r"^pam_unix\(sshd:session\): session closed for user (?P<user>[^\s(]+)", "info"),
]]


def parse_sshd_message(msg: str) -> dict[str, Any]:
    """sshd message text -> parsed fields. Unrecognised messages get ssh_event "other"."""
    f: dict[str, Any] = {"kind": "ssh", "ssh_event": "other", "outcome": "info", "auth_method": None,
                         "invalid_user": False, "preauth": "[preauth]" in msg, "port": None,
                         "_ip": None, "_user": None}
    for event, rx, outcome in SSHD_PATTERNS:
        m = rx.search(msg)
        if not m:
            continue
        g = {k: v for k, v in m.groupdict().items() if v is not None}
        user = g.get("user") if g.get("user") is not None else g.get("user2")
        f.update(ssh_event=event, outcome=outcome, _ip=g.get("ip"), _user=user,
                 port=int(g["port"]) if g.get("port") else None)
        if "method" in g:
            f["auth_method"] = g["method"]
        if event == "invalid_user" or g.get("invalid") or g.get("phase") == "invalid":
            f["invalid_user"] = True
        if "count" in g:
            f["count"] = int(g["count"])
        if "reason" in g:
            f["reason"] = g["reason"]
        if event in ("auth_failure_pam", "auth_failures_more"):
            f["auth_method"] = "password"
        break
    if f["_ip"] in ("", "UNKNOWN"):
        f["_ip"] = None
    return f


def _program_fields(prog: str, pid: str | None, msg: str) -> tuple[dict[str, Any], str | None, str | None]:
    f: dict[str, Any] = {"program": prog, "pid": int(pid) if pid else None, "message": msg}
    ip = user = None
    if prog in SSHD_PROGRAMS:
        ssh = parse_sshd_message(msg)
        ip, user = ssh.pop("_ip"), ssh.pop("_user")
        f.update(ssh)
    else:
        f["kind"] = "log"
    return f, ip, user or None


def parse_syslog(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    if m := SYSLOG_BSD.match(line):
        ts = _syslog_time(m["mon"], m["day"], m["hms"], tz, now)
    elif m := SYSLOG_ISO.match(line):
        try:
            dt = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        except ValueError:
            return None
        ts = _iso(dt if dt.tzinfo else _local(dt, tz))
    else:
        return None
    f, ip, user = _program_fields(m["prog"], m["pid"], m["msg"])
    return Parsed({"format": "syslog", **f}, ts=ts, host=m["host"], src_ip=ip, user=user)


# ---------------------------------------------------------------- journald

def parse_journald(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """One line of ``journalctl -o json``."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or "MESSAGE" not in rec:
        return None
    msg = rec["MESSAGE"]
    if isinstance(msg, list):  # journald sends non-UTF-8 messages as byte arrays
        msg = bytes(x for x in msg if isinstance(x, int)).decode("utf-8", "replace")
    ts = None
    if (us := rec.get("__REALTIME_TIMESTAMP")) and str(us).isdigit():
        ts = _iso(datetime.fromtimestamp(int(us) / 1_000_000, tz or log_tz()))
    prog = rec.get("SYSLOG_IDENTIFIER") or rec.get("_COMM") or "journald"
    f, ip, user = _program_fields(str(prog), rec.get("_PID") or rec.get("SYSLOG_PID"), str(msg))
    f["unit"] = rec.get("_SYSTEMD_UNIT")
    return Parsed({"format": "journald", **f}, ts=ts, host=rec.get("_HOSTNAME"), src_ip=ip, user=user,
                  extra={"cursor": rec.get("__CURSOR")})


# ---------------------------------------------------------------- dispatch

PARSERS = {
    "nginx": (parse_nginx_access, parse_nginx_error),
    "nginx_access": (parse_nginx_access,),
    "nginx_error": (parse_nginx_error,),
    "syslog": (parse_syslog,),
    "sshd": (parse_syslog,),
    "journald": (parse_journald,),
}
AUTO = (parse_nginx_access, parse_syslog, parse_nginx_error)


def parse_line(line: str, fmt: str = "auto", tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """Parse one log line. ``fmt`` "text"/"auto" tries nginx, then syslog, then the nginx error log."""
    for parser in PARSERS.get(fmt, AUTO):
        if (p := parser(line, tz, now)) is not None:
            return p
    return None
