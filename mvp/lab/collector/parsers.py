"""Parsers for real server log lines: nginx access/error logs, syslog (sshd, sudo, su, systemd-logind and
friends), journald JSON, Windows Event Log records, Suricata eve.json alerts, and MySQL/MariaDB,
PostgreSQL and MongoDB logs; plus the output of ``who`` and ``quser`` (who is signed in right now).

``parse_line(line, fmt)`` returns a ``Parsed`` (the log's own timestamp, host, source IP and user,
plus a ``fields`` dict that becomes the Event's ``parsed`` object), or None when the line is not in
a format we know. ``fmt`` is the format recorded in ``scout/sources.json``: "nginx", "syslog",
"journald", "winevent", "suricata", "mysql", "postgres", "mongodb", "jsonl", or "text"/"auto"
(try nginx and syslog in turn). A ``Parsed`` with ``extra["drop"]`` is a line the format writes but
SentrAI has no use for (Suricata flow records, MongoDB storage notes): the collector skips it. The field names are listed in
``mvp/CONTRACT.md`` under "Parsed fields".

Stdlib only. Lines without a time zone (classic syslog, nginx error log) are read in the log
machine's zone: ``SENTRAI_LOG_TZ`` (an IANA name such as "Asia/Singapore", or "+08:00"), otherwise
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
    """The zone for log lines that carry none: SENTRAI_LOG_TZ, else this computer's local zone."""
    name = name if name is not None else os.environ.get("SENTRAI_LOG_TZ", "").strip()
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
# "... port 51234 ssh2: ED25519 SHA256:..." : the key a publickey sign-in used (OpenSSH 6.8 and later; a
# certificate reads "ED25519-CERT SHA256:... ID ..."). Older servers wrote nothing after "ssh2".
KEY = r"(?: ssh2(?:: (?P<key_type>[\w-]+) (?P<key_fingerprint>(?:SHA256|MD5):\S+))?)?"

# Order matters: first match wins. Each entry: (ssh_event, regex, outcome).
# outcome: "success", "failure" (an authentication attempt that failed), or "info".
SSHD_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [(ev, re.compile(rx), out) for ev, rx, out in [
    ("accepted", rf"^Accepted (?P<method>[\w/-]+) for {USER} from {IP}(?: {PORT})?{KEY}", "success"),
    ("failed_auth", rf"^Failed (?P<method>[\w/-]+) for (?P<invalid>invalid user )?{USER} from {IP}(?: {PORT})?{KEY}",
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
                         "key_type": None, "key_fingerprint": None,
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
        if g.get("key_fingerprint"):
            f.update(key_type=g.get("key_type"), key_fingerprint=g["key_fingerprint"])
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


# ---------------------------------------------------------------- sudo, su, systemd-logind

# Who became root, and how. The Event's ``user`` is always the account that ran sudo or su, never the
# account it ran as ("USER=root"): the core ties the command to that person's sign-in.
SU_PROGRAMS = {"su", "su-l"}
# "erick : TTY=pts/0 ; PWD=/home/erick ; USER=root ; COMMAND=/usr/bin/systemctl stop sentrai-core"
# A refused one carries its reason first: "erick : user NOT in sudoers ; TTY=pts/0 ; ... ; COMMAND=/bin/bash",
# "erick : 3 incorrect password attempts ; TTY=...". PWD, USER, GROUP and ENV are not always written, and
# sudo pads the message with spaces.
SUDO_COMMAND = re.compile(
    r"^\s*(?P<user>[^\s:]+) : (?:(?P<message>[^;]*?) ; )?TTY=(?P<tty>[^;]*?) ;(?: PWD=(?P<pwd>[^;]*?) ;)?"
    r"(?: USER=(?P<target>[^;]*?) ;)?(?: GROUP=[^;]*? ;)?(?: ENV=[^;]*? ;)? COMMAND=(?P<command>.*)$")
SUDO_REFUSALS = (("not in sudoers", "not_in_sudoers"), ("not allowed", "not_allowed"),
                 ("incorrect password", "wrong_password"))
# "pam_unix(sudo:session): session opened for user root(uid=0) by erick(uid=1000)" (sudo, sudo-i, su, su-l);
# older PAM wrote "session opened for user root by erick(uid=1000)" or "... by (uid=1000)".
PAM_SESSION = re.compile(
    r"pam_unix\((?P<service>sudo|sudo-i|su|su-l):session\): session (?P<what>opened|closed) for user "
    r"(?P<target>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)\(uid=\d+\))?")
# "pam_unix(sudo:auth): authentication failure; logname=erick uid=1000 euid=0 tty=/dev/pts/0 ruser=erick rhost=  user=erick"
PAM_AUTH_FAILURE = re.compile(
    r"pam_unix\((?P<service>sudo|sudo-i|su|su-l):auth\): authentication failure;(?:.*?\blogname=(?P<logname>\S*))?"
    r".*?\btty=(?P<tty>\S*).*?\bruser=(?P<ruser>\S*).*?\buser=(?P<target>\S*)")
# "(to root) erick on pts/0" / "FAILED SU (to root) erick on pts/0"
SU_SWITCH = re.compile(r"^\s*(?P<failed>FAILED SU )?\(to (?P<target>[^)\s]+)\) (?P<user>\S*) on (?P<tty>\S+)")
# "New session 5 of user erick." / "Removed session 5." / "Session 5 logged out. Waiting for processes to exit."
LOGIND_NEW = re.compile(r"^New session (?P<sid>\S+) of user (?P<user>\S+?)\.?$")
LOGIND_GONE = re.compile(r"^(?:Removed session (?P<sid>\S+?)\.?$|Session (?P<sid2>\S+) logged out\b)")


def _tty(value: str | None) -> str | None:
    """'/dev/pts/0' -> 'pts/0'; the words that mean no terminal ('unknown', '?', 'none') -> None."""
    v = (value or "").strip()
    if v.startswith("/dev/"):
        v = v[5:]
    return v if v not in ("", "unknown", "?", "none") else None


def parse_sudo_message(msg: str) -> dict[str, Any]:
    """sudo's message text -> parsed fields (kind "sudo"). ``_user`` is the account that ran sudo."""
    f: dict[str, Any] = {"kind": "sudo", "sudo_event": "other", "by": None, "target_user": None, "tty": None,
                         "command": None, "outcome": "info", "count": None}
    if m := PAM_SESSION.search(msg):
        if m["service"] in ("sudo", "sudo-i"):
            f.update(sudo_event=f"session_{m['what']}", by=m["by"] or None, target_user=m["target"])
    elif m := PAM_AUTH_FAILURE.search(msg):
        if m["service"] in ("sudo", "sudo-i"):
            f.update(sudo_event="auth_failure", by=m["ruser"] or m["logname"] or None,
                     target_user=m["target"] or None, tty=_tty(m["tty"]), outcome="failure")
    elif m := SUDO_COMMAND.match(msg):
        reason = (m["message"] or "").strip()
        event, outcome, count = "command", "success", None
        if reason:
            low = reason.lower()
            event = next((name for words, name in SUDO_REFUSALS if words in low), "refused")
            outcome = "failure"
            if event == "wrong_password":
                n = re.match(r"(\d+) ", reason)
                count = int(n.group(1)) if n else 1
        f.update(sudo_event=event, by=m["user"], target_user=m["target"] or None, tty=_tty(m["tty"]),
                 command=m["command"].strip() or None, outcome=outcome, count=count)
    f["_user"] = f["by"]
    return f


def parse_su_message(msg: str) -> dict[str, Any]:
    """su's message text -> parsed fields (kind "su"). ``_user`` is the account that ran su."""
    f: dict[str, Any] = {"kind": "su", "su_event": "other", "by": None, "target_user": None, "tty": None,
                         "outcome": "info"}
    if m := PAM_SESSION.search(msg):
        if m["service"] in SU_PROGRAMS:
            f.update(su_event=f"session_{m['what']}", by=m["by"] or None, target_user=m["target"])
    elif m := PAM_AUTH_FAILURE.search(msg):
        if m["service"] in SU_PROGRAMS:
            f.update(su_event="auth_failure", by=m["ruser"] or m["logname"] or None,
                     target_user=m["target"] or None, tty=_tty(m["tty"]), outcome="failure")
    elif m := SU_SWITCH.match(msg):
        failed = bool(m["failed"])
        f.update(su_event="failed" if failed else "switched", by=m["user"] or None, target_user=m["target"],
                 tty=_tty(m["tty"]), outcome="failure" if failed else "success")
    f["_user"] = f["by"]
    return f


def parse_logind_message(msg: str) -> dict[str, Any]:
    """systemd-logind's message -> parsed fields: kind "login_session" when a session was opened or
    closed (its id is logind's), kind "log" for its other notes (seats, power keys, lids)."""
    text = msg.strip()
    if m := LOGIND_NEW.match(text):
        return {"kind": "login_session", "session_event": "started", "user": m["user"], "tty": None,
                "origin": None, "session_id": m["sid"], "since": None, "_user": m["user"]}
    if m := LOGIND_GONE.match(text):
        return {"kind": "login_session", "session_event": "ended", "user": None, "tty": None, "origin": None,
                "session_id": m["sid"] or m["sid2"], "since": None, "_user": None}
    return {"kind": "log", "_user": None}


def _program_fields(prog: str, pid: str | None, msg: str) -> tuple[dict[str, Any], str | None, str | None]:
    f: dict[str, Any] = {"program": prog, "pid": int(pid) if pid else None, "message": msg}
    ip = user = None
    if prog in SSHD_PROGRAMS:
        ssh = parse_sshd_message(msg)
        ip, user = ssh.pop("_ip"), ssh.pop("_user")
        f.update(ssh)
    elif prog == "sudo":
        sudo = parse_sudo_message(msg)
        user = sudo.pop("_user")
        f.update(sudo)
    elif prog in SU_PROGRAMS:
        su = parse_su_message(msg)
        user = su.pop("_user")
        f.update(su)
    elif prog == "systemd-logind":
        session = parse_logind_message(msg)
        user = session.pop("_user")
        f.update(session)
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


# ---------------------------------------------------------------- shared helpers for the formats below

_FRACTION = re.compile(r"(\.\d{6})\d+")
_BASIC_OFFSET = re.compile(r"([+-]\d{2})(\d{2})$")


def _parse_iso(text: str, tz: tzinfo | None = None) -> str | None:
    """'2026-10-26T10:00:00.1234567Z', '...+0800', '2026-10-26 10:00:00' -> ISO 8601 with offset.
    Trims to microseconds and adds the colon to "+0800" so Python 3.11 reads it."""
    text = _BASIC_OFFSET.sub(r"\1:\2", _FRACTION.sub(r"\1", text.strip().replace("Z", "+00:00")))
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return _iso(_local(dt, tz))
    return _iso(dt.astimezone(tz or log_tz()))


def _ip(value: Any) -> str | None:
    """A client address as logs write it ('::ffff:203.0.113.9', '203.0.113.9:51234', '-') -> IP or None."""
    if value is None:
        return None
    text = str(value).strip().strip("[]")
    if text.lower().startswith("::ffff:"):
        text = text[7:]
    if text.count(":") == 1 and "." in text:  # IPv4 with a port
        text = text.split(":", 1)[0]
    if text in ("", "-", "::", "0.0.0.0", "unknown", "UNKNOWN", "localhost") or not re.fullmatch(r"[0-9a-fA-F:.]+", text):
        return None
    return text


def _dropped(fields: dict[str, Any], ts: str | None = None) -> Parsed:
    return Parsed(fields, ts=ts, extra={"drop": True})


# ---------------------------------------------------------------- Windows Event Log

# Event ID -> (win_event, outcome, kind). "auth" events count toward brute force in core; the others
# are "windows_event" facts the rules turn into incidents (log cleared, admin group change, malware).
WINDOWS_EVENTS: dict[int, tuple[str, str, str]] = {
    4624: ("logon", "success", "auth"),
    4625: ("logon_failed", "failure", "auth"),
    4771: ("kerberos_preauth_failed", "failure", "auth"),
    4776: ("ntlm_validation", "success", "auth"),       # outcome from Status: 0x0 success, else failure
    4740: ("account_locked", "info", "auth"),
    18456: ("sql_login_failed", "failure", "auth"),      # SQL Server, Application log
    1102: ("log_cleared", "info", "windows_event"),      # Security log cleared
    104: ("log_cleared", "info", "windows_event"),       # System or another log cleared
    4720: ("account_created", "info", "windows_event"),
    4728: ("group_member_added", "info", "windows_event"),  # global group (Domain Admins)
    4732: ("group_member_added", "info", "windows_event"),  # local group (Administrators)
    4756: ("group_member_added", "info", "windows_event"),  # universal group (Enterprise Admins)
    4688: ("process_created", "info", "windows_event"),
    4697: ("service_installed", "info", "windows_event"),
    7045: ("service_installed", "info", "windows_event"),
    1116: ("malware_detected", "info", "windows_event"),  # Microsoft Defender
    1117: ("malware_action", "info", "windows_event"),
}
# IDs that more than one program uses: only these providers mean what the table says.
WINDOWS_PROVIDERS = {104: "eventlog", 1102: "eventlog", 1116: "defender", 1117: "defender", 18456: "mssql",
                     7045: "service control manager"}
LOGON_TYPES = {2: "interactive", 3: "network", 4: "batch", 5: "service", 7: "unlock", 8: "network_cleartext",
               9: "new_credentials", 10: "remote_desktop", 11: "cached"}
SQL_CLIENT = re.compile(r"\[CLIENT: ?(?P<ip>[^\]]+)\]")
SQL_USER = re.compile(r"Login failed for user '(?P<user>[^']*)'")


def _windows_user(data: dict[str, Any], *keys: str) -> str | None:
    for k in keys:
        v = data.get(k)
        if v not in (None, "", "-"):
            return str(v)
    return None


def winevent_parsed(rec: dict[str, Any], tz: tzinfo | None = None) -> Parsed | None:
    """One Windows event as a plain record -> Parsed. ``rec`` keys: event_id, channel, provider,
    computer, time (ISO), record_id, data (EventData by name; unnamed values as "0", "1", ...),
    message. Events SentrAI has no rule for return None."""
    try:
        eid = int(rec.get("event_id"))
    except (TypeError, ValueError):
        return None
    if eid not in WINDOWS_EVENTS:
        return None
    provider = str(rec.get("provider") or "")
    if (want := WINDOWS_PROVIDERS.get(eid)) and provider and not (
            provider.upper().startswith("MSSQL") if want == "mssql" else want in provider.lower()):
        return None
    win_event, outcome, kind = WINDOWS_EVENTS[eid]
    data = {str(k): v for k, v in (rec.get("data") or {}).items()}
    message = str(rec.get("message") or "").strip()
    channel = str(rec.get("channel") or "")
    f: dict[str, Any] = {"format": "winevent", "kind": kind, "event_id": eid, "win_event": win_event,
                         "channel": channel, "provider": provider, "record_id": rec.get("record_id"),
                         "program": "windows", "message": message.splitlines()[0][:300] if message else None}
    ip = _ip(data.get("IpAddress"))
    user = _windows_user(data, "TargetUserName")
    domain = _windows_user(data, "TargetDomainName")
    if eid in (4624, 4625):
        try:
            logon_type = int(data.get("LogonType") or 0)
        except ValueError:
            logon_type = 0
        f.update(logon_type=LOGON_TYPES.get(logon_type, str(logon_type or "")) or None,
                 status=data.get("SubStatus") if str(data.get("SubStatus") or "0x0").lower() != "0x0" else data.get("Status"),
                 workstation=_windows_user(data, "WorkstationName"),
                 service="rdp" if logon_type == 10 else "windows_logon")
        if eid == 4624 and (logon_type not in (3, 8, 10) or ip is None or ip in ("127.0.0.1", "::1")):
            return None  # service, batch and local sign-ins: thousands a day and never an attack signal
    elif eid == 4771:
        f.update(status=data.get("Status"), service="kerberos")
    elif eid == 4776:
        status = str(data.get("Status") or "0x0").lower()
        outcome = "success" if status in ("0x0", "0") else "failure"
        f.update(status=status, workstation=_windows_user(data, "Workstation"), service="ntlm")
    elif eid == 4740:
        f.update(service="windows_logon", workstation=_windows_user(data, "TargetDomainName"))
        domain = None
    elif eid == 18456:
        values = " ".join(str(v) for v in data.values()) + " " + message
        if m := SQL_CLIENT.search(values):
            ip = _ip(m["ip"])
        user = (m["user"] if (m := SQL_USER.search(message)) else None) or _windows_user(data, "0")
        if r := re.search(r"Reason: ?([^\[\]]+?)\s*(?:\[|$)", values):
            f["reason"] = r.group(1).strip().rstrip(".")
        f.update(service="mssql", program="mssql")
    elif win_event == "group_member_added":
        f.update(group=_windows_user(data, "TargetUserName"),
                 member=_windows_user(data, "MemberName", "MemberSid"), by=_windows_user(data, "SubjectUserName"))
        user = f["member"]
    elif eid == 4720:
        f["by"] = _windows_user(data, "SubjectUserName")
    elif eid == 4688:
        f.update(process=_windows_user(data, "NewProcessName"), parent=_windows_user(data, "ParentProcessName"),
                 command_line=_windows_user(data, "CommandLine"))
        user = _windows_user(data, "SubjectUserName")
    elif win_event == "service_installed":
        f.update(service_name=_windows_user(data, "ServiceName"),
                 image_path=_windows_user(data, "ImagePath", "ServiceFileName"),
                 account=_windows_user(data, "AccountName", "ServiceAccount"))
        user = _windows_user(data, "SubjectUserName")
    elif win_event in ("malware_detected", "malware_action"):
        f.update(threat=_windows_user(data, "Threat Name", "ThreatName"), path=_windows_user(data, "Path"),
                 severity=_windows_user(data, "Severity Name"), action=_windows_user(data, "Action Name"),
                 program="defender")
        user = _windows_user(data, "Detection User")
    elif win_event == "log_cleared":
        f["log"] = _windows_user(data, "Channel") or channel
        user = _windows_user(data, "SubjectUserName")
    if kind == "auth":
        f["outcome"] = outcome
        f.setdefault("service", "windows_logon")
        if f["service"] == "rdp":
            f["program"] = "rdp"
    if kind == "auth" and user and domain and "\\" not in user and "@" not in user and domain not in ("-", "."):
        user = f"{domain}\\{user}"
    ts = _parse_iso(str(rec["time"]), tz) if rec.get("time") else None
    return Parsed(f, ts=ts, host=str(rec["computer"]) if rec.get("computer") else None, src_ip=ip, user=user)


def winevent_raw(p: Parsed) -> str:
    """A readable one-line summary of a Windows event, used as the Event's ``raw``."""
    f = p.fields
    bits = [f"{k}={v}" for k, v in (("user", p.user), ("ip", p.src_ip), ("logon_type", f.get("logon_type")),
                                    ("status", f.get("status")), ("group", f.get("group")),
                                    ("service", f.get("service_name")), ("image", f.get("image_path")),
                                    ("threat", f.get("threat")), ("path", f.get("path")),
                                    ("parent", f.get("parent")), ("process", f.get("process")),
                                    ("cmdline", f.get("command_line")), ("reason", f.get("reason"))) if v]
    head = f"Windows {f.get('channel') or 'event'} {f['event_id']} {f['win_event']}:"
    tail = f" | {f['message']}" if f.get("message") else ""
    return " ".join([head, *bits]) + tail


_EVT_NS = re.compile(r"\{[^}]*\}")


def winevent_from_xml(xml: str) -> list[dict[str, Any]]:
    """``wevtutil qe ... /f:RenderedXml /e:Events`` (or one ``<Event>``) -> plain records."""
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    events = [root] if _EVT_NS.sub("", root.tag) == "Event" else [e for e in root if _EVT_NS.sub("", e.tag) == "Event"]
    out = []
    for ev in events:
        rec: dict[str, Any] = {"data": {}}
        for part in ev:
            name = _EVT_NS.sub("", part.tag)
            if name == "System":
                for el in part:
                    tag = _EVT_NS.sub("", el.tag)
                    if tag == "Provider":
                        rec["provider"] = el.get("Name") or el.get("EventSourceName")
                    elif tag == "EventID":
                        rec["event_id"] = (el.text or "").strip()
                    elif tag == "TimeCreated":
                        rec["time"] = el.get("SystemTime")
                    elif tag == "EventRecordID":
                        rec["record_id"] = int(el.text) if (el.text or "").strip().isdigit() else None
                    elif tag in ("Channel", "Computer"):
                        rec[tag.lower()] = (el.text or "").strip()
            elif name in ("EventData", "UserData"):
                items = list(part) if name == "EventData" else [x for child in part for x in child]
                for i, d in enumerate(items):
                    key = d.get("Name") or (_EVT_NS.sub("", d.tag) if name == "UserData" else str(i))
                    if _EVT_NS.sub("", d.tag) != "Binary":
                        rec["data"][key] = (d.text or "").strip()
            elif name == "RenderingInfo":
                for el in part:
                    if _EVT_NS.sub("", el.tag) == "Message":
                        rec["message"] = (el.text or "").strip()
        out.append(rec)
    return out


def winevent_from_json(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Winlogbeat, NXLog, or ``Get-WinEvent | ConvertTo-Json`` (with ``EventData``) -> plain record."""
    if isinstance(obj.get("winlog"), dict):  # Winlogbeat / Elastic Agent
        w = obj["winlog"]
        return {"event_id": w.get("event_id"), "channel": w.get("channel"), "provider": w.get("provider_name"),
                "computer": w.get("computer_name"), "record_id": w.get("record_id"),
                "time": obj.get("@timestamp"), "data": w.get("event_data") or {}, "message": obj.get("message")}
    eid = obj.get("EventID", obj.get("Id", obj.get("event_id")))
    if eid is None:
        return None
    known = {"EventID", "Id", "event_id", "Channel", "LogName", "SourceName", "ProviderName", "Hostname",
             "MachineName", "Computer", "EventTime", "TimeCreated", "RecordNumber", "RecordId", "Message", "EventData"}
    data = obj.get("EventData") if isinstance(obj.get("EventData"), dict) else \
        {k: v for k, v in obj.items() if k not in known and not isinstance(v, (dict, list))}
    when = obj.get("EventTime") or obj.get("TimeCreated")
    if isinstance(when, str) and (m := re.match(r"/Date\((\d+)\)/", when)):  # PowerShell 5 JSON dates
        when = datetime.fromtimestamp(int(m.group(1)) / 1000, timezone.utc).isoformat()
    return {"event_id": eid, "channel": obj.get("Channel") or obj.get("LogName"),
            "provider": obj.get("SourceName") or obj.get("ProviderName"),
            "computer": obj.get("Hostname") or obj.get("MachineName") or obj.get("Computer"),
            "record_id": obj.get("RecordNumber") or obj.get("RecordId"), "time": when, "data": data,
            "message": obj.get("Message")}


def parse_winevent(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """One exported or forwarded Windows event per line: JSON (Winlogbeat, NXLog, Get-WinEvent) or
    one ``<Event>`` XML element. Events of no interest come back dropped."""
    line = line.strip()
    rec: dict[str, Any] | None = None
    if line.startswith("<"):
        recs = winevent_from_xml(line)
        rec = recs[0] if recs else None
    else:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        rec = winevent_from_json(obj) if isinstance(obj, dict) else None
    if rec is None:
        return None
    p = winevent_parsed(rec, tz)
    return p if p is not None else _dropped({"format": "winevent", "kind": "log"})


# ---------------------------------------------------------------- Suricata eve.json

def parse_suricata(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """One line of Suricata's ``eve.json``. Only ``alert`` records are kept; flows, DNS, TLS, stats
    and the rest come back dropped. ``src_ip`` is the far end of the connection (for an alert on
    traffic leaving this network, the outside address it went to), so a block hits the right side."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or "event_type" not in rec:
        return None
    ts = _parse_iso(str(rec["timestamp"]), tz) if rec.get("timestamp") else None
    if rec["event_type"] != "alert" or not isinstance(rec.get("alert"), dict):
        return _dropped({"format": "suricata", "kind": "network", "event_type": rec["event_type"]}, ts)
    a = rec["alert"]
    src, dest = _ip(rec.get("src_ip")), _ip(rec.get("dest_ip"))
    outbound = src is not None and dest is not None and _private(src) and not _private(dest)
    f: dict[str, Any] = {"format": "suricata", "kind": "network_alert", "program": "suricata",
                         "signature": a.get("signature"), "signature_id": a.get("signature_id"),
                         "alert_category": a.get("category") or None, "severity": a.get("severity"),
                         "action": a.get("action"), "proto": rec.get("proto"), "app_proto": rec.get("app_proto"),
                         "src_ip": src, "src_port": rec.get("src_port"), "dest_ip": dest,
                         "dest_port": rec.get("dest_port"), "direction": "outbound" if outbound else "inbound",
                         "interface": rec.get("in_iface")}
    if isinstance(rec.get("http"), dict):
        f.update(http_host=rec["http"].get("hostname"), http_url=rec["http"].get("url"),
                 user_agent=rec["http"].get("http_user_agent"))
    return Parsed(f, ts=ts, src_ip=dest if outbound else src)


def suricata_raw(p: Parsed) -> str:
    f = p.fields
    url = f" {f['http_host'] or ''}{f['http_url'] or ''}" if f.get("http_url") else ""
    return (f"Suricata alert [{f.get('action') or 'allowed'}] {f.get('signature')} "
            f"(category: {f.get('alert_category') or 'none'}, severity {f.get('severity')}) "
            f"{f.get('proto') or ''} {f.get('src_ip')}:{f.get('src_port')} -> {f.get('dest_ip')}:{f.get('dest_port')}{url}")


_LOCAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")


def _private(ip: str) -> bool:
    """An address inside this network (RFC 1918, CGNAT, ULA, loopback, link-local). Python's own
    is_private also counts the documentation ranges, which tests and examples use as "outside"."""
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_loopback or a.is_link_local or any(a in ipaddress.ip_network(n) for n in _LOCAL_NETS
                                                   if ipaddress.ip_network(n).version == a.version)


# ---------------------------------------------------------------- MySQL / MariaDB

# Error log: "2026-10-26T10:00:00.123456Z 8 [Note] [MY-010926] [Server] Access denied for user ..."
# (MySQL 8), "2026-10-26 10:00:00 8 [Warning] Access denied ..." (MariaDB), "161026 10:00:00 [Warning] ..." (old).
MYSQL_ERROR = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\d{6} +\d{1,2}:\d{2}:\d{2})"
    r"\s+(?:(?P<thread>\d+)\s+)?\[(?P<level>[A-Za-z]+)\](?:\s+\[(?P<code>MY-\d+)\])?(?:\s+\[(?P<subsys>\w+)\])?\s+(?P<msg>.*)$")
# General query log: "2026-10-26T10:00:00.123456Z\t   12 Query\tSELECT ..." / "...  12 Connect\troot@203.0.113.9 on shop"
MYSQL_GENERAL = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<thread>\d+)\s+"
    r"(?P<cmd>Query|Connect|Quit|Init DB|Execute|Prepare)\b\s*(?P<arg>.*)$")
MYSQL_DENIED = re.compile(r"Access denied for user '(?P<user>[^']*)'@'(?P<host>[^']*)'(?: \(using password: (?P<pw>YES|NO)\))?")
MYSQL_CONNECT = re.compile(r"^(?P<user>[^@\s]+)@(?P<host>\S+) on (?P<db>\S*)")
MYSQL_ABORTED = re.compile(r"Aborted connection \d+ to db: '(?P<db>[^']*)' user: '(?P<user>[^']*)' host: '(?P<host>[^']*)'")
MYSQL_BLOCKED = re.compile(r"Host '(?P<host>[^']*)' is blocked because of many connection errors")


def _mysql_time(ts: str, tz: tzinfo | None) -> str | None:
    if re.match(r"^\d{6} ", ts):  # 161026 10:00:00
        try:
            return _iso(_local(datetime.strptime(re.sub(r" +", " ", ts), "%y%m%d %H:%M:%S"), tz))
        except ValueError:
            return None
    return _parse_iso(ts, tz)


def parse_mysql(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """MySQL / MariaDB error log or general query log. Failed sign-ins appear in the error log
    (MariaDB by default; MySQL 8 with ``log_error_verbosity = 3``)."""
    f: dict[str, Any] = {"format": "mysql", "program": "mysql", "service": "mysql"}
    if m := MYSQL_GENERAL.match(line):
        cmd, arg = m["cmd"], m["arg"].strip()
        f.update(session=f"mysql:{m['thread']}", command=cmd)
        if cmd in ("Query", "Execute"):
            f.update(kind="db_query", sql=arg)
            return Parsed(f, ts=_mysql_time(m["ts"], tz))
        if cmd == "Connect":
            if d := MYSQL_DENIED.search(arg):
                f.update(kind="auth", auth_event="access_denied", outcome="failure",
                         password_used=d["pw"] != "NO" if d["pw"] else None)
                return Parsed(f, ts=_mysql_time(m["ts"], tz), src_ip=_ip(d["host"]), user=d["user"] or None)
            if c := MYSQL_CONNECT.match(arg):
                f.update(kind="auth", auth_event="connected", outcome="success", database=c["db"] or None)
                return Parsed(f, ts=_mysql_time(m["ts"], tz), src_ip=_ip(c["host"]), user=c["user"])
        return _dropped({**f, "kind": "log"}, _mysql_time(m["ts"], tz))
    m = MYSQL_ERROR.match(line)
    if not m:
        return None
    msg, ts = m["msg"], _mysql_time(m["ts"], tz)
    f.update(kind="log", level=m["level"].lower(), code=m["code"], message=msg[:300])
    if m["thread"]:
        f["session"] = f"mysql:{m['thread']}"
    ip = user = None
    if d := MYSQL_DENIED.search(msg):
        f.update(kind="auth", auth_event="access_denied", outcome="failure",
                 password_used=d["pw"] != "NO" if d["pw"] else None)
        ip, user = _ip(d["host"]), d["user"] or None
    elif a := MYSQL_ABORTED.search(msg):
        unauth = a["user"] in ("unauthenticated", "")
        f.update(kind="auth", auth_event="aborted_preauth" if unauth else "aborted", outcome="info")
        ip, user = _ip(a["host"]), None if unauth else a["user"]
    elif b := MYSQL_BLOCKED.search(msg):
        f.update(kind="auth", auth_event="host_blocked", outcome="info")
        ip = _ip(b["host"])
    elif f["level"] in ("note", "system", "info"):
        return _dropped(f, ts)  # start-up, InnoDB and replication notes
    return Parsed(f, ts=ts, src_ip=ip, user=user)


# ---------------------------------------------------------------- PostgreSQL

# log_line_prefix '%m [%p] ' (default) or '%m [%p] %q%u@%d ' (Debian), optionally with %h / %r (client).
POSTGRES = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: (?P<tz>[A-Za-z]{1,5}|[+-]\d{2}(?::?\d{2})?))? "
    r"\[(?P<pid>\d+)\](?:-\d+)? (?:(?P<prefix>.*?) )?"
    r"(?P<level>LOG|FATAL|ERROR|WARNING|NOTICE|INFO|PANIC|STATEMENT|DETAIL|HINT|CONTEXT|DEBUG\d?):  (?P<msg>.*)$")
PG_AUTH_FAILED = re.compile(r'(?:(?P<method>\w+) )?authentication failed for user "(?P<user>[^"]*)"')
PG_HBA = re.compile(r'no pg_hba\.conf entry for host "(?P<host>[^"]*)", user "(?P<user>[^"]*)"')
PG_NO_ROLE = re.compile(r'^role "(?P<user>[^"]*)" does not exist')
PG_RECEIVED = re.compile(r"^connection received: host=(?P<host>\S+)")
PG_AUTHORIZED = re.compile(r"^connection authorized: user=(?P<user>\S+)")
PG_STATEMENT = re.compile(r"^(?:duration: [\d.]+ ms\s+)?(?:statement|execute [^:]*): (?P<sql>.*)$")
PG_CLIENT = re.compile(r"(?:^|[\s@])(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F]*:[0-9a-fA-F:]+)(?:\(\d+\))?(?:\s|$)")


def _pg_zone(name: str | None, tz: tzinfo | None) -> tzinfo | None:
    """%m writes the server's zone as "UTC", "+08" or an abbreviation such as "SGT"."""
    if name and (name.upper() in ("UTC", "GMT") or _OFFSET.match(name)):
        return log_tz(name)
    return tz  # an abbreviation: use the log machine's zone


def parse_postgres(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """PostgreSQL server log (stderr / logging collector, the usual prefixes). Failed sign-ins need no
    setting; the client address comes from the line prefix (%h / %r) or from the
    ``connection received`` line of the same process (``log_connections = on``)."""
    m = POSTGRES.match(line)
    if not m:
        return None
    try:
        dt = datetime.fromisoformat(m["ts"])
    except ValueError:
        return None
    ts = _iso(_local(dt, _pg_zone(m["tz"], tz)).astimezone(tz or log_tz()))
    msg, level = m["msg"], m["level"]
    f: dict[str, Any] = {"format": "postgres", "kind": "log", "program": "postgres", "service": "postgres",
                         "level": level.lower(), "pid": int(m["pid"]), "session": f"postgres:{m['pid']}",
                         "message": msg[:300]}
    prefix = m["prefix"] or ""
    ip = _ip(c["ip"]) if (c := PG_CLIENT.search(prefix)) else None
    user = None
    if (pu := re.match(r"^(?P<user>[\w.-]+)@", prefix)) and pu["user"] not in ("[unknown]",):
        user = pu["user"]
    if level == "FATAL" and (a := PG_AUTH_FAILED.search(msg)):
        f.update(kind="auth", auth_event="password_failed" if (a["method"] or "password") in ("password", "md5", "scram")
                 else f"{a['method'].lower()}_failed", outcome="failure")
        user = a["user"]
    elif level == "FATAL" and (h := PG_HBA.search(msg)):
        f.update(kind="auth", auth_event="no_hba_entry", outcome="failure")
        ip, user = _ip(h["host"]) or ip, h["user"]
    elif level == "FATAL" and (r := PG_NO_ROLE.search(msg)):
        f.update(kind="auth", auth_event="no_such_role", outcome="failure", invalid_user=True)
        user = r["user"]
    elif r := PG_RECEIVED.search(msg):
        f.update(kind="auth", auth_event="connection_received", outcome="info")
        ip = _ip(r["host"])
    elif a := PG_AUTHORIZED.search(msg):
        f.update(kind="auth", auth_event="connected", outcome="success")
        user = a["user"]
    elif level in ("LOG", "STATEMENT") and (s := PG_STATEMENT.search(msg)):
        f.update(kind="db_query", sql=s["sql"])
    elif level == "STATEMENT":  # the query that caused the ERROR line above it
        f.update(kind="db_query", sql=msg)
    elif level not in ("FATAL", "ERROR", "WARNING", "PANIC"):
        return _dropped(f, ts)  # checkpoints, autovacuum, DETAIL / HINT / CONTEXT lines
    return Parsed(f, ts=ts, src_ip=ip, user=user)


# ---------------------------------------------------------------- MongoDB

def parse_mongodb(line: str, tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """MongoDB 4.4+ structured log (one JSON object per line). Sign-ins are kept; everything else
    (storage, replication, index builds) comes back dropped."""
    try:
        rec = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(rec, dict) or "msg" not in rec or "c" not in rec:
        return None
    when = rec.get("t", {}).get("$date") if isinstance(rec.get("t"), dict) else rec.get("t")
    ts = _parse_iso(str(when), tz) if when else None
    attr = rec.get("attr") if isinstance(rec.get("attr"), dict) else {}
    msg = str(rec["msg"])
    f: dict[str, Any] = {"format": "mongodb", "kind": "auth", "program": "mongodb", "service": "mongodb",
                         "component": rec["c"], "log_id": rec.get("id"), "message": msg[:300]}
    if rec.get("ctx"):
        f["session"] = f"mongodb:{rec['ctx']}"
    remote = _ip(attr.get("remote") or attr.get("client"))
    user = attr.get("principalName") or attr.get("user") or None
    low = msg.lower()
    if rec["c"] == "ACCESS" and ("authentication failed" in low or "failed to authenticate" in low):
        f.update(auth_event="auth_failed", outcome="failure", mechanism=attr.get("mechanism"),
                 database=attr.get("authenticationDatabase") or attr.get("db"), reason=attr.get("error"))
    elif rec["c"] == "ACCESS" and ("authentication succeeded" in low or "successfully authenticated" in low):
        f.update(auth_event="connected", outcome="success", mechanism=attr.get("mechanism"))
    elif rec["c"] == "NETWORK" and msg == "Connection accepted":
        f.update(auth_event="connection_received", outcome="info")
        user = None
    else:
        return _dropped({**f, "kind": "log"}, ts)
    return Parsed(f, ts=ts, src_ip=remote, user=str(user) if user else None)


# ---------------------------------------------------------------- who is signed in: who / quser

# "erick    pts/0        2026-10-28 10:21 (203.0.113.5)" (GNU who), "erick  ttys000  Oct 28 10:21 (203.0.113.5)"
# (macOS, BSD). The brackets say where the person came from: an address, a host name, or a display such as
# ":0"; a console sign-in has none.
WHO_LINE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<when>\d{4}-\d{2}-\d{2} \d{2}:\d{2}(?::\d{2})?"
    r"|[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}(?::\d{2})?)(?:\s+\((?P<origin>[^)]*)\))?")
# quser: " USERNAME  SESSIONNAME  ID  STATE  IDLE TIME  LOGON TIME"; ">" marks the session running quser,
# and a disconnected session has no session name.
QUSER_LINE = re.compile(
    r"^\s*>?\s*(?P<user>\S+)\s+(?:(?P<session>\S+)\s+)?(?P<id>\d+)\s+(?P<state>\S+)\s+(?P<idle>\S+)\s+(?P<logon>.+?)\s*$")
QUSER_TIMES = ("%m/%d/%Y %I:%M %p", "%d/%m/%Y %H:%M", "%m/%d/%Y %H:%M", "%d.%m.%Y %H:%M", "%Y/%m/%d %H:%M",
               "%Y-%m-%d %H:%M", "%d/%m/%Y %I:%M %p", "%Y-%m-%d %I:%M %p")


def _with_zone(dt: datetime, tz: tzinfo | None) -> str:
    """A naive local time -> ISO 8601 with this computer's offset at that moment (or ``tz``'s)."""
    return _iso(dt.replace(tzinfo=tz) if tz is not None else dt.astimezone())


def _who_time(text: str, tz: tzinfo | None, now: datetime | None) -> str | None:
    if m := re.match(r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})(?::(\d{2}))?$", text):
        try:
            dt = datetime(*(int(x) for x in m.groups()[:5]), int(m.group(6) or 0))
        except ValueError:
            return None
        return _with_zone(dt, tz)
    m = re.match(r"^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2})(?::(\d{2}))?$", text)
    month = MONTHS.get(m.group(1)) if m else None
    if not month:
        return None
    now = now or (datetime.now(tz) if tz is not None else datetime.now().astimezone())
    try:  # BSD who writes no year: this year, or last year for a December line read in January
        dt = datetime(now.year, month, int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5) or 0))
    except ValueError:
        return None
    if dt - now.replace(tzinfo=None) > timedelta(days=2):
        dt = dt.replace(year=dt.year - 1)
    return _with_zone(dt, tz)


def parse_who(text: str, tz: tzinfo | None = None, now: datetime | None = None) -> list[dict[str, Any]]:
    """The output of ``who`` -> the sessions open now: ``user``, ``tty``, ``origin`` (an address, a host
    name, a display, or None at the console), ``session_id`` (None) and ``since`` (ISO 8601 with the
    offset of this computer's zone, where ``who`` prints its times)."""
    out = []
    for line in text.splitlines():
        m = WHO_LINE.match(line.strip())
        if not m:
            continue
        origin = (m["origin"] or "").strip() or None
        out.append({"user": m["user"], "tty": m["tty"], "origin": origin, "session_id": None,
                    "since": _who_time(m["when"], tz, now)})
    return out


def parse_quser(text: str, tz: tzinfo | None = None, now: datetime | None = None) -> list[dict[str, Any]]:
    """The output of Windows ``quser`` -> the sessions open now. The session name (console, rdp-tcp#3) is
    the ``tty``, a disconnected session (no name) is ``session-<id>``, the ID column is ``session_id``,
    and ``origin`` is always None: quser does not say where a Remote Desktop user came from."""
    out = []
    for line in text.splitlines():
        m = QUSER_LINE.match(line)
        if not m:
            continue
        since = None
        for fmt in QUSER_TIMES:
            try:
                since = _with_zone(datetime.strptime(m["logon"].strip(), fmt), tz)
                break
            except ValueError:
                continue
        out.append({"user": m["user"], "tty": m["session"] or f"session-{m['id']}", "origin": None,
                    "session_id": m["id"], "since": since})
    return out


# ---------------------------------------------------------------- dispatch

PARSERS = {
    "nginx": (parse_nginx_access, parse_nginx_error),
    "nginx_access": (parse_nginx_access,),
    "nginx_error": (parse_nginx_error,),
    "syslog": (parse_syslog,),
    "sshd": (parse_syslog,),
    "journald": (parse_journald,),
    "winevent": (parse_winevent,),
    "suricata": (parse_suricata,),
    "mysql": (parse_mysql,),
    "mariadb": (parse_mysql,),
    "postgres": (parse_postgres,),
    "postgresql": (parse_postgres,),
    "mongodb": (parse_mongodb,),
}
AUTO = (parse_nginx_access, parse_syslog, parse_nginx_error)


def parse_line(line: str, fmt: str = "auto", tz: tzinfo | None = None, now: datetime | None = None) -> Parsed | None:
    """Parse one log line. ``fmt`` "text"/"auto" tries nginx, then syslog, then the nginx error log."""
    for parser in PARSERS.get(fmt, AUTO):
        if (p := parser(line, tz, now)) is not None:
            return p
    return None
