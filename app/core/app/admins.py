"""The administrators: who holds the keys to each machine, and whether the root at work right now is one of them.

The rules read every line the same way whoever typed it, so an administrator's own `sudo systemctl stop
sentrai-core` looked exactly like an intruder covering their tracks. This module answers the question
the rules cannot: who did it, and does SentrAI know that person? Warden asks it for every line seen
on a host (a sudo or su command, a Windows admin event, a sign-in) and acts on the answer:

  * root work inside a sign-in SentrAI trusts is recorded as admin activity (audit record
    ``admin_action``, the machine's Admins tab), not raised as an incident;
  * root work from a sign-in it does not recognise becomes one incident per address,
    "Root access from an unrecognised sign-in", which asks "was this you?";
  * a sign-in SentrAI distrusts (after password guessing from the same address) is treated the same.

What makes a sign-in trusted, in order:

  1. its SSH key fingerprint is a known administrator key (ADMIN_SSH_KEYS, taught, or learned);
  2. its address is a known administrator address: ADMIN_IPS, taught with "This was me", learned, or
     vouched for by a dashboard sign-in with the authenticator (ADMIN_SIGNIN_HOURS);
  3. a console sign-in (no address) by a known administrator account (ADMIN_ACCOUNTS or taught).

A trusted sign-in teaches the other half (with ADMIN_LEARN on): a known key from a new address makes
the address known, a new key from a known address makes the key known. A sudo command in a trusted
session makes its account a known administrator account on that machine.

A root command is tied to its sign-in by the terminal it ran on (sudo logs TTY=pts/0; the collector's
``who`` poll says which sign-in owns pts/0), or failing that by the account's most recent live session on
that host. A command with no sign-in behind it (SentrAI started after the person signed in, or the
sign-in line was never collected) is trusted only when its account is a known administrator account.

Everything learned or taught is kept in people/admins.json next to the database (SENTRAI_ADMINS), on
the machine that runs the panel: addresses and keys never go into the repository or the audit chain in
full. "This was me" (POST /incidents/{id}/mine) and the Admins tab change it; the audit chain records
each change as ``admin_confirmed``, ``admin_changed`` or ``admin_distrusted``.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from . import protect
from .netlogs import (SERVICE_ACCOUNTS, SudoLine, SuLine, is_ip, parse_auth, parse_login_session, parse_sshd,
                      parse_su, parse_sudo)

log = logging.getLogger("sentrai.admins")

TRUSTED, UNKNOWN, SUSPECT = "trusted", "unknown", "suspect"
CATEGORY = "unauthorised_admin"  # the incident category Warden gives root work from an unrecognised sign-in
MERGE_WINDOW_S = 600.0  # a `who` session and an sshd sign-in this close are the same session
ACTIVITY_KEEP = 300  # admin actions kept for the Admins tab (the audit chain keeps them all)
WIPE_LINK_S = 300.0  # a collector "log shrank" notice this soon after an admin's wiping command is theirs
WINDOWS_SESSION_LOGONS = ("interactive", "remote_desktop", "unlock", "cached", "remote_interactive")
# Windows events that are admin work when a known administrator does them, and root work otherwise.
WINDOWS_PRIVILEGED = ("group_member_added", "service_installed", "log_cleared", "account_created")
# Windows itself, not a person: what these accounts do is left to the rules.
WINDOWS_SYSTEM = frozenset({"system", "localsystem", "local service", "network service", "anonymous logon", "-"})
RANK = {SUSPECT: 0, UNKNOWN: 1, TRUSTED: 2}
HOW_CONFIG = {"address": "ADMIN_IPS", "key": "ADMIN_SSH_KEYS", "account": "ADMIN_ACCOUNTS"}
# What the rules raise about a command that a known administrator may well have typed on purpose. Anything
# else they find on a host (malware on disk, a decoy touched, text written to trick the AI) stands whoever
# is signed in.
SUPPRESSIBLE = frozenset({"log_tampering", "privilege_escalation"})
FLUSH_EVERY_S = 5.0
KEY_RX = re.compile(r"^(SHA256|MD5):[A-Za-z0-9+/=:]{8,}$")


def short_key(fp: str | None) -> str:
    """A fingerprint cut for a sentence: 'SHA256:AbCdEfGh…'."""
    if not fp:
        return "no key"
    return fp if len(fp) <= 20 else fp[:19] + "…"


def _canon_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(str(value).strip().strip("[]"))
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def _since_ts(text: str | None, fallback: float) -> float:
    """The collector's `since` (ISO 8601 with an offset) as a clock time; the event's time otherwise."""
    if not text:
        return fallback
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return fallback
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.timestamp()


class _Benign:
    category, reason = "benign", ""


_BENIGN = _Benign()


@dataclass
class Session:
    sid: str
    host: str
    user: str
    via: str  # ssh, console, windows, logind, who
    src_ip: str | None
    tty: str | None
    key: str | None
    key_type: str | None
    method: str | None
    started: float
    last_seen: float
    trust: str
    why: str
    ended: float | None = None
    logind_id: str | None = None
    preexisting: bool = False  # already signed in when SentrAI started watching the machine
    actions: int = 0  # root commands seen in it
    incident: str | None = None  # the "was this you?" incident its root work opened
    taught_by: str | None = None
    remote_host: str | None = None  # `who` gave a name, not an address: a remote sign-in SentrAI cannot check

    def public(self, iso: Any) -> dict[str, Any]:
        return {"session": self.sid, "host": self.host, "user": self.user, "via": self.via, "address": self.src_ip,
                "tty": self.tty, "key": self.key, "key_type": self.key_type, "method": self.method,
                "trust": self.trust, "why": self.why, "since": iso(self.started), "last_seen": iso(self.last_seen),
                "ended": iso(self.ended) if self.ended else None, "preexisting": self.preexisting,
                "remote_host": self.remote_host,
                "actions": self.actions, "incident": self.incident}


@dataclass
class Verdict:
    """What Warden should do with one event, given who did it."""
    actor: dict[str, Any]
    suppress: bool = False  # a known administrator's own work: no incident
    escalate: bool = False  # root work from an unrecognised sign-in: the "was this you?" incident
    reason: str = ""
    src_ip: str | None = None  # the sign-in's address, so the incident (and a block) has a target
    activity: str | None = None  # what to show on the Admins tab, when it is admin work
    learned: list[str] = field(default_factory=list)


class Admins:
    def __init__(self, path: Path, settings: Any, clock: Any) -> None:
        self.path = Path(path)
        self.settings = settings
        self.clock = clock
        self.on = bool(getattr(settings, "admin_sessions", True))
        self.accounts: dict[str, dict[str, Any]] = {}  # "user@host" -> {how, by, at}
        self.addresses: dict[str, dict[str, Any]] = {}  # ip or network -> {how, by, at, label, last_seen}
        self.keys: dict[str, dict[str, Any]] = {}  # fingerprint -> {type, users, how, by, at, last_seen}
        self.signins: dict[str, dict[str, Any]] = {}  # ip -> {email, role, at, until}
        self.sessions: dict[str, Session] = {}
        self.activity: deque[dict[str, Any]] = deque(maxlen=ACTIVITY_KEEP)
        self._suspect: dict[str, tuple[float, str]] = {}  # ip -> (until, why)
        self._n = 0
        self._dirty = False
        self._last_flush = 0.0
        self.learned_log: list[dict[str, Any]] = []  # what was learned on its own since Warden last asked
        self._load()

    # ------------------------------------------------------------------ file
    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(data, dict):
            return
        for name in ("accounts", "addresses", "keys", "signins"):
            part = data.get(name)
            if isinstance(part, dict):
                setattr(self, name, {str(k): dict(v) for k, v in part.items() if isinstance(v, dict)})
        self._n = int(data.get("next", 0) or 0)
        now = self.clock.now()
        for raw in data.get("sessions") or []:
            try:
                s = Session(**{k: raw.get(k) for k in Session.__dataclass_fields__})  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if s.sid and s.user and not s.ended and now - float(s.last_seen or 0) <= self._window():
                self.sessions[s.sid] = s
        for a in data.get("activity") or []:
            if isinstance(a, dict):
                self.activity.append(a)

    def _save(self) -> None:
        self._dirty = False
        data = {
            "version": 1,
            "note": "The administrators SentrAI knows: taught with 'This was me' or on the Admins tab, or learned "
                    "from a trusted sign-in. Not a copy of any log.",
            "next": self._n,
            "accounts": self.accounts, "addresses": self.addresses, "keys": self.keys, "signins": self.signins,
            "sessions": [asdict(s) for s in self.sessions.values() if not s.ended],
            "activity": list(self.activity)[-100:],
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(prefix=".admins-", suffix=".json", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False, default=str)
                if os.name == "posix":
                    os.chmod(tmp, 0o600)
                os.replace(tmp, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError as exc:
            log.warning("could not write %s: %s", self.path, exc)

    def flush(self, force: bool = False) -> None:
        """Write what changed. Sessions change on every root command, so Warden's calls (after each batch and
        tick) write at most every few seconds; what is taught is written at once."""
        if self._dirty and (force or time.monotonic() - self._last_flush >= FLUSH_EVERY_S):
            self._last_flush = time.monotonic()
            self._save()

    def _touch(self, write: bool = False) -> None:
        self._dirty = True
        if write:
            self.flush(force=True)

    def live_count(self, host: str, now: float | None = None) -> int:
        """How many sign-ins are open on a machine right now."""
        return len(self._live(host, None, self.clock.now() if now is None else now))

    def forget_sessions(self) -> None:
        """A demo reset: the sign-ins seen so far go, what was taught stays."""
        self.sessions.clear()
        self.activity.clear()
        self._suspect.clear()
        self._touch(write=True)

    # ------------------------------------------------------------- what is known
    def _window(self) -> float:
        return self.clock.real_seconds(max(0.1, float(getattr(self.settings, "admin_session_hours", 12.0))))

    def _signin_window(self) -> float:
        return self.clock.real_seconds(max(0.0, float(getattr(self.settings, "admin_signin_hours", 12.0))))

    def known_address(self, ip: str | None, now: float | None = None) -> str | None:
        """How this address is known as an administrator's, or None: the setting, taught, learned, or a dashboard sign-in."""
        ip = _canon_ip(ip)
        if not ip:
            return None
        now = self.clock.now() if now is None else now
        if protect.matches(ip, getattr(self.settings, "admin_ips", set()) or set()):
            return HOW_CONFIG["address"]
        for entry, meta in self.addresses.items():
            if protect.matches(ip, [entry]):
                return self._how(meta)
        s = self.signins.get(ip)
        if s and float(s.get("until", 0)) > now:
            return f"dashboard sign-in by {s.get('email') or 'an administrator'}"
        return None

    def _known_key(self, fp: str | None) -> str | None:
        if not fp:
            return None
        if fp in (getattr(self.settings, "admin_ssh_keys", set()) or set()):
            return HOW_CONFIG["key"]
        meta = self.keys.get(fp)
        return self._how(meta) if meta else None

    def _known_account(self, host: str, user: str | None) -> str | None:
        if not user:
            return None
        u = user.lower()
        configured = {x.lower() for x in (getattr(self.settings, "admin_accounts", set()) or set())}
        if u in configured or f"{u}@{host.lower()}" in configured:
            return HOW_CONFIG["account"]
        for key in (f"{u}@{host.lower()}", f"{u}@*"):
            if key in self.accounts:
                return self._how(self.accounts[key])
        return None

    @staticmethod
    def _how(meta: dict[str, Any] | None) -> str:
        if not meta:
            return "known"
        how = str(meta.get("how") or "known")
        if how == "taught" and meta.get("by"):
            return f"taught by {meta['by']}"
        if how == "learned":
            return "learned from a trusted sign-in"
        return how

    def _firm(self, how: str | None) -> bool:
        """Known by a person's say-so (a setting, or taught), rather than learned or vouched for a while."""
        return bool(how) and (how in HOW_CONFIG.values() or str(how).startswith("taught"))

    def mark_suspect(self, ip: str | None, why: str, now: float) -> None:
        """Password guessing came from this address: its sign-ins are suspect for a session window."""
        ip = _canon_ip(ip)
        if ip and self.on:
            self._suspect[ip] = (now + self._window(), why)

    def _suspect_why(self, ip: str | None, now: float) -> str | None:
        ip = _canon_ip(ip)
        if not ip:
            return None
        until, why = self._suspect.get(ip, (0.0, ""))
        if until > now:
            return why
        self._suspect.pop(ip, None)
        return None

    # ------------------------------------------------------------ learning
    def _note_learned(self, kind: str, value: str, by: str, how: str) -> None:
        """A new known fact: written at once, and kept for Warden's audit record (take_learned)."""
        if how == "learned":
            self.learned_log.append({"kind": kind, "value": value, "from": by})
        self._dirty = True
        self.flush(force=True)

    def take_learned(self) -> list[dict[str, Any]]:
        out, self.learned_log = self.learned_log, []
        return out

    def _learn_address(self, ip: str, by: str, now: float, how: str = "learned", label: str = "") -> str:
        ip = _canon_ip(ip) or ip
        entry = self.addresses.get(ip)
        if entry and (self._firm(self._how(entry)) or how == "learned"):
            entry["last_seen"] = self.clock.iso(now)
        else:
            self.addresses[ip] = {"how": how, "by": by, "at": self.clock.iso(now), "label": label,
                                  "last_seen": self.clock.iso(now)}
            self._note_learned("address", ip, by, how)
        self._touch()
        return f"address {ip}"

    def _learn_key(self, fp: str, key_type: str | None, user: str | None, by: str, now: float,
                   how: str = "learned") -> str:
        entry = self.keys.get(fp)
        if entry and (self._firm(self._how(entry)) or how == "learned"):
            entry["last_seen"] = self.clock.iso(now)
            if user and user not in entry.setdefault("users", []):
                entry["users"].append(user)
        else:
            self.keys[fp] = {"type": key_type, "users": [user] if user else [], "how": how, "by": by,
                             "at": self.clock.iso(now), "last_seen": self.clock.iso(now)}
            self._note_learned("key", short_key(fp), by, how)
        self._touch()
        return f"SSH key {short_key(fp)}"

    def _learn_account(self, host: str, user: str, by: str, now: float, how: str = "learned") -> str:
        key = f"{user.lower()}@{host.lower()}"
        entry = self.accounts.get(key)
        if entry and (self._firm(self._how(entry)) or how == "learned"):
            entry["last_seen"] = self.clock.iso(now)
        else:
            self.accounts[key] = {"how": how, "by": by, "at": self.clock.iso(now), "last_seen": self.clock.iso(now)}
            self._note_learned("account", key, by, how)
        self._touch()
        return f"account {user} on {host}"

    def _evaluate(self, host: str, user: str, ip: str | None, key: str | None, key_type: str | None,
                  method: str | None, now: float, remote_host: str | None = None) -> tuple[str, str, list[str]]:
        """How far to trust a sign-in, why, and what it taught."""
        learn = bool(getattr(self.settings, "admin_learn", True))
        acct = self._known_account(host, user)
        ip = _canon_ip(ip)
        if not ip and remote_host:
            return UNKNOWN, (f"sign-in from {remote_host}: a name, not an address SentrAI can check (it is trusted "
                             f"once sshd's line for it, with its address and key, is seen)"), []
        if not ip:
            if acct:
                return TRUSTED, f"console sign-in by a known administrator account ({acct})", []
            return UNKNOWN, "console sign-in by an account SentrAI does not know as an administrator's", []
        addr = self.known_address(ip, now)
        kkey = self._known_key(key)
        if (bad := self._suspect_why(ip, now)) and not self._firm(addr) and not self._firm(kkey):
            return SUSPECT, f"sign-in from {ip} after {bad}", []
        learned: list[str] = []
        if kkey:
            why = f"known SSH key {short_key(key)} ({kkey})"
            if not addr and learn:
                learned.append(self._learn_address(ip, f"key {short_key(key)}", now))
                why += f"; {ip} is now a known administrator address"
            return TRUSTED, why, learned
        if addr:
            why = f"known administrator address {ip} ({addr})"
            if key and learn:
                learned.append(self._learn_key(key, key_type, user, f"address {ip}", now))
                why += f"; key {short_key(key)} is now a known administrator key"
            return TRUSTED, why, learned
        what = f"with {method} " if method else ""
        detail = f"key {short_key(key)}" if key else "no key SentrAI knows"
        return UNKNOWN, f"sign-in {what}from {ip} ({detail}): neither the address nor the key is known as an administrator's", []

    # ------------------------------------------------------------ sessions
    def _live(self, host: str, user: str | None, now: float) -> list[Session]:
        window = self._window()
        out = [s for s in self.sessions.values() if s.host == host and (user is None or s.user.lower() == user.lower())
               and not s.ended and now - s.last_seen <= window]
        out.sort(key=lambda s: s.last_seen, reverse=True)
        return out

    def _expire(self, now: float) -> None:
        window = self._window()
        gone = [sid for sid, s in self.sessions.items()
                if (s.ended and now - s.ended > 3600.0) or (not s.ended and now - s.last_seen > window)]
        for sid in gone:
            del self.sessions[sid]
        if gone:
            self._touch()

    def _new_session(self, host: str, user: str, via: str, ip: str | None, tty: str | None, key: str | None,
                     key_type: str | None, method: str | None, now: float, started: float | None = None,
                     logind_id: str | None = None, preexisting: bool = False,
                     remote_host: str | None = None) -> Session:
        self._n += 1
        trust, why, learned = self._evaluate(host, user, ip, key, key_type, method, now, remote_host)
        s = Session(f"s{self._n}", host, user, via, _canon_ip(ip) if ip else None, tty, key, key_type, method,
                    started if started is not None else now, now, trust, why, logind_id=logind_id,
                    preexisting=preexisting, remote_host=remote_host)
        self.sessions[s.sid] = s
        self._touch()
        if learned:
            s.why += " (learned: " + ", ".join(learned) + ")"
        return s

    def _start(self, host: str, user: str, via: str, ip: str | None, tty: str | None, key: str | None,
               key_type: str | None, method: str | None, now: float, since: float | None = None,
               preexisting: bool = False, remote_host: str | None = None) -> Session:
        """A sign-in was seen: the session it belongs to, merged with one already known for the same person
        (sshd names the address and key, `who` names the terminal: together they describe one sign-in).

        via is ssh (an sshd "Accepted" line), who (the collector's session poll: a terminal, and an address,
        a name, or nothing for the console) or windows (a remote desktop sign-in)."""
        self._expire(now)
        ip = _canon_ip(ip) if ip else None
        started = since if since is not None else now
        live = self._live(host, user, now)
        if tty:
            for s in live:
                if s.tty == tty:
                    s.last_seen = now
                    return s
        for s in live:  # newest first
            close = abs(s.started - started) <= MERGE_WINDOW_S or abs(s.last_seen - now) <= MERGE_WINDOW_S
            if not close:
                continue
            if via == "ssh" and s.via == "who" and s.method is None and \
                    ((ip and s.src_ip == ip) or (s.src_ip is None and s.remote_host)):
                # The `who` poll saw the terminal first; sshd now tells from where and with which key.
                s.via, s.src_ip, s.key, s.key_type, s.method = "ssh", ip, key, key_type, method
                s.trust, s.why, learned = self._evaluate(host, user, ip, key, key_type, method, now)
                if learned:
                    s.why += " (learned: " + ", ".join(learned) + ")"
                s.last_seen = now
                self._touch()
                return s
            if via == "who" and s.via == "ssh" and s.tty is None and \
                    ((ip and s.src_ip == ip) or (not ip and remote_host)):
                # sshd saw the sign-in first; `who` now names its terminal. A console line (no origin at
                # all) is a different sign-in and never borrows a remote one's trust.
                s.tty = tty
                s.last_seen = now
                self._touch()
                return s
        return self._new_session(host, user, via, ip, tty, key, key_type, method, now, started, None, preexisting,
                                 remote_host)

    def _logind(self, host: str, user: str | None, logind_id: str | None, now: float) -> None:
        """systemd-logind registers every sign-in, remote ones too, with no address or terminal: its id is
        attached to the newest matching session (so "Removed session" can end it), never a session of its own,
        so a logind line can never make a remote sign-in look like one at the console."""
        if not user or not logind_id:
            return
        for s in self._live(host, user, now):
            if s.logind_id == logind_id:
                return
        for s in self._live(host, user, now):
            if s.logind_id is None and now - s.started <= MERGE_WINDOW_S:
                s.logind_id = logind_id
                self._touch()
                return

    def _end(self, host: str, user: str | None = None, tty: str | None = None, logind_id: str | None = None,
             now: float | None = None, ip: str | None = None) -> None:
        """A sign-in ended: by terminal or logind id; for an sshd line, only when exactly one SSH sign-in of
        that account (from that address) is open, so the wrong one is never closed."""
        now = self.clock.now() if now is None else now
        live = self._live(host, user, now)
        if tty or logind_id:
            match = [s for s in live if (tty and s.tty == tty) or (logind_id and s.logind_id == logind_id)]
        else:
            match = [s for s in live if s.via == "ssh" and (not ip or s.src_ip == _canon_ip(ip))]
            if len(match) != 1:
                return
        if match:
            match[0].ended = now
            self._touch()

    def _find(self, host: str, user: str, tty: str | None, now: float) -> tuple[Session | None, str]:
        """The sign-in a command ran in, and a note when SentrAI had to guess. By terminal when one matches;
        with one sign-in open, that one; with several and no terminal to tell them apart (tmux, an older
        collector), the least trusted of them: a guess never gives a command more trust than it may deserve."""
        live = self._live(host, user, now)
        if tty:
            for s in live:
                if s.tty == tty:
                    return s, ""
        if len(live) <= 1:
            return (live[0] if live else None), ""
        worst = min(live, key=lambda s: (RANK.get(s.trust, 1), -s.last_seen))
        if worst.trust == TRUSTED:
            return live[0], ""
        where = f" from {worst.src_ip}" if worst.src_ip else ""
        return worst, (f"{len(live)} sign-ins were open for {user} and nothing tells which one ran this, so SentrAI "
                       f"took the one it does not trust{where}")

    # ------------------------------------------------------------ the question
    def observe(self, ev: dict[str, Any], cls: Any, now: float) -> Verdict | None:
        """Who did this, and what should Warden make of it. None when the line is not about a person on a host."""
        if not self.on:
            return None
        host = str(ev.get("host") or "unknown")
        parsed = ev.get("parsed") if isinstance(ev.get("parsed"), dict) else {}
        malicious = cls.category != "benign" and float(cls.malicious) >= 0.4
        ssh = parse_sshd(ev)
        if ssh is not None:
            return self._observe_ssh(ev, ssh, host, cls, now)
        sudo = parse_sudo(ev)
        if sudo is not None:
            return self._observe_sudo(ev, sudo, host, cls, malicious, now)
        su = parse_su(ev)
        if su is not None:
            return self._observe_su(ev, su, host, cls, malicious, now)
        session = parse_login_session(ev)
        if session is not None:
            return self._observe_session(ev, session, host, cls, now)
        auth = parse_auth(ev)
        if auth is not None:
            if auth.outcome == "success" and auth.service in ("windows_logon", "rdp") and ev.get("user") \
                    and str(parsed.get("logon_type") or "") in WINDOWS_SESSION_LOGONS:
                if not self._windows_itself(str(ev["user"])):
                    self._start(host, str(ev["user"]), "windows", ev.get("src_ip"), None, None, None,
                                str(parsed.get("logon_type") or "windows"), now)
            return None
        if parsed.get("kind") == "windows_event" and ev.get("user") and not self._windows_itself(str(ev["user"])):
            privileged = str(parsed.get("win_event") or "") in WINDOWS_PRIVILEGED
            what = f"Windows {parsed.get('win_event', 'event')} by {ev['user']}"
            return self._verdict_for(host, str(ev["user"]), None, cls, malicious, privileged, what, now)
        if str(ev.get("source") or "") == "log_integrity" and malicious:
            if self._recent_wipe(host, now):
                return Verdict({"host": host, "trust": TRUSTED, "why": "follows a known administrator's own log command"},
                               suppress=True, reason="a log changed right after a known administrator's own command on it",
                               activity=f"log changed on disk: {str(ev.get('raw') or '')[:120]}")
            return None
        if ev.get("layer") == "os" and ev.get("user") and malicious and cls.category in SUPPRESSIBLE:
            return self._verdict_for(host, str(ev["user"]), None, cls, malicious, False,
                                     f"{str(ev.get('source') or 'host')}: {str(ev.get('raw') or '')[:120]}", now)
        return None

    @staticmethod
    def _windows_itself(user: str) -> bool:
        u = user.strip().lower()
        return u in WINDOWS_SYSTEM or u in SERVICE_ACCOUNTS or u.endswith("$") or u.startswith(("nt authority\\", "nt service\\"))

    def _observe_ssh(self, ev: dict[str, Any], ssh: Any, host: str, cls: Any, now: float) -> Verdict | None:
        if ssh.event == "accepted" and ssh.user and ssh.src_ip:
            s = self._start(host, ssh.user, "ssh", ssh.src_ip, None, ssh.key_fingerprint, ssh.key_type, ssh.method, now)
            if cls.category == "brute_force":  # the password was guessed: whatever the address, this sign-in is suspect
                s.trust, s.why = SUSPECT, f"SSH sign-in that followed password guessing ({cls.reason[:120]})"
                self.mark_suspect(ssh.src_ip, "password guessing", now)
            actor = self._actor(s, host, ssh.user)
            if ssh.user.lower() == "root" and s.trust != TRUSTED and cls.category == "benign":
                # Root itself signed in from a sign-in SentrAI does not know: that is the question already.
                # (A guessed password is the rules' brute-force finding, which stands; root's commands then ask.)
                return Verdict(actor, escalate=True, reason=f"root signed in over SSH: {s.why}", src_ip=s.src_ip)
            return Verdict(actor)
        parsed = ev.get("parsed") if isinstance(ev.get("parsed"), dict) else {}
        user = ssh.user or ev.get("user")
        if (parsed.get("ssh_event") == "session_closed" or ssh.event == "disconnect") and (user or ssh.src_ip):
            self._end(host, str(user) if user else None, now=now, ip=ssh.src_ip)
        return None

    def _observe_session(self, ev: dict[str, Any], session: Any, host: str, cls: Any, now: float) -> Verdict | None:
        if session.event == "ended":
            self._end(host, session.user, session.tty, session.sid, now)
            return None
        if not session.user:
            return None
        if not session.tty:  # systemd-logind: an id for a sign-in, nothing more
            self._logind(host, session.user, session.sid, now)
            return None
        origin = str(session.origin).strip("[]") if session.origin else None
        ip = origin if is_ip(origin) else None
        # No origin, or an X display (":0"), is the machine's own console; any other name is remote.
        remote_host = origin if origin and not ip and not origin.startswith(":") else None
        before = self._n
        s = self._start(host, session.user, "who", ip, session.tty, None, None, None, now,
                        since=_since_ts(session.since, now), preexisting=session.event == "existing",
                        remote_host=remote_host)
        fresh = self._n != before  # a sign-in not seen before (the collector repeats "existing" now and then)
        actor = self._actor(s, host, session.user)
        if fresh and session.user.lower() == "root" and s.trust != TRUSTED and not ip and not remote_host:
            # Root at the console. A remote root sign-in is asked about on sshd's line, which names its key.
            where = f"on {session.tty}" + (" since before SentrAI started watching" if s.preexisting else "")
            return Verdict(actor, escalate=True, reason=f"root is signed in {where}: {s.why}", src_ip=s.src_ip)
        return Verdict(actor)

    def _observe_sudo(self, ev: dict[str, Any], sudo: SudoLine, host: str, cls: Any, malicious: bool, now: float) -> Verdict | None:
        user = sudo.user or (str(ev.get("user")) if ev.get("user") else None)
        if not user or user.lower() in SERVICE_ACCOUNTS:
            return None  # a service account is never an administrator: the rules already said what this is
        if sudo.event in ("session_opened", "session_closed", "other"):
            return None
        privileged = sudo.event == "command"
        what = f"sudo{' as ' + sudo.target if sudo.target and sudo.target != 'root' else ''}: {(sudo.command or sudo.event)[:120]}"
        if not privileged:
            what = f"sudo {sudo.event.replace('_', ' ')}: {(sudo.command or '')[:120]}".rstrip(": ")
        return self._verdict_for(host, user, sudo.tty, cls, malicious, privileged, what, now)

    def _observe_su(self, ev: dict[str, Any], su: SuLine, host: str, cls: Any, malicious: bool, now: float) -> Verdict | None:
        user = su.user or (str(ev.get("user")) if ev.get("user") else None)
        if not user or user.lower() in SERVICE_ACCOUNTS or su.event in ("session_opened", "session_closed", "other"):
            return None
        privileged = su.event == "switched"
        what = f"su to {su.target or '?'}" + ("" if privileged else f" ({su.event.replace('_', ' ')})")
        v = self._verdict_for(host, user, su.tty, cls, malicious, privileged, what, now)
        if v is not None and privileged and su.target and v.actor.get("trust") == TRUSTED:
            # Root's own commands after `su` carry no TTY link back: let the switch open root's session on this terminal.
            s = self.sessions.get(str(v.actor.get("session") or ""))
            if s is not None:
                root = self._start(host, su.target, s.via, s.src_ip, su.tty or s.tty, s.key, s.key_type, s.method, now)
                root.trust, root.why = TRUSTED, f"opened with su by {user} in a trusted session ({s.why})"
        return v

    def _actor(self, s: Session | None, host: str, user: str, trust: str | None = None, why: str | None = None) -> dict[str, Any]:
        if s is None:
            return {"host": host, "user": user, "via": None, "address": None, "key": None, "session": None,
                    "trust": trust or UNKNOWN, "why": why or "no sign-in seen"}
        return {"host": host, "user": user, "via": s.via, "address": s.src_ip, "key": s.key, "session": s.sid,
                "trust": s.trust, "why": s.why, "since": self.clock.iso(s.started)}

    def _verdict_for(self, host: str, user: str, tty: str | None, cls: Any, malicious: bool, privileged: bool,
                     what: str, now: float) -> Verdict:
        self._expire(now)
        s, guessed = self._find(host, user, tty, now)
        if s is None:
            how = self._known_account(host, user)
            if how:
                trust, why = TRUSTED, f"no sign-in seen (SentrAI started watching after it), but {user} is a known administrator account ({how})"
            else:
                trust, why = UNKNOWN, f"no sign-in seen for {user} on {host}, and it is not a known administrator account"
            actor = self._actor(None, host, user, trust, why)
            src_ip = None
        else:
            s.last_seen = now
            if privileged:
                s.actions += 1
            self._touch()
            actor, trust, why, src_ip = self._actor(s, host, user), s.trust, s.why, s.src_ip
            if guessed:
                why = actor["why"] = f"{guessed} ({s.why})"
        if trust == TRUSTED:
            learned: list[str] = []
            if privileged and bool(getattr(self.settings, "admin_learn", True)) and not self._known_account(host, user):
                learned.append(self._learn_account(host, user, "a trusted sign-in", now))
            suppress = malicious and cls.category in SUPPRESSIBLE
            v = Verdict(actor, suppress=suppress, reason=f"a known administrator's own work ({why})", src_ip=src_ip,
                        activity=what if (privileged or suppress) else None, learned=learned)
            if v.activity:
                self.record_activity(host, user, actor, what, cls if suppress else _BENIGN, now)
            return v
        if privileged:
            return Verdict(actor, escalate=True, reason=(f"root work by {user} from a sign-in SentrAI does not recognise: {why}"
                                                         if trust == UNKNOWN else
                                                         f"root work by {user} from a sign-in SentrAI distrusts: {why}"),
                           src_ip=src_ip)
        return Verdict(actor, src_ip=src_ip)  # not root work: what the rules said stands, with the actor attached

    def record_activity(self, host: str, user: str, actor: dict[str, Any], what: str, cls: Any, now: float) -> None:
        self.activity.append({"at": self.clock.iso(now), "host": host, "user": user, "via": actor.get("via"),
                              "address": actor.get("address"), "session": actor.get("session"), "what": what,
                              "flagged_as": None if cls.category == "benign" else cls.category,
                              "reason": None if cls.category == "benign" else str(cls.reason)[:200]})
        self._touch()

    def _recent_wipe(self, host: str, now: float) -> bool:
        for a in reversed(self.activity):
            if a.get("host") != host:
                continue
            at = _since_ts(a.get("at"), 0.0)
            if now - at > WIPE_LINK_S:
                return False
            if a.get("flagged_as") == "log_tampering":
                return True
        return False

    # ------------------------------------------------------------ "this was me"
    def _sessions_of(self, inc: dict[str, Any], events: list[dict[str, Any]]) -> list[Session]:
        sids = {str((e.get("actor") or {}).get("session") or "") for e in events if isinstance(e, dict)}
        found = [self.sessions[s] for s in sids if s in self.sessions]
        if not found and inc.get("src_ip") and inc.get("host"):
            # No session on the events (SentrAI started after the sign-in): the live ones from that address.
            found = [s for s in self._live(str(inc["host"]), None, self.clock.now()) if s.src_ip == _canon_ip(inc["src_ip"])]
        return found

    def teach(self, inc: dict[str, Any], events: list[dict[str, Any]], operator: str, now: float) -> list[str]:
        """"This was me": the incident's sign-in facts become known administrator facts. Returns them in words."""
        learned: list[str] = []
        host, user = str(inc.get("host") or "unknown"), inc.get("user")
        seen_ip, seen_key = set(), set()
        for s in self._sessions_of(inc, events):
            s.trust, s.why, s.taught_by = TRUSTED, f"{operator} said this was them", operator
            if s.src_ip and s.src_ip not in seen_ip:
                seen_ip.add(s.src_ip)
                learned.append(self._learn_address(s.src_ip, operator, now, how="taught"))
            if s.key and s.key not in seen_key:
                seen_key.add(s.key)
                learned.append(self._learn_key(s.key, s.key_type, s.user, operator, now, how="taught"))
            if s.user and s.user.lower() not in SERVICE_ACCOUNTS:
                learned.append(self._learn_account(host, s.user, operator, now, how="taught"))
        ip = _canon_ip(inc.get("src_ip"))
        if ip and ip not in seen_ip and not ipaddress.ip_address(ip).is_loopback:
            learned.append(self._learn_address(ip, operator, now, how="taught"))
        if user and str(user).lower() not in SERVICE_ACCOUNTS and (inc.get("layer") == "os" or inc.get("category") == CATEGORY) \
                and f"account {user} on {host}" not in learned:
            learned.append(self._learn_account(host, str(user), operator, now, how="taught"))
        for e in events:
            if isinstance(e, dict) and isinstance(e.get("actor"), dict):
                e["actor"]["trust"], e["actor"]["why"] = TRUSTED, f"{operator} said this was them"
        self._suspect.pop(ip or "", None)
        self._touch(write=True)
        return list(dict.fromkeys(learned))

    def distrust(self, inc: dict[str, Any], events: list[dict[str, Any]], operator: str, now: float) -> list[str]:
        """"Not me": the sign-in is an intruder's. What was only learned from it is forgotten, and its address is suspect."""
        forgotten: list[str] = []
        for s in self._sessions_of(inc, events):
            s.trust, s.why = SUSPECT, f"{operator} said this was not them"
            if s.src_ip and (self.addresses.get(s.src_ip) or {}).get("how") == "learned":
                del self.addresses[s.src_ip]
                forgotten.append(f"address {s.src_ip}")
            if s.key and (self.keys.get(s.key) or {}).get("how") == "learned":
                del self.keys[s.key]
                forgotten.append(f"SSH key {short_key(s.key)}")
            self.mark_suspect(s.src_ip, f"{operator} said a sign-in from it was not them", now)
        if ip := _canon_ip(inc.get("src_ip")):
            self.signins.pop(ip, None)
            self.mark_suspect(ip, f"{operator} said a sign-in from it was not them", now)
        self._touch(write=True)
        return forgotten

    def same_actor(self, inc: dict[str, Any], events: list[dict[str, Any]], other: dict[str, Any],
                   other_events: list[dict[str, Any]]) -> bool:
        """Whether another incident is the same person's doing: same machine and the same sign-in, or the
        same account on a host-level incident with no address of its own."""
        if other.get("host") != inc.get("host"):
            return False
        mine = {str((e.get("actor") or {}).get("session") or "") for e in other_events if isinstance(e, dict)} - {""}
        theirs = {s.sid for s in self._sessions_of(inc, events)}
        if mine and theirs and mine & theirs:
            return True
        same_user = bool(inc.get("user")) and str(inc.get("user")).lower() == str(other.get("user") or "").lower()
        same_ip = bool(inc.get("src_ip")) and inc.get("src_ip") == other.get("src_ip")
        host_level = other.get("layer") == "os" or other.get("category") == CATEGORY
        return host_level and (same_ip or (same_user and not other.get("src_ip")))

    # ------------------------------------------------------------ the dashboard
    def signed_in(self, email: str, role: str, ip: str | None, now: float) -> dict[str, Any]:
        """A dashboard sign-in with the authenticator vouches for its address for ADMIN_SIGNIN_HOURS."""
        ip = _canon_ip(ip)
        vouches = bool(ip) and str(role or "").strip().lower() in ("owner", "admin") and self.on
        if not vouches:
            return {"ok": True, "vouched": False, "address": ip, "until": None}
        until = now + self._signin_window()
        self.signins[ip] = {"email": email, "role": role, "at": self.clock.iso(now), "until": until}
        for key in [k for k, v in self.signins.items() if float(v.get("until", 0)) <= now]:
            del self.signins[key]
        self._touch(write=True)
        return {"ok": True, "vouched": True, "address": ip, "until": self.clock.iso(until)}

    def change(self, operator: str, action: str, kind: str, value: str, label: str = "", host: str | None = None,
               now: float | None = None) -> dict[str, Any]:
        """Add or forget one known administrator fact by hand. Raises ValueError for a bad value."""
        now = self.clock.now() if now is None else now
        value = str(value or "").strip()
        if action not in ("add", "forget"):
            raise ValueError("action must be add or forget")
        if kind == "address":
            try:
                ipaddress.ip_network(value.strip("[]"), strict=False)
            except ValueError:
                raise ValueError(f"{value!r} is not an address or a network")
            if "/" not in value:
                value = _canon_ip(value) or value
            if action == "add":
                self.addresses[value] = {"how": "taught", "by": operator, "at": self.clock.iso(now), "label": label,
                                        "last_seen": None}
            else:
                self.addresses.pop(value, None)
                self.signins.pop(value, None)
        elif kind == "key":
            if not KEY_RX.match(value):
                raise ValueError("a key fingerprint looks like SHA256:... (ssh-keygen -lf id_ed25519.pub shows it)")
            if action == "add":
                self.keys[value] = {"type": None, "users": [], "how": "taught", "by": operator, "at": self.clock.iso(now),
                                    "label": label, "last_seen": None}
            else:
                self.keys.pop(value, None)
        elif kind == "account":
            user, _, at_host = value.partition("@")
            at_host = (host or at_host or "*").strip().lower()
            if not user or re.search(r"\s", user):
                raise ValueError("an account is a user name, or user@machine")
            key = f"{user.lower()}@{at_host}"
            if action == "add":
                self.accounts[key] = {"how": "taught", "by": operator, "at": self.clock.iso(now), "label": label}
            else:
                self.accounts.pop(key, None)
        else:
            raise ValueError("kind must be address, key or account")
        self._touch(write=True)
        return self.public(now)

    def public(self, now: float | None = None) -> dict[str, Any]:
        now = self.clock.now() if now is None else now
        self._expire(now)
        iso = self.clock.iso
        s = self.settings
        accounts = [{"account": k.split("@", 1)[0], "host": k.split("@", 1)[1], **v} for k, v in sorted(self.accounts.items())]
        accounts += [{"account": a.split("@", 1)[0], "host": a.split("@", 1)[1] if "@" in a else "*", "how": "setting",
                      "by": HOW_CONFIG["account"], "at": None} for a in sorted(getattr(s, "admin_accounts", set()) or set())]
        addresses = [{"address": k, **v} for k, v in sorted(self.addresses.items())]
        addresses += [{"address": a, "how": "setting", "by": HOW_CONFIG["address"], "at": None, "label": "", "last_seen": None}
                      for a in sorted(getattr(s, "admin_ips", set()) or set())]
        keys = [{"fingerprint": k, **v} for k, v in sorted(self.keys.items())]
        keys += [{"fingerprint": k, "type": None, "users": [], "how": "setting", "by": HOW_CONFIG["key"], "at": None,
                  "last_seen": None} for k in sorted(getattr(s, "admin_ssh_keys", set()) or set())]
        signins = [{"address": ip, "email": v.get("email"), "role": v.get("role"), "at": v.get("at"),
                    "until": iso(float(v.get("until", 0)))} for ip, v in sorted(self.signins.items())
                   if float(v.get("until", 0)) > now]
        return {
            "on": self.on,
            "accounts": accounts, "addresses": addresses, "keys": keys, "sign_ins": signins,
            "sessions": [x.public(iso) for x in sorted(self.sessions.values(), key=lambda x: x.last_seen, reverse=True)
                         if not x.ended],
            "activity": list(reversed(self.activity)),
            "suspect": [{"address": ip, "why": why, "until": iso(until)} for ip, (until, why) in sorted(self._suspect.items())
                        if until > now],
            "settings": {"session_hours": float(getattr(s, "admin_session_hours", 12.0)),
                         "signin_hours": float(getattr(s, "admin_signin_hours", 12.0)),
                         "learn": bool(getattr(s, "admin_learn", True))},
        }
