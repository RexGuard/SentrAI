"""Part 1 of 3: the collector. Turns raw logs into Events and ships them to core.

A source is any ``Source`` subclass: implement ``poll()`` and return new Event
dicts (build them with ``make_event`` so every source emits the same shape, see
``mvp/CONTRACT.md``). The ``Collector`` polls all its sources, batches the events
to core ``POST /events`` once per second, and keeps them buffered while core is down.

Default sources: one ``JsonLogSource`` per target-app log, one ``DiscoveredLogSource`` (or
``JournaldSource``) per approved server log in ``scout/sources.json``, plus a ``HeartbeatSource``
every 10 seconds so Watchdog can tell the collector is alive.

Server logs (nginx, sshd via syslog or journald) are parsed by ``collector/parsers.py``: events carry
the log's own timestamp and host name and a ``parsed`` object (see "Parsed fields" in
``mvp/CONTRACT.md``). Read positions are saved in ``collector-state.json`` (next to the settings
file, or ``CACTAI_COLLECTOR_STATE``) once core has accepted the events, so a restart carries on
where it stopped instead of re-sending whole files.

Run:  python -m collector.collector           (from mvp/lab)
   or python collector/collector.py
      python -m collector.collector --add-system-logs   approve this server's nginx and SSH logs

On a new machine (no settings file yet) it first runs the setup wizard in
``mvp/cactai_config.py``; the logs directory and file names come from there.

Handles file creation (logs may not exist yet), rotation (reads the rest of the rotated
``.1`` file first) and truncation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# Allow running both as ``python -m collector.collector`` and as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.append(str(Path(__file__).resolve().parents[2]))
import cactai_config  # noqa: E402

if __name__ == "__main__":
    # First run on this machine: ask for the settings before any path or log name is read.
    cactai_config.ensure()
from collector import parsers  # noqa: E402
from target_app import paths  # noqa: E402

HOST = "web-01"  # the demo portal's pretend server name; real logs use the real host name

# log file -> (layer, source)
SOURCE_MAP = {
    paths.ACCESS_LOG: ("web", "flask_access"),
    paths.AUTH_LOG: ("web", "flask_auth"),
    paths.DB_LOG: ("db", "db_query"),
    paths.OS_LOG: ("os", "os_process"),
    paths.DECEPTION_LOG: ("web", "cactus_spine"),  # a spine sets its own layer ("db" for bait rows)
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def real_host() -> str:
    """This machine's name (``CACTAI_HOST`` overrides), for server logs that don't name their host."""
    return os.environ.get("CACTAI_HOST") or socket.gethostname() or "unknown"


def criticality_for(layer: str, record: dict) -> float:
    """1.5 for DB-layer or PII-tagged events, else 1.0."""
    if layer == "db" or record.get("pii"):
        return 1.5
    return 1.0


def make_event(layer: str, source: str, raw: str, *, src_ip: str | None = None, user: str | None = None,
               ts: str | None = None, criticality: float = 1.0, host: str | None = None,
               parsed: dict[str, Any] | None = None) -> dict[str, Any]:
    """The one place an Event dict is built (contract Event schema)."""
    event = {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": ts or _now_iso(),
        "host": host or HOST,
        "layer": layer,
        "source": source,
        "src_ip": src_ip,
        "user": user,
        "raw": raw,
        "asset_criticality": criticality,
    }
    if parsed is not None:
        event["parsed"] = parsed
    return event


def normalize(log_name: str, record: dict[str, Any]) -> dict[str, Any] | None:
    """Turn one raw log line into a contract Event dict.

    Returns None if the log file is unknown.
    """
    mapping = SOURCE_MAP.get(log_name)
    if mapping is None:
        return None
    layer, source = mapping
    if source == "cactus_spine" and record.get("layer") in ("web", "db", "os", "network", "cloud"):
        layer = record["layer"]
    return make_event(layer, source, record.get("raw", ""), src_ip=record.get("src_ip"), user=record.get("user"),
                      ts=record.get("ts"), criticality=criticality_for(layer, record),
                      parsed=_demo_fields(source, record))


def _demo_fields(source: str, record: dict[str, Any]) -> dict[str, Any]:
    """The demo portal's JSON fields in the same ``parsed`` shape as real logs, so rules can use either."""
    f: dict[str, Any] = {"format": "cactai_demo"}
    if source == "flask_access":
        f.update(kind="http_request", method=record.get("method"), path=record.get("path"),
                 status=record.get("status"))
    elif source == "flask_auth":
        result = str(record.get("result") or "")
        f.update(kind="web_login", outcome="success" if result in ("success", "ok") else "failure" if result else "info")
    elif source == "db_query":
        f.update(kind="db_query", rows=record.get("rows"))
    else:
        f["kind"] = "log"
    return f


def heartbeat_event() -> dict[str, Any]:
    return make_event("os", "heartbeat", "collector heartbeat")


def state_file() -> Path:
    env = os.environ.get("CACTAI_COLLECTOR_STATE")
    return Path(env) if env else cactai_config.config_path().parent / "collector-state.json"


def path_key(path: Path) -> str:
    """How a file is named in collector-state.json."""
    return str(path.absolute())


class OffsetStore:
    """Where each log was read up to, saved as JSON so a restart resumes instead of re-sending."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or state_file()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.data: dict[str, dict] = data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            self.data = {}

    def get(self, key: str) -> dict | None:
        entry = self.data.get(key)
        return entry if isinstance(entry, dict) else None

    def save(self, updates: dict[str, dict]) -> None:
        if not updates or all(self.data.get(k) == v for k, v in updates.items()):
            return
        self.data.update(updates)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(json.dumps(self.data, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            print(f"[collector] could not save read positions to {self.path} ({exc})", flush=True)


HEAD_BYTES = 256            # the start of a file identifies it across renames and restarts
MAX_READ = 1 << 20          # read at most 1 MiB per file per poll
BACKFILL = int(os.environ.get("CACTAI_COLLECTOR_BACKFILL_KB", "256")) * 1024


class Tailer:
    """Follows a single append-only file, tolerant of creation, rotation and truncation.

    ``start`` says where to begin the first time a file that already exists is seen with no
    saved position: "beginning", "end", or "backfill" (only its last ``BACKFILL`` bytes).
    A file that appears later is always read from its beginning. ``checkpoint()`` returns the
    position to save once the lines read so far have been delivered.
    """

    def __init__(self, path: Path, saved: dict | None = None, start: str = "beginning") -> None:
        self.path = path
        self.pos = 0
        self._inode: int | None = None
        self._head: str | None = None
        self._head_len = 0
        self._first = True
        self._saved = saved
        self._start = start
        self._warned = False

    # -- file identity
    @staticmethod
    def _fingerprint(path: Path, length: int) -> str | None:
        try:
            with open(path, "rb") as fh:
                return hashlib.sha1(fh.read(length)).hexdigest()
        except OSError:
            return None

    def _remember_head(self, size: int) -> None:
        if self._head_len < HEAD_BYTES and size > self._head_len:
            self._head_len = min(size, HEAD_BYTES)
            self._head = self._fingerprint(self.path, self._head_len)

    def _same_file(self, path: Path, inode: int, size: int, want_inode: int | None, head: str | None,
                   head_len: int) -> bool:
        if want_inode and inode and inode != want_inode:
            return False
        if size < head_len:
            return False
        return head is None or self._fingerprint(path, head_len) == head

    def checkpoint(self) -> dict:
        return {"pos": self.pos, "inode": self._inode or 0, "head": self._head, "head_len": self._head_len}

    def _stat(self, path: Path | None = None):
        try:
            return (path or self.path).stat()
        except FileNotFoundError:
            return None
        except OSError:
            return None

    def _begin(self, st) -> list[str]:
        """First look at a file: resume a saved position, or apply the start policy."""
        self._first = False
        inode, size = getattr(st, "st_ino", 0), st.st_size
        saved = self._saved
        lines: list[str] = []
        if saved:
            s_inode, s_pos = saved.get("inode") or 0, int(saved.get("pos") or 0)
            s_head, s_len = saved.get("head"), int(saved.get("head_len") or 0)
            if self._same_file(self.path, inode, size, s_inode, s_head, s_len) and size >= s_pos:
                self.pos, self._head, self._head_len = s_pos, s_head, s_len
                self._inode = inode
                return []
            # Rotated while we were stopped: finish the old file (now "<name>.1"), then read the new one.
            lines = self._drain_rotated(s_inode, s_pos, s_head, s_len)
            self.pos = 0
        elif self._start == "end":
            self.pos = size
        elif self._start == "backfill" and size > BACKFILL:
            self.pos = self._line_start(size - BACKFILL)
        self._inode = inode
        self._head, self._head_len = None, 0
        return lines

    def _line_start(self, offset: int) -> int:
        """The first line boundary at or after ``offset``."""
        try:
            with open(self.path, "rb") as fh:
                fh.seek(max(offset - 1, 0))
                if offset == 0 or fh.read(1) == b"\n":
                    return offset
                fh.readline()
                return fh.tell()
        except OSError:
            return offset

    def _drain_rotated(self, inode: int, pos: int, head: str | None, head_len: int) -> list[str]:
        """logrotate renames access.log to access.log.1: read what was added there after ``pos``."""
        old = self.path.with_name(self.path.name + ".1")
        st = self._stat(old)
        if st is None or st.st_size <= pos or not self._same_file(old, getattr(st, "st_ino", 0), st.st_size,
                                                                  inode, head, head_len):
            return []
        lines, _ = self._read_from(old, pos, st.st_size, final=True)
        return lines

    def _read_from(self, path: Path, pos: int, size: int, final: bool = False) -> tuple[list[str], int]:
        """Complete lines from ``pos``; returns them and the new position (a partial last line stays unread)."""
        try:
            with open(path, "rb") as fh:
                fh.seek(pos)
                chunk = fh.read(min(size - pos, MAX_READ))
        except OSError as exc:
            if not self._warned:
                self._warned = True
                print(f"[collector] cannot read {path} ({exc.__class__.__name__}: {exc}); "
                      f"run the collector as a user that can read it", flush=True)
            return [], pos
        self._warned = False
        end = chunk.rfind(b"\n")
        if end < 0 and not final and len(chunk) < MAX_READ:
            return [], pos  # no complete line yet
        used = chunk if (end < 0 or (final and end < len(chunk) - 1)) else chunk[:end + 1]
        text = used.decode("utf-8", errors="replace")
        lines = [ln.strip() for ln in text.split("\n")]
        return [ln for ln in lines if ln], pos + len(used)

    def read_new_lines(self) -> list[str]:
        st = self._stat()
        if st is None:
            # File not created yet (or gone): when it appears it is new, so read it from the start.
            if self._first and self._saved:
                pass  # keep the saved position until the file is back
            else:
                self._first = False
                self.pos = 0
                self._inode = None
                self._head, self._head_len = None, 0
            return []
        lines: list[str] = []
        if self._first:
            lines = self._begin(st)
        inode = getattr(st, "st_ino", 0)
        # Rotation (new inode) or truncation (shrunk file): start again from the top.
        if self._inode is not None and inode != self._inode:
            lines += self._drain_rotated(self._inode, self.pos, self._head, self._head_len)
            self.pos, self._head, self._head_len = 0, None, 0
        elif st.st_size < self.pos:
            self.pos, self._head, self._head_len = 0, None, 0
        self._inode = inode
        self._remember_head(st.st_size)
        if st.st_size > self.pos:
            new, self.pos = self._read_from(self.path, self.pos, st.st_size)
            lines += new
        return lines


class Source(ABC):
    """Anything that produces events: a log file, a syslog socket, a cloud API."""

    key: str | None = None  # names the source in collector-state.json; None = nothing to resume

    @abstractmethod
    def poll(self) -> list[dict[str, Any]]:
        """Return the Events that appeared since the last call (may be empty)."""

    def checkpoint(self) -> dict | None:
        """Where to resume after a restart, once the events polled so far have reached core."""
        return None


class FileSource(Source):
    """A source that tails one file and can resume from a saved read position."""

    def __init__(self, path: Path, saved: dict | None = None, start: str = "beginning") -> None:
        self.name = path.name
        self.key = path_key(path)
        self.tailer = Tailer(path, saved, start)

    def checkpoint(self) -> dict | None:
        return self.tailer.checkpoint()


class JsonLogSource(FileSource):
    """One JSON-lines log file written by the target app."""

    def poll(self) -> list[dict[str, Any]]:
        events = []
        for line in self.tailer.read_new_lines():
            try:
                event = normalize(self.name, json.loads(line))
            except json.JSONDecodeError:
                continue
            if event is not None:
                events.append(event)
        return events


class HeartbeatSource(Source):
    """Emits one heartbeat event every ``interval`` seconds."""

    def __init__(self, interval: float = 10.0) -> None:
        self.interval = interval
        self._last = time.time()  # first heartbeat one interval after start

    def poll(self) -> list[dict[str, Any]]:
        now = time.time()
        if now - self._last < self.interval:
            return []
        self._last = now
        return [heartbeat_event()]


IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER = re.compile(r"(?i)\b(?:user(?:name)?|for(?: invalid user)?)[=: ]+([\w.@-]+)")


def server_log_event(line: str, layer: str, source: str, fmt: str) -> dict[str, Any]:
    """One line of a real server log -> Event. Known formats (nginx, syslog/sshd, journald JSON) are
    parsed; anything else keeps its raw text with the source IP and user guessed from it."""
    src_ip = user = ts = host = None
    fields: dict[str, Any] | None = None
    raw = line
    if fmt == "jsonl":
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            rec = None
        if isinstance(rec, dict):
            src_ip = next((str(rec[k]) for k in ("src_ip", "ip", "client_ip", "remote_addr") if rec.get(k)), None)
            user = next((str(rec[k]) for k in ("user", "username", "account") if rec.get(k)), None)
            ts = rec.get("ts") or rec.get("timestamp")
            ts = ts if isinstance(ts, str) else None
        fields = {"format": "jsonl", "kind": "log"}
    elif (p := parsers.parse_line(line, fmt)) is not None:
        src_ip, user, ts, host, fields = p.src_ip, p.user, p.ts, p.host, p.fields
        if fmt == "journald":
            raw = str(fields.get("message") or line)
    if fields is None:
        fields = {"format": "text", "kind": "log"}
    guess = fields.get("kind") == "log" or fields.get("ssh_event") == "other"
    if src_ip is None and guess and (m := IPV4.search(raw)):
        src_ip = m.group(0)
    if user is None and guess and (m := USER.search(raw)):
        user = m.group(1)
    return make_event(layer, source, raw[:2000], src_ip=src_ip, user=user, ts=ts, host=host or real_host(),
                      parsed=fields)


class DiscoveredLogSource(FileSource):
    """A log file Scout found and the technician approved (``scout/sources.json``).

    Any format: each new line becomes one event carrying the raw text. nginx access/error logs and
    syslog files (auth.log, secure: sshd and friends) are parsed into the ``parsed`` fields with the
    log's own timestamp and host; JSON-lines fields are used when present; otherwise the source IP
    and user are guessed from the text.

    With no saved read position, a file that exists at startup is read from its last
    ``CACTAI_COLLECTOR_BACKFILL_KB`` (256) KB, and one approved while running only from its end."""

    def __init__(self, path: Path, layer: str, fmt: str = "text", from_end: bool = False,
                 saved: dict | None = None) -> None:
        super().__init__(path, saved, "end" if from_end else "backfill")
        self.layer, self.fmt = layer, fmt
        self.source = f"scout:{path.name}"

    def poll(self) -> list[dict[str, Any]]:
        return [server_log_event(line, self.layer, self.source, self.fmt) for line in self.tailer.read_new_lines()]


JOURNALD_SSH = ["SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sshd-auth"]


class JournaldSource(Source):
    """Follows ``journalctl -o json`` for systems that keep SSH logins only in the journal (no
    /var/log/auth.log or /var/log/secure). sources.json entry: ``{"path": "journald:sshd",
    "format": "journald", "layer": "os"}``; ``"match"`` (a list of journalctl matches) picks other
    programs. Resumes from the saved journal cursor; with none, starts with the last 200 entries."""

    def __init__(self, layer: str = "os", match: list[str] | None = None, name: str = "sshd",
                 saved: dict | None = None, from_end: bool = False, command: list[str] | None = None) -> None:
        self.name = f"journald:{name}"
        self.key = self.name
        self.layer = layer
        self.source = f"journald:{name}"
        self.match = match or JOURNALD_SSH
        self.cursor: str | None = (saved or {}).get("cursor")
        self._read_cursor = self.cursor
        self._from_end = from_end
        self._command = command
        self._proc: subprocess.Popen | None = None
        self._lines: queue.Queue[str] = queue.Queue()
        self._next_start = 0.0
        self._warned = False

    def command(self) -> list[str]:
        if self._command is not None:
            return self._command
        cmd = ["journalctl", "-o", "json", "--no-pager", "--follow"]
        if self._read_cursor:
            cmd += ["--after-cursor", self._read_cursor]
        else:
            cmd += ["--lines", "0" if self._from_end else "200"]
        return cmd + self.match

    def _start(self) -> None:
        if time.time() < self._next_start:
            return
        self._next_start = time.time() + 10  # retry a failed journalctl at most every 10 s
        try:
            self._proc = subprocess.Popen(self.command(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                          stdin=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
        except OSError as exc:
            if not self._warned:
                self._warned = True
                print(f"[collector] cannot run journalctl ({exc}); SSH logins are not collected", flush=True)
            self._proc = None
            return
        threading.Thread(target=self._pump, args=(self._proc,), daemon=True).start()

    def _pump(self, proc: subprocess.Popen) -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            self._lines.put(line)

    def poll(self) -> list[dict[str, Any]]:
        if self._proc is None or (self._proc.poll() is not None and self._lines.empty()):
            self._start()
        events = []
        while True:
            try:
                line = self._lines.get_nowait().strip()
            except queue.Empty:
                break
            if not line:
                continue
            parsed = parsers.parse_journald(line)
            if parsed is None:
                continue
            if parsed.extra.get("cursor"):
                self._read_cursor = parsed.extra["cursor"]
            events.append(server_log_event(line, self.layer, self.source, "journald"))
        return events

    def checkpoint(self) -> dict | None:
        return {"cursor": self._read_cursor} if self._read_cursor else None

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()


def source_for(entry: dict, store: OffsetStore | None = None, from_end: bool = False) -> Source:
    """A ``scout/sources.json`` entry -> the Source that reads it."""
    fmt = entry.get("format", "text")
    if fmt == "journald" or str(entry["path"]).startswith("journald:"):
        name = str(entry["path"]).split(":", 1)[1] if ":" in str(entry["path"]) else "sshd"
        key = f"journald:{name}"
        return JournaldSource(entry["layer"], entry.get("match"), name,
                              saved=store.get(key) if store else None, from_end=from_end)
    path = Path(entry["path"])
    return DiscoveredLogSource(path, entry["layer"], fmt, from_end=from_end,
                               saved=store.get(path_key(path)) if store else None)


def discovered_sources(store: OffsetStore | None = None) -> list[Source]:
    from scout import sources as scout_sources

    return [source_for(s, store) for s in scout_sources.load()]


def default_sources(logs_dir: Path, heartbeat_interval: float = 10.0, store: OffsetStore | None = None) -> list[Source]:
    def saved(name: str) -> dict | None:
        return store.get(path_key(logs_dir / name)) if store else None

    return [*(JsonLogSource(logs_dir / name, saved(name)) for name in SOURCE_MAP), *discovered_sources(store),
            HeartbeatSource(heartbeat_interval)]


class Collector:
    def __init__(self, core_url: str, logs_dir: Path,
                 flush_interval: float = 1.0, heartbeat_interval: float = 10.0,
                 sources: list[Source] | None = None, token: str = ""):
        self.core_url = core_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"} if token else {}
        self.logs_dir = logs_dir
        self.flush_interval = flush_interval
        self.heartbeat_interval = heartbeat_interval
        self.watch_sources = sources is None  # default set: also pick up newly approved log files
        self.store = OffsetStore() if sources is None else None
        self.sources = sources if sources is not None else default_sources(logs_dir, heartbeat_interval, self.store)
        self._sources_stamp: float | None = None
        self._tail_from_end = False
        self._started = time.time()
        self.pending: list[dict] = []

    def refresh_discovered(self) -> list[Source]:
        """Start tailing log files approved since startup (Scout, or a process scan in the dashboard)."""
        from scout import sources as scout_sources

        f = scout_sources.sources_file()
        try:
            stamp = f.stat().st_mtime
        except OSError:
            return []
        if stamp == self._sources_stamp:
            return []
        self._tail_from_end = self._sources_stamp is not None or stamp > self._started
        self._sources_stamp = stamp
        tailed = {str(s.tailer.path) for s in self.sources if isinstance(s, DiscoveredLogSource)}
        tailed |= {s.name for s in self.sources if isinstance(s, JournaldSource)}
        added: list[Source] = [source_for(s, self.store, from_end=self._tail_from_end)
                               for s in scout_sources.load() if str(Path(s["path"])) not in tailed
                               and s["path"] not in tailed]
        for src in added:
            print(f"[collector] now watching {src.name} ({src.layer})", flush=True)
        self.sources[-1:-1] = added  # before the heartbeat
        return added

    def collect(self) -> None:
        if self.watch_sources:
            self.refresh_discovered()
        for source in self.sources:
            self.pending.extend(source.poll())

    def flush(self) -> bool:
        """POST pending events. Keep them buffered if core is down."""
        if not self.pending:
            self.save_positions()
            return True
        batch = self.pending
        try:
            resp = requests.post(f"{self.core_url}/events", json=batch, headers=self.headers, timeout=3)
            resp.raise_for_status()
            body = {}
            try:
                body = resp.json()
            except Exception:
                pass
            print(f"[collector] sent {len(batch)} events -> core "
                  f"(risk_index={body.get('risk_index', '?')})", flush=True)
            self.pending = []
            self.save_positions()
            return True
        except Exception as exc:
            print(f"[collector] core unreachable ({exc.__class__.__name__}); "
                  f"buffering {len(batch)} events, will retry", flush=True)
            return False

    def save_positions(self) -> None:
        """Everything polled so far has reached core: remember where each log was read up to."""
        if self.store is None:
            return
        self.store.save({s.key: cp for s in self.sources if s.key and (cp := s.checkpoint()) is not None})

    def run(self) -> None:
        print(f"[collector] tailing {self.logs_dir} -> {self.core_url}/events "
              f"(flush {self.flush_interval}s, heartbeat {self.heartbeat_interval}s)",
              flush=True)
        while True:
            self.collect()
            self.flush()
            time.sleep(self.flush_interval)


NGINX_LOGS = [("/var/log/nginx/access.log", "web", "nginx"), ("/var/log/nginx/error.log", "web", "nginx")]
AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure"]  # Debian/Ubuntu, RHEL/Fedora


def system_log_entries(root: Path = Path("/"), has_journalctl: bool | None = None) -> list[dict]:
    """This server's nginx and SSH login logs, as ``scout/sources.json`` entries."""
    def here(p: str) -> Path:
        return root / p.lstrip("/")

    entries = [{"path": str(here(p)), "layer": layer, "format": fmt, "why": "nginx web server log"}
               for p, layer, fmt in NGINX_LOGS if here(p).is_file()]
    auth = next((here(p) for p in AUTH_LOGS if here(p).is_file()), None)
    if auth is not None:
        entries.append({"path": str(auth), "layer": "os", "format": "syslog", "why": "SSH logins (sshd)"})
    elif has_journalctl if has_journalctl is not None else shutil.which("journalctl"):
        entries.append({"path": "journald:sshd", "layer": "os", "format": "journald",
                        "why": "SSH logins (sshd) from the systemd journal; this system has no auth.log"})
    return entries


def add_system_logs() -> int:
    from scout import sources as scout_sources

    entries = system_log_entries()
    if not entries:
        print("[collector] found no nginx, auth.log, secure or journald logs on this machine")
        return 1
    for e in entries:
        scout_sources.add(e, "collector --add-system-logs")
        print(f"[collector] approved {e['path']} ({e['why']})")
    print(f"[collector] saved to {scout_sources.sources_file()}; a running collector picks them up by itself")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="SentrAI log collector")
    ap.add_argument("--core", default=os.environ.get("CACTAI_CORE_URL",
                                                      "http://127.0.0.1:8000"))
    ap.add_argument("--logs", default=str(paths.logs_dir()))
    ap.add_argument("--flush-interval", type=float, default=1.0)
    ap.add_argument("--heartbeat-interval", type=float, default=10.0)
    ap.add_argument("--add-system-logs", action="store_true",
                    help="approve this server's nginx logs and SSH login log (auth.log, secure or journald), then exit")
    args = ap.parse_args()
    if args.add_system_logs:
        sys.exit(add_system_logs())

    logs_dir = Path(args.logs)
    logs_dir.mkdir(parents=True, exist_ok=True)
    Collector(args.core, logs_dir, args.flush_interval,
              args.heartbeat_interval, token=cactai_config.api_token()).run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[collector] stopped.")
