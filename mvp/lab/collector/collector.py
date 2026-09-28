"""Part 1 of 3: the collector. Turns raw logs into Events and ships them to core.

A source is any ``Source`` subclass: implement ``poll()`` and return new Event
dicts (build them with ``make_event`` so every source emits the same shape, see
``mvp/CONTRACT.md``). The ``Collector`` polls all its sources, batches the events
to core ``POST /events`` once per second, and keeps them buffered while core is down.

Default sources: one ``JsonLogSource`` per target-app log, plus a ``HeartbeatSource``
every 10 seconds so Watchdog can tell the collector is alive.

Run:  python -m collector.collector           (from mvp/lab)
   or python collector/collector.py

On a new machine (no settings file yet) it first runs the setup wizard in
``mvp/cactai_config.py``; the logs directory and file names come from there.

Handles file creation (logs may not exist yet) and rotation/truncation.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
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
from target_app import paths  # noqa: E402

HOST = "web-01"
SGT = timezone(timedelta(hours=8))

# log file -> (layer, source)
SOURCE_MAP = {
    paths.ACCESS_LOG: ("web", "flask_access"),
    paths.AUTH_LOG: ("web", "flask_auth"),
    paths.DB_LOG: ("db", "db_query"),
    paths.OS_LOG: ("os", "os_process"),
}


def _now_iso() -> str:
    return datetime.now(SGT).isoformat(timespec="seconds")


def criticality_for(layer: str, record: dict) -> float:
    """1.5 for DB-layer or PII-tagged events, else 1.0."""
    if layer == "db" or record.get("pii"):
        return 1.5
    return 1.0


def make_event(layer: str, source: str, raw: str, *, src_ip: str | None = None, user: str | None = None,
               ts: str | None = None, criticality: float = 1.0) -> dict[str, Any]:
    """The one place an Event dict is built (contract Event schema)."""
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": ts or _now_iso(),
        "host": HOST,
        "layer": layer,
        "source": source,
        "src_ip": src_ip,
        "user": user,
        "raw": raw,
        "asset_criticality": criticality,
    }


def normalize(log_name: str, record: dict[str, Any]) -> dict[str, Any] | None:
    """Turn one raw log line into a contract Event dict.

    Returns None if the log file is unknown.
    """
    mapping = SOURCE_MAP.get(log_name)
    if mapping is None:
        return None
    layer, source = mapping
    return make_event(layer, source, record.get("raw", ""), src_ip=record.get("src_ip"), user=record.get("user"),
                      ts=record.get("ts"), criticality=criticality_for(layer, record))


def heartbeat_event() -> dict[str, Any]:
    return make_event("os", "heartbeat", "collector heartbeat")


class Tailer:
    """Follows a single append-only file, tolerant of creation & rotation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.pos = 0
        self._inode: int | None = None
        self._buf = ""

    def _stat(self):
        try:
            return self.path.stat()
        except FileNotFoundError:
            return None

    def read_new_lines(self) -> list[str]:
        st = self._stat()
        if st is None:
            # File not created yet.
            self.pos = 0
            self._inode = None
            return []
        inode = getattr(st, "st_ino", 0)
        # Rotation / truncation detection: new inode or shrunk file.
        if self._inode is not None and inode != self._inode:
            self.pos = 0
        if st.st_size < self.pos:
            self.pos = 0
        self._inode = inode
        if st.st_size == self.pos:
            return []
        lines: list[str] = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self.pos)
            chunk = fh.read()
            self.pos = fh.tell()
        self._buf += chunk
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.strip()
            if line:
                lines.append(line)
        return lines


class Source(ABC):
    """Anything that produces events: a log file, a syslog socket, a cloud API."""

    @abstractmethod
    def poll(self) -> list[dict[str, Any]]:
        """Return the Events that appeared since the last call (may be empty)."""


class JsonLogSource(Source):
    """One JSON-lines log file written by the target app."""

    def __init__(self, path: Path) -> None:
        self.name = path.name
        self.tailer = Tailer(path)

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


class DiscoveredLogSource(Source):
    """A log file Scout found and the technician approved (``scout/sources.json``).

    Any format: each new line becomes one event carrying the raw text. The source IP and
    user are taken from JSON fields when present, otherwise guessed from the text."""

    def __init__(self, path: Path, layer: str, fmt: str = "text", from_end: bool = False) -> None:
        self.name = path.name
        self.layer, self.fmt = layer, fmt
        self.source = f"scout:{path.name}"
        self.tailer = Tailer(path)
        if from_end:  # added while running: only new lines, not the file's whole history
            with contextlib.suppress(OSError):
                self.tailer.pos = path.stat().st_size

    def poll(self) -> list[dict[str, Any]]:
        events = []
        for line in self.tailer.read_new_lines():
            src_ip = user = ts = None
            if self.fmt == "jsonl":
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    rec = None
                if isinstance(rec, dict):
                    src_ip = next((str(rec[k]) for k in ("src_ip", "ip", "client_ip", "remote_addr") if rec.get(k)), None)
                    user = next((str(rec[k]) for k in ("user", "username", "account") if rec.get(k)), None)
                    ts = rec.get("ts") or rec.get("timestamp")
            if src_ip is None and (m := IPV4.search(line)):
                src_ip = m.group(0)
            if user is None and (m := USER.search(line)):
                user = m.group(1)
            events.append(make_event(self.layer, self.source, line[:2000], src_ip=src_ip, user=user,
                                     ts=ts if isinstance(ts, str) else None))
        return events


def discovered_sources() -> list[Source]:
    from scout import sources as scout_sources

    return [DiscoveredLogSource(Path(s["path"]), s["layer"], s.get("format", "text")) for s in scout_sources.load()]


def default_sources(logs_dir: Path, heartbeat_interval: float = 10.0) -> list[Source]:
    return [*(JsonLogSource(logs_dir / name) for name in SOURCE_MAP), *discovered_sources(),
            HeartbeatSource(heartbeat_interval)]


class Collector:
    def __init__(self, core_url: str, logs_dir: Path,
                 flush_interval: float = 1.0, heartbeat_interval: float = 10.0,
                 sources: list[Source] | None = None):
        self.core_url = core_url.rstrip("/")
        self.logs_dir = logs_dir
        self.flush_interval = flush_interval
        self.heartbeat_interval = heartbeat_interval
        self.watch_sources = sources is None  # default set: also pick up newly approved log files
        self.sources = sources if sources is not None else default_sources(logs_dir, heartbeat_interval)
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
        added: list[Source] = [DiscoveredLogSource(Path(s["path"]), s["layer"], s.get("format", "text"),
                                                   from_end=self._tail_from_end)
                               for s in scout_sources.load() if str(Path(s["path"])) not in tailed]
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
            return True
        batch = self.pending
        try:
            resp = requests.post(f"{self.core_url}/events", json=batch, timeout=3)
            resp.raise_for_status()
            body = {}
            try:
                body = resp.json()
            except Exception:
                pass
            print(f"[collector] sent {len(batch)} events -> core "
                  f"(risk_index={body.get('risk_index', '?')})", flush=True)
            self.pending = []
            return True
        except Exception as exc:
            print(f"[collector] core unreachable ({exc.__class__.__name__}); "
                  f"buffering {len(batch)} events, will retry", flush=True)
            return False

    def run(self) -> None:
        print(f"[collector] tailing {self.logs_dir} -> {self.core_url}/events "
              f"(flush {self.flush_interval}s, heartbeat {self.heartbeat_interval}s)",
              flush=True)
        while True:
            self.collect()
            self.flush()
            time.sleep(self.flush_interval)


def main() -> None:
    ap = argparse.ArgumentParser(description="CactAI log collector")
    ap.add_argument("--core", default=os.environ.get("CACTAI_CORE_URL",
                                                      "http://127.0.0.1:8000"))
    ap.add_argument("--logs", default=str(paths.logs_dir()))
    ap.add_argument("--flush-interval", type=float, default=1.0)
    ap.add_argument("--heartbeat-interval", type=float, default=10.0)
    args = ap.parse_args()

    logs_dir = Path(args.logs)
    logs_dir.mkdir(parents=True, exist_ok=True)
    Collector(args.core, logs_dir, args.flush_interval,
              args.heartbeat_interval).run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[collector] stopped.")
