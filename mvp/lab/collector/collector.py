"""CactAI log collector.

Tails the target app's JSON-lines logs, normalizes each line into the shared
Event schema (see ``mvp/CONTRACT.md``), and batches them to core
``POST /events`` once per second. Retries on failure and emits a heartbeat
event every 10 seconds so Watchdog can tell the collector is alive.

Run:  python -m collector.collector           (from mvp/lab)
   or python collector/collector.py

Handles file creation (logs may not exist yet) and rotation/truncation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterable

import requests

# Allow running both as ``python -m collector.collector`` and as a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
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


def normalize(log_name: str, record: dict[str, Any]) -> dict[str, Any] | None:
    """Turn one raw log line into a contract Event dict.

    Returns None if the log file is unknown.
    """
    mapping = SOURCE_MAP.get(log_name)
    if mapping is None:
        return None
    layer, source = mapping
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": record.get("ts") or _now_iso(),
        "host": HOST,
        "layer": layer,
        "source": source,
        "src_ip": record.get("src_ip"),
        "user": record.get("user"),
        "raw": record.get("raw", ""),
        "asset_criticality": criticality_for(layer, record),
    }


def heartbeat_event() -> dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "timestamp": _now_iso(),
        "host": HOST,
        "layer": "os",
        "source": "heartbeat",
        "src_ip": None,
        "user": None,
        "raw": "collector heartbeat",
        "asset_criticality": 1.0,
    }


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


class Collector:
    def __init__(self, core_url: str, logs_dir: Path,
                 flush_interval: float = 1.0, heartbeat_interval: float = 10.0):
        self.core_url = core_url.rstrip("/")
        self.logs_dir = logs_dir
        self.flush_interval = flush_interval
        self.heartbeat_interval = heartbeat_interval
        self.tailers = {name: Tailer(logs_dir / name) for name in SOURCE_MAP}
        self.pending: list[dict] = []
        self._last_heartbeat = 0.0

    def collect(self) -> None:
        for name, tailer in self.tailers.items():
            for line in tailer.read_new_lines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event = normalize(name, record)
                if event is not None:
                    self.pending.append(event)

    def maybe_heartbeat(self) -> None:
        now = time.time()
        if now - self._last_heartbeat >= self.heartbeat_interval:
            self.pending.append(heartbeat_event())
            self._last_heartbeat = now

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
        # Prime heartbeat so the first one fires promptly after startup.
        self._last_heartbeat = time.time()
        while True:
            self.collect()
            self.maybe_heartbeat()
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
