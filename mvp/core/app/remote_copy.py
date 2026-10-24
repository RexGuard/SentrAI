"""Off-box copy: every audit record and every sealed log line goes to a SentrAI witness.

The witness (``mvp/witness/witness.py``) runs on another machine and can only add records; the
token the core holds cannot change, delete or even read them back. So deleting or rebuilding the
audit database here, or editing a log after the collector read it, leaves the witness's copy as
it was, and the comparison below shows exactly what changed:

    python -m app.remote_copy compare --read-token-file /path/to/read.token

The core sends as things happen: an audit append wakes the sender at once, and log lines go out
in the same moment they are checked. If the witness refuses a record because it differs from the
copy it already holds, the local record was rebuilt: that becomes a ``log_tampering`` incident.
"""

from __future__ import annotations

import argparse
import re
import socket
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any

import httpx

from .audit import AuditLog
from .integrity import integrity_event

BATCH = 500
LINE_BACKLOG = 100_000  # lines held while the witness is unreachable; the oldest go first
UNREACHABLE_NOTE_S = 300.0  # how long the witness may be unreachable before the audit says so


def _safe(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)[:60] or "host"


def audit_stream(audit: AuditLog, host: str) -> str | None:
    """The witness stream for this chain: host plus the first record's hash, so a chain that was
    archived and restarted (or replaced) gets a stream of its own instead of overwriting one."""
    first = audit.records_after(0, 1)
    return f"audit-{_safe(host)}-{first[0]['hash'][:12]}" if first else None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class RemoteCopy:
    def __init__(self, audit: AuditLog, url: str, token: str, ca: str = "", host: str | None = None,
                 timeout_s: float = 5.0) -> None:
        self.audit = audit
        self.url = url.rstrip("/")
        self.host = host or socket.gethostname() or "sentrai-core"
        self.http = httpx.Client(timeout=timeout_s, headers={"Authorization": f"Bearer {token}"},
                                 verify=ca or True)
        self.problems: list[dict[str, Any]] = []  # integrity events for the core to ingest
        self.notes: list[tuple[str, dict[str, Any]]] = []  # (audit type, data) for the core to record
        self._lines: deque[dict[str, Any]] = deque(maxlen=LINE_BACKLOG)
        self._lines_dropped = 0
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sent: dict[str, int] = {}  # audit stream -> newest seq the witness holds
        self._refused: set[str] = set()  # audit streams the witness refused: nothing more goes there
        self._lock = threading.Lock()
        self._down_since: float | None = None
        self._down_noted = False
        self.status: dict[str, Any] = {"url": self.url, "ok": None, "audit_seq": 0, "lines_sent": 0,
                                       "last_sent_at": None, "error": None}
        audit.listeners.append(self._wake.set)

    # ------------------------------------------------------------------ input
    def add_line(self, event: dict[str, Any]) -> None:
        """A log event a collector sealed (it has ``chain``); sent with the next wake-up."""
        if isinstance(event.get("chain"), dict):
            with self._lock:
                if len(self._lines) == self._lines.maxlen:
                    self._lines_dropped += 1
                self._lines.append(event)
            self._wake.set()

    # ------------------------------------------------------------------ loop
    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="remote-copy", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self.http.close()

    def _run(self) -> None:
        backoff = 0.5
        while not self._stop.is_set():
            self._wake.wait(timeout=1.0)
            self._wake.clear()
            if self.flush():
                backoff = 0.5
            else:
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)

    def flush(self) -> bool:
        """Sends everything waiting. False when the witness could not be reached."""
        try:
            self._send_audit()
            self._send_lines()
        except httpx.HTTPError as e:
            self._down(f"{type(e).__name__}: {e}")
            return False
        self._up()
        return True

    # ------------------------------------------------------------------ sending
    def _post(self, stream: str, items: list[dict[str, Any]]) -> httpx.Response:
        r = self.http.post(f"{self.url}/append", json={"stream": stream, "items": items})
        if r.status_code not in (200, 409):
            raise httpx.HTTPStatusError(f"witness answered {r.status_code}: {r.text[:200]}", request=r.request, response=r)
        return r

    def _send_audit(self) -> None:
        stream = audit_stream(self.audit, self.host)
        if stream is None or stream in self._refused:
            return
        if stream not in self._sent:
            r = self.http.get(f"{self.url}/head", params={"stream": stream})
            r.raise_for_status()
            self._sent[stream] = int(r.json()["seq"])
        while batch := self.audit.records_after(self._sent[stream], BATCH):
            r = self._post(stream, batch)
            body = r.json()
            if r.status_code == 409:
                self._refused.add(stream)
                self._sent[stream] = int(body.get("seq") or 0)
                self.problems.append(integrity_event(
                    f"remote copy refused: {body.get('error')}. The record on this server was changed or rebuilt "
                    f"after the witness got it; compare with: python -m app.remote_copy compare"))
                return
            self._sent[stream] = int(body["seq"])
            self.status.update(audit_seq=self._sent[stream], last_sent_at=_now())

    def _send_lines(self) -> None:
        while True:
            with self._lock:
                if not self._lines:
                    return
                batch = [self._lines.popleft() for _ in range(min(BATCH, len(self._lines)))]
            by_stream: dict[str, list[dict[str, Any]]] = {}
            for ev in batch:
                by_stream.setdefault(f"lines-{_safe(str(ev['chain'].get('stream') or 'unknown'))}", []).append(ev)
            try:
                for stream, items in by_stream.items():
                    if self._post(stream, items).status_code == 409 and len(items) > 1:
                        # One line was refused (the core's own chain check already raised it):
                        # send the rest one by one so the lines after it are not lost.
                        for item in items:
                            self._post(stream, [item])
            except httpx.HTTPError:
                with self._lock:  # put them back, in order, for the next try
                    self._lines.extendleft(reversed(batch))
                raise
            self.status["lines_sent"] += len(batch)
            self.status["last_sent_at"] = _now()

    # ------------------------------------------------------------------ health
    def _down(self, error: str) -> None:
        self.status.update(ok=False, error=error)
        now = time.monotonic()
        if self._down_since is None:
            self._down_since = now
        if not self._down_noted and now - self._down_since >= UNREACHABLE_NOTE_S:
            self._down_noted = True
            self.notes.append(("remote_copy_unreachable", {"url": self.url, "error": error,
                                                           "lines_waiting": len(self._lines)}))

    def _up(self) -> None:
        if self._down_noted:
            self.notes.append(("remote_copy_restored", {"url": self.url, "lines_dropped": self._lines_dropped}))
        self._down_since, self._down_noted = None, False
        self.status.update(ok=True, error=None, lines_waiting=len(self._lines), lines_dropped=self._lines_dropped)

    def take(self) -> tuple[list[dict[str, Any]], list[tuple[str, dict[str, Any]]]]:
        """Problems and notes gathered since the last call (the core ingests and records them)."""
        problems, self.problems = self.problems, []
        notes, self.notes = self.notes, []
        return problems, notes


def from_settings(audit: AuditLog, settings: Any) -> RemoteCopy | None:
    if not settings.remote_copy_url:
        return None
    return RemoteCopy(audit, settings.remote_copy_url, settings.remote_copy_token, settings.remote_copy_ca)


# ---------------------------------------------------------------------- compare
def compare(audit: AuditLog, url: str, read_token: str, stream: str | None = None, ca: str = "",
            host: str | None = None) -> tuple[bool, list[str]]:
    """Checks the chain on this server against the witness's copy. (same, plain-language lines)."""
    stream = stream or audit_stream(audit, host or socket.gethostname() or "sentrai-core")
    if stream is None:
        return False, ["the audit record here is empty: it was deleted or reset. Name the witness's stream with "
                       "--stream to see what it held"]
    local = {r["seq"]: r for r in audit.records()}
    remote: dict[int, dict[str, Any]] = {}
    with httpx.Client(timeout=30, headers={"Authorization": f"Bearer {read_token}"}, verify=ca or True) as http:
        start = 1
        while True:
            r = http.get(f"{url.rstrip('/')}/records", params={"stream": stream, "from": start})
            r.raise_for_status()
            page = r.json()
            for rec in page:
                remote[int(rec["seq"])] = rec
            if not page or len(page) < 5000:
                break
            start = int(page[-1]["seq"]) + 1
    if not remote:
        return False, [f"the witness has no stream {stream}: check the URL, or this chain was never sent"]
    out: list[str] = []
    for seq, rec in sorted(remote.items()):
        mine = local.get(seq)
        if mine is None:
            out.append(f"record #{seq} ({rec.get('type')}, {rec.get('ts')}) is missing here")
        elif mine["hash"] != rec["hash"]:
            what = "its content" if mine["data"] != rec["data"] else "its hash"
            out.append(f"record #{seq} ({rec.get('type')}, {rec.get('ts')}) differs: {what} changed here")
    if not out:
        top = max(remote)
        newer = len([q for q in local if q > top])
        return True, [f"records 1 to {top} match the witness's copy" + (f"; {newer} newer not sent yet" if newer else "")]
    return False, out


def main(argv: list[str] | None = None) -> int:
    from pathlib import Path

    from .config import Settings, _secret

    ap = argparse.ArgumentParser(prog="python -m app.remote_copy", description="Compare with the off-box copy.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare", help="check the audit record here against the witness's copy")
    c.add_argument("--url", help="witness URL (default: CACTAI_REMOTE_COPY_URL)")
    c.add_argument("--read-token-file", type=Path, help="the witness's read token (default: CACTAI_WITNESS_READ_TOKEN)")
    c.add_argument("--stream", help="witness stream (default: this host's current chain)")
    c.add_argument("--db", type=Path)
    args = ap.parse_args(argv)
    s = Settings()
    url = args.url or s.remote_copy_url
    token = (args.read_token_file.read_text(encoding="utf-8").strip() if args.read_token_file
             else _secret("CACTAI_WITNESS_READ_TOKEN"))
    if not url or not token:
        print("needs the witness URL and its read token (--url, --read-token-file)", file=sys.stderr)
        return 2
    audit = AuditLog(args.db or s.db_path)
    try:
        same, lines = compare(audit, url, token, args.stream, s.remote_copy_ca)
    finally:
        audit.close()
    print(("MATCHES: " if same else "DIFFERS:\n  ") + "\n  ".join(lines))
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main())
