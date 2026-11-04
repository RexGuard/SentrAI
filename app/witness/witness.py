"""SentrAI witness: an off-box copy that can be added to but never changed.

Run it on a second machine (or anywhere the watched server's root cannot log in). The core sends
it every audit record and every log line its collectors read, as they happen. The witness checks
each one continues the chain before it and appends it to a file; it has no way to edit or delete
anything, and the token the core holds can only add. Deleting the audit database, or rebuilding it,
on the watched server then leaves the witness's copy as it was.

    python3 witness.py serve --data /var/lib/sentrai-witness --port 8600
    python3 witness.py token            # prints a new random token

Tokens are read from files so they never show up in ``ps``:
  --append-token-file  the core's token: add records, read the newest record of a stream
  --read-token-file    an auditor's token: read records (the core does not get this one)

Streams (one JSONL file each, under --data):
  audit   ``audit-<host>-<first hash>``: the core's audit records (CONTRACT.md "Audit chain").
          Records must arrive in order with no gaps.
  lines   ``lines-<collector stream>``: raw log events sealed by a collector (CONTRACT.md "Line
          chain"). A gap is stored as a note, since the core has already raised it as tampering.
Something that does not fit is refused with 409 and written to ``conflicts.jsonl``.

Standard library only (Python 3.10+), so it runs on a bare server with no install step.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

GENESIS = "0" * 64
STREAM = re.compile(r"^(audit|lines)-[A-Za-z0-9._-]{1,120}$")
LINE_FIELDS = ("event_id", "timestamp", "host", "layer", "source", "raw")  # the collector's
MAX_BODY = 8 * 1024 * 1024
MAX_READ = 5000


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def audit_hash(prev: str, rec: dict[str, Any]) -> str:  # core/app/audit.py compute_hash
    body = canonical({"seq": rec.get("seq"), "ts": rec.get("ts"), "type": rec.get("type"), "data": rec.get("data")})
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


def line_hash(prev: str, event: dict[str, Any]) -> str:  # lab/collector/collector.py chain_hash
    body = json.dumps([event.get(k) for k in LINE_FIELDS], separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


def seal(kind: str, item: dict[str, Any]) -> tuple[int, str, str, bool]:
    """(seq, prev, hash, hash checks out) of one audit record or sealed line."""
    if kind == "audit":
        prev, h = str(item.get("prev_hash") or ""), str(item.get("hash") or "")
        return int(item.get("seq") or 0), prev, h, audit_hash(prev, item) == h
    c = item.get("chain") if isinstance(item.get("chain"), dict) else {}
    prev, h = str(c.get("prev") or ""), str(c.get("hash") or "")
    return int(c.get("seq") or 0), prev, h, line_hash(prev, item) == h


class Conflict(Exception):
    pass


class Store:
    """Append-only JSONL per stream, plus the newest (seq, hash) of each in memory."""

    def __init__(self, data: Path) -> None:
        self.data = Path(data)
        self.data.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._heads: dict[str, tuple[int, str]] = {}
        self._recent: dict[str, dict[int, str]] = {}  # lines: recent seq -> hash, for replays
        for f in sorted(self.data.glob("*.jsonl")):
            if STREAM.match(f.stem):
                for row in self._rows(f.stem):
                    if "seq" in row:
                        self._remember(f.stem, row["seq"], row["hash"])

    def path(self, stream: str) -> Path:
        return self.data / f"{stream}.jsonl"

    def _rows(self, stream: str):
        try:
            with open(self.path(stream), encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        yield json.loads(line)
        except FileNotFoundError:
            return

    def _remember(self, stream: str, seq: int, h: str) -> None:
        self._heads[stream] = (seq, h)
        if stream.startswith("lines-"):
            recent = self._recent.setdefault(stream, {})
            recent[seq] = h
            if len(recent) > 5000:
                for k in sorted(recent)[:1000]:
                    del recent[k]

    def _write(self, name: str, rows: list[dict[str, Any]]) -> None:
        # O_APPEND: every write lands at the end, whatever else has the file open.
        fd = os.open(str(self.data / name), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o640)
        try:
            os.write(fd, "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    def head(self, stream: str) -> dict[str, Any]:
        seq, h = self._heads.get(stream, (0, GENESIS))
        return {"stream": stream, "seq": seq, "hash": h}

    def append(self, stream: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        kind = stream.split("-", 1)[0]
        with self._lock:
            rows, added = [], 0
            seq0, head = self._heads.get(stream, (0, GENESIS))
            new_heads: list[tuple[int, str]] = []
            known: dict[int, str] | None = None  # audit hashes already kept, read once if a retry comes in
            try:
                for item in items:
                    seq, prev, h, ok = seal(kind, item)
                    if not ok or seq < 1:
                        self._conflict(stream, f"record #{seq} does not match its own hash", item)
                    if kind == "lines" and self._recent.get(stream, {}).get(seq) == h:
                        continue  # sent again (a retry, or a collector replaying after a crash)
                    if kind == "audit" and seq <= seq0:
                        if known is None:
                            known = {r["seq"]: r["hash"] for r in self._rows(stream) if r.get("seq", 0) >= seq}
                        if known.get(seq) == h:
                            continue  # sent again
                        self._conflict(stream, f"record #{seq} differs from the copy kept here", item)
                    # A lines stream may start mid-chain (the core forwards from when it started).
                    if not ((prev == head and seq == seq0 + 1) or (kind == "lines" and seq0 == 0)):
                        if kind == "audit":
                            self._conflict(stream, f"record #{seq} does not follow #{seq0} kept here", item)
                        rows.append({"note": f"does not follow: #{seq} after #{seq0}", "after": seq0})
                    rows.append({"seq": seq, "hash": h, "item": item})
                    new_heads.append((seq, h))
                    seq0, head = seq, h
                    added += 1
            finally:  # what fitted before a refused record is kept
                if rows:
                    self._write(f"{stream}.jsonl", rows)
                    for s, h in new_heads:
                        self._remember(stream, s, h)
            return {**self.head(stream), "added": added}

    def _conflict(self, stream: str, why: str, item: dict[str, Any]) -> None:
        self._write("conflicts.jsonl", [{"stream": stream, "why": why, "item": item}])
        raise Conflict(why)

    def read(self, stream: str, start: int = 1, limit: int = MAX_READ) -> list[dict[str, Any]]:
        out = []
        for row in self._rows(stream):
            if row.get("seq", 0) >= start:
                out.append(row["item"])
                if len(out) >= limit:
                    break
        return out

    def streams(self) -> list[dict[str, Any]]:
        return [self.head(s) for s in sorted(self._heads)]


def make_handler(store: Store, append_token: str, read_token: str | None):
    class Handler(BaseHTTPRequestHandler):
        server_version = "sentrai-witness/1"

        def log_message(self, fmt: str, *args: Any) -> None:  # one line per refused request only
            pass

        def _send(self, code: int, body: dict[str, Any] | list[Any]) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _role(self) -> str | None:
            got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if got and hmac.compare_digest(got, append_token):
                return "append"
            if got and read_token and hmac.compare_digest(got, read_token):
                return "read"
            return None

        def _stream(self, q: dict[str, list[str]]) -> str | None:
            s = (q.get("stream") or [""])[0]
            return s if STREAM.match(s) else None

        def do_GET(self) -> None:
            u = urlparse(self.path)
            q = parse_qs(u.query)
            role = self._role()
            if u.path == "/health":
                return self._send(200, {"ok": True})
            if role is None:
                return self._send(401, {"error": "token required"})
            if u.path == "/head":
                stream = self._stream(q)
                return self._send(200, store.head(stream)) if stream else self._send(400, {"error": "bad stream"})
            if role != "read":  # the core's token cannot read the copy back
                return self._send(403, {"error": "this token can only add records"})
            if u.path == "/streams":
                return self._send(200, store.streams())
            if u.path == "/records":
                stream = self._stream(q)
                if not stream:
                    return self._send(400, {"error": "bad stream"})
                start = int((q.get("from") or ["1"])[0])
                limit = min(int((q.get("limit") or [str(MAX_READ)])[0]), MAX_READ)
                return self._send(200, store.read(stream, start, limit))
            return self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            u = urlparse(self.path)
            if self._role() != "append":
                return self._send(401, {"error": "append token required"})
            if u.path != "/append":
                return self._send(404, {"error": "not found"})
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return self._send(413, {"error": "body too large"})
            try:
                body = json.loads(self.rfile.read(n))
                stream, items = body["stream"], body["items"]
                assert STREAM.match(stream) and isinstance(items, list)
            except (ValueError, KeyError, TypeError, AssertionError):
                return self._send(400, {"error": "expected {stream, items}"})
            try:
                return self._send(200, store.append(stream, items))
            except Conflict as e:
                return self._send(409, {"error": str(e), **store.head(stream)})

        # Nothing can change or remove what is stored.
        def do_PUT(self) -> None:
            self._send(405, {"error": "the witness only adds"})

        do_DELETE = do_PATCH = do_PUT

    return Handler


def _token(path: Path | None, env: str) -> str | None:
    if path:
        return Path(path).read_text(encoding="utf-8").strip() or None
    return os.environ.get(env, "").strip() or None


def make_server(data: Path, append_token: str, read_token: str | None, bind: str = "0.0.0.0", port: int = 8600):
    return ThreadingHTTPServer((bind, port), make_handler(Store(data), append_token, read_token))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="witness.py", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve", help="run the witness")
    s.add_argument("--data", type=Path, default=Path("/var/lib/sentrai-witness"))
    s.add_argument("--bind", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8600)
    s.add_argument("--append-token-file", type=Path, help="default: WITNESS_APPEND_TOKEN")
    s.add_argument("--read-token-file", type=Path, help="default: WITNESS_READ_TOKEN")
    s.add_argument("--tls-cert", type=Path, help="serve HTTPS with this certificate (and --tls-key)")
    s.add_argument("--tls-key", type=Path)
    sub.add_parser("token", help="print a new random token")
    args = ap.parse_args(argv)
    if args.cmd == "token":
        print(secrets.token_urlsafe(32))
        return 0
    append = _token(args.append_token_file, "WITNESS_APPEND_TOKEN")
    if not append:
        print("an append token is required (--append-token-file or WITNESS_APPEND_TOKEN)", file=sys.stderr)
        return 2
    srv = make_server(args.data, append, _token(args.read_token_file, "WITNESS_READ_TOKEN"), args.bind, args.port)
    if args.tls_cert:
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(args.tls_cert), str(args.tls_key) if args.tls_key else None)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    scheme = "https" if args.tls_cert else "http"
    print(f"SentrAI witness on {scheme}://{args.bind}:{args.port}, keeping {args.data}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
