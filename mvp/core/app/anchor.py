"""Record fingerprints sent off the box, so a rebuilt audit chain can be proven fake.

The audit chain (audit.py) proves its own consistency, but someone with root on the server can
drop the guard triggers, edit records and recompute every hash. What they cannot do is recall
a message that already left the machine. So the core regularly sends the newest record's
number and hash ("the fingerprint") to the alert channels (Telegram, email), signed with a key
of its own:

    SENTRAI-FP v1 seq=1234 head=3fa9...e1 at=2026-10-02T10:00:00Z sig=8b12...

Anyone holding that line can later check the chain on disk still has that hash at that
record, which fails if any record up to it was changed or removed since:

    python -m app.anchor verify "SENTRAI-FP v1 seq=1234 head=... at=... sig=..."

The signature (HMAC-SHA256 with the anchor key) shows the line came from this SentrAI; the
key is ``anchor.key`` next to the audit database (mode 0600), or ``CACTAI_ANCHOR_KEY``.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLog, compute_hash, GENESIS_HASH

PREFIX = "SENTRAI-FP v1"
LINE = re.compile(r"SENTRAI-FP v1 seq=(\d+) head=([0-9a-f]{16,64}) at=(\S+)(?: sig=([0-9a-f]{32}))?")
MIN_PREFIX = 16  # a short fingerprint in an alert still pins the record (64 bits)


def key_path(db_path: Path) -> Path:
    return Path(db_path).parent / "anchor.key"


def load_key(db_path: Path, create: bool = True) -> bytes | None:
    """The signing key: CACTAI_ANCHOR_KEY, else anchor.key next to the database (made on first use)."""
    env = os.getenv("CACTAI_ANCHOR_KEY", "").strip()
    if env:
        return env.encode()
    path = key_path(db_path)
    try:
        return path.read_text(encoding="ascii").strip().encode()
    except FileNotFoundError:
        if not create:
            return None
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(key + "\n")
    return key.encode()


def _sig(key: bytes, seq: int, head: str, at: str) -> str:
    return hmac.new(key, f"{seq}|{head}|{at}".encode(), hashlib.sha256).hexdigest()[:32]


@dataclass
class Fingerprint:
    seq: int
    head: str
    at: str
    sig: str | None = None

    def line(self) -> str:
        return f"{PREFIX} seq={self.seq} head={self.head} at={self.at}" + (f" sig={self.sig}" if self.sig else "")

    def short(self) -> str:
        return f"#{self.seq} {self.head[:MIN_PREFIX]}"


def fingerprint(audit: AuditLog, key: bytes | None) -> Fingerprint:
    seq, head = audit.head()
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return Fingerprint(seq, head, at, _sig(key, seq, head, at) if key else None)


def parse(text: str) -> Fingerprint | None:
    m = LINE.search(text or "")
    if not m:
        return None
    return Fingerprint(int(m.group(1)), m.group(2), m.group(3), m.group(4))


def verify(audit: AuditLog, text: str, key: bytes | None = None) -> tuple[bool, str]:
    """Checks a fingerprint line against the chain on disk. (ok, plain-language reason)."""
    fp = parse(text)
    if fp is None:
        return False, "not a SentrAI fingerprint line (it starts with 'SENTRAI-FP v1')"
    if key is not None and fp.sig is not None and not hmac.compare_digest(_sig(key, fp.seq, fp.head, fp.at), fp.sig):
        return False, "the signature does not match: this line was not made by this SentrAI, or was altered"
    if fp.seq == 0:
        return True, "the fingerprint was taken before any record existed"
    prev, found = GENESIS_HASH, None
    for rec in audit.records():
        if rec["seq"] > fp.seq:
            break
        if rec["prev_hash"] != prev or compute_hash(prev, rec["seq"], rec["ts"], rec["type"], rec["data"]) != rec["hash"]:
            return False, f"the chain on disk is broken at record {rec['seq']}, before the fingerprinted record {fp.seq}"
        prev = rec["hash"]
        if rec["seq"] == fp.seq:
            found = rec
    if found is None:
        return False, f"record {fp.seq} is missing: the chain on disk is shorter than when the fingerprint was sent"
    if not found["hash"].startswith(fp.head):
        return False, (f"record {fp.seq} has a different hash now: records up to it were changed or removed "
                       f"and the chain was rebuilt since {fp.at}")
    signed = " and the signature matches" if key is not None and fp.sig else ""
    return True, f"records 1 to {fp.seq} are exactly as they were at {fp.at}{signed}"


def main(argv: list[str] | None = None) -> int:
    from .config import Settings

    ap = argparse.ArgumentParser(prog="python -m app.anchor", description="Check or print audit fingerprints.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check a fingerprint line (from Telegram or email) against the chain on disk")
    v.add_argument("line", help='the whole line, e.g. "SENTRAI-FP v1 seq=12 head=... at=... sig=..."')
    sub.add_parser("show", help="print the current fingerprint")
    ap.add_argument("--db", type=Path, help="audit database (default: CACTAI_DB / the core's default)")
    args = ap.parse_args(argv)
    db = args.db or Settings().db_path
    if not Path(db).exists():
        print(f"no audit database at {db}", file=sys.stderr)
        return 2
    audit = AuditLog(Path(db))
    try:
        if args.cmd == "show":
            print(fingerprint(audit, load_key(db)).line())
            return 0
        ok, why = verify(audit, args.line, load_key(db, create=False))
        print(("OK: " if ok else "TAMPERED: ") + why)
        return 0 if ok else 1
    finally:
        audit.close()


if __name__ == "__main__":
    raise SystemExit(main())
