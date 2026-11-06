"""The shared fingerprint list: files known to be malware, by their SHA-256 or MD5, for every machine.

An antivirus is only as good as its list of known-bad files, and that list goes stale in weeks. This
keeps one list on the panel that every agent fetches (GET /fleet/signatures, about every 30 minutes,
with a copy kept on the machine for when the panel cannot be reached). Fingerprints come from:

* ``quarantine``: a file a person locked away on any machine (or on the panel). Its fingerprint joins
  the list, so the same file is flagged on every other machine at its next check. Paid antivirus calls
  this cloud reputation; here it stays inside the customer's own fleet.
* ``import``: a list the SentrAI team loads by CLI (``sentrai signatures import FILE``). It reads a
  plain list (one fingerprint per line, ``#`` comments), a CSV export that has a SHA-256 column (as
  MalwareBazaar's), and ClamAV's hash formats (``.hdb`` / ``.hsb``: ``hash:size:name``). Only the
  format is read here; no ClamAV code is used.
* ``operator``: fingerprints added one by one (``sentrai signatures add HASH --name N``).
* the system profile's older ``threat_scan.known_bad_sha256`` list, read as before.

Only fingerprints and short names are kept and sent, never file contents. Standard library only.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Iterable

MAX_ENTRIES = 200_000
NAME_LEN = 80
HEX = re.compile(r"^[0-9a-f]+$")


class SignatureError(Exception):
    pass


def kind_of(h: str) -> str | None:
    h = h.strip().lower()
    if not HEX.match(h):
        return None
    return {64: "sha256", 32: "md5"}.get(len(h))


def _clean_name(name: Any) -> str:
    return re.sub(r"[^\w .:/+\-()]", "", str(name or ""))[:NAME_LEN].strip()


def parse(text: str) -> list[tuple[str, str]]:
    """(fingerprint, name) pairs from a plain list, a CSV export or a ClamAV .hdb/.hsb file."""
    out: list[tuple[str, str]] = []
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    if not lines:
        return out
    head = lines[0].lower()
    if "sha256" in head and ("," in head or "\t" in head):  # a CSV export with a header row
        dialect = "excel-tab" if "\t" in head and "," not in head else "excel"
        rows = csv.reader(io.StringIO("\n".join(lines)), dialect=dialect, skipinitialspace=True)
        header = [c.strip().strip('"').lower() for c in next(rows)]
        hcol = next((i for i, c in enumerate(header) if "sha256" in c), None)
        ncol = next((i for i, c in enumerate(header) if c in ("signature", "malware", "name", "file_name")), None)
        for row in rows:
            if hcol is None or len(row) <= hcol:
                continue
            h = row[hcol].strip().strip('"').lower()
            if kind_of(h):
                out.append((h, _clean_name(row[ncol]) if ncol is not None and len(row) > ncol else ""))
        return out
    for ln in lines:
        ln = ln.strip()
        if ":" in ln:  # ClamAV: HashString:FileSize:MalwareName[:Flevel]
            parts = ln.split(":")
            if kind_of(parts[0]):
                out.append((parts[0].lower(), _clean_name(parts[2] if len(parts) > 2 else "")))
                continue
        tokens = re.split(r"[\s,;]+", ln, maxsplit=1)
        if kind_of(tokens[0].strip('"')):
            out.append((tokens[0].strip('"').lower(), _clean_name(tokens[1] if len(tokens) > 1 else "")))
    return out


class Signatures:
    """The panel's list, in signatures.json next to the database."""

    def __init__(self, path: Path, clock=time.time) -> None:
        self.path = path
        self.clock = clock
        self.lock = threading.Lock()
        self._items: dict[str, dict[str, Any]] = {}
        self.version = 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self._items = {h: v for h, v in (data.get("items") or {}).items() if kind_of(h) and isinstance(v, dict)}
            self.version = int(data.get("version") or 0)
        except (OSError, ValueError, AttributeError):
            pass

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"version": self.version, "items": self._items}, f)
        os.replace(tmp, self.path)

    def add(self, pairs: Iterable[tuple[str, str]], source: str, by: str) -> dict[str, int]:
        """Adds new fingerprints. Returns how many were added, already known and refused."""
        added = known = bad = 0
        now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(self.clock()))
        with self.lock:
            for h, name in pairs:
                h = str(h).strip().lower()
                if not kind_of(h):
                    bad += 1
                    continue
                if h in self._items:
                    known += 1
                    continue
                if len(self._items) >= MAX_ENTRIES:
                    raise SignatureError(f"the list is full ({MAX_ENTRIES} fingerprints); remove a source first")
                self._items[h] = {"name": _clean_name(name), "source": source[:60], "by": by[:64], "at": now}
                added += 1
            if added:
                self.version += 1
                self._save()
        return {"added": added, "known": known, "refused": bad}

    def remove(self, hashes: Iterable[str] = (), source: str | None = None) -> int:
        """Removes fingerprints by value, or every one from a source (``import:feed.csv``)."""
        with self.lock:
            drop = {h.strip().lower() for h in hashes}
            gone = [h for h, v in self._items.items() if h in drop or (source and v.get("source") == source)]
            for h in gone:
                del self._items[h]
            if gone:
                self.version += 1
                self._save()
        return len(gone)

    def lookup(self, h: str) -> dict[str, Any] | None:
        with self.lock:
            v = self._items.get(h.strip().lower())
            return dict(v) if v else None

    def hashes(self, extra: Iterable[str] = ()) -> dict[str, list[str]]:
        """What agents fetch: the fingerprints by kind (names stay on the panel)."""
        with self.lock:
            keys = list(self._items)
        keys += [h.strip().lower() for h in extra if isinstance(h, str) and kind_of(h)]
        uniq = sorted(set(keys))
        return {"sha256": [h for h in uniq if len(h) == 64], "md5": [h for h in uniq if len(h) == 32]}

    def summary(self, recent: int = 20) -> dict[str, Any]:
        with self.lock:
            items = dict(self._items)
        by_source: dict[str, int] = {}
        for v in items.values():
            src = str(v.get("source") or "?")
            by_source[src] = by_source.get(src, 0) + 1
        latest = sorted(items.items(), key=lambda kv: kv[1].get("at") or "", reverse=True)[:recent]
        return {"version": self.version, "count": len(items), "by_source": by_source,
                "recent": [{"hash": h, **v} for h, v in latest]}


# ------------------------------------------------------------------ the agent's copy
def save_copy(path: Path, data: dict[str, Any]) -> None:
    """The agent keeps the last list it fetched, so its checks work while the panel is unreachable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps({"version": data.get("version"), "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                               "sha256": data.get("sha256") or [], "md5": data.get("md5") or []}), encoding="utf-8")
    os.replace(tmp, path)


def load_copy(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}
