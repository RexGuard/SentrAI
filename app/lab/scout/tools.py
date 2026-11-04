"""Read-only folder tools shared by the trail recorder (humans) and the Scout agent (Claude).

Everything is confined to the allowed roots and nothing is ever written, moved or deleted.
File previews are capped and have obvious secrets masked before anyone (or any model) sees them.
"""
from __future__ import annotations

import fnmatch
import os
import re
import time
from pathlib import Path

MAX_ENTRIES = 200
MAX_PEEK_LINES = 40
MAX_LINE_CHARS = 300
MAX_FIND_RESULTS = 100
MAX_FIND_VISITED = 20000

SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)(\s*[=:]\s*(?:bearer\s+)?)(\S+)")


def redact(line: str) -> str:
    return SECRET.sub(lambda m: f"{m.group(1)}{m.group(2)}[hidden]", line)


class SafeFS:
    def __init__(self, roots: list[str | Path]) -> None:
        self.roots = [Path(r).resolve() for r in roots]
        if not self.roots:
            raise ValueError("Scout needs at least one folder it is allowed to look in")

    def resolve(self, path: str) -> Path:
        p = Path(path).expanduser()
        p = (p if p.is_absolute() else self.roots[0] / p).resolve()
        if not any(p == r or r in p.parents for r in self.roots):
            raise PermissionError(f"{path} is outside the folders Scout may look in")
        return p

    def list_dir(self, path: str) -> str:
        p = self.resolve(path)
        if not p.is_dir():
            return f"{p} is not a folder"
        rows = []
        try:
            entries = sorted(p.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower()))
        except PermissionError:
            return f"No permission to open {p}"
        for e in entries[:MAX_ENTRIES]:
            try:
                st = e.stat()
            except OSError:
                continue
            if e.is_dir():
                rows.append(f"[dir]  {e.name}/")
            else:
                age = _age(st.st_mtime)
                rows.append(f"[file] {e.name}  {_size(st.st_size)}  modified {age} ago")
        more = f"\n... {len(entries) - MAX_ENTRIES} more not shown" if len(entries) > MAX_ENTRIES else ""
        return f"{p}\n" + ("\n".join(rows) or "(empty)") + more

    def peek_file(self, path: str, lines: int = 20, tail: bool = True) -> str:
        """First or last few lines of a text file (the end is where new log lines are)."""
        p = self.resolve(path)
        if not p.is_file():
            return f"{p} is not a file"
        n = max(1, min(int(lines), MAX_PEEK_LINES))
        try:
            with open(p, "rb") as fh:
                head = fh.read(2048)
                if b"\x00" in head:
                    return f"{p} looks like a binary file (e.g. Windows .evtx); it cannot be previewed as text"
                if tail:
                    fh.seek(0, os.SEEK_END)
                    size = fh.tell()
                    fh.seek(max(0, size - 64 * 1024))
                data = fh.read(64 * 1024).decode("utf-8", errors="replace")
        except PermissionError:
            return f"No permission to read {p} (it may need administrator rights)"
        text = data.splitlines()
        chosen = text[-n:] if tail else text[:n]
        body = "\n".join(redact(t[:MAX_LINE_CHARS]) for t in chosen)
        return f"{p} ({'last' if tail else 'first'} {len(chosen)} lines)\n{body}"

    def find_files(self, pattern: str, under: str | None = None) -> str:
        """Files whose name matches a wildcard pattern such as *.log or *auth*."""
        start = self.resolve(under) if under else None
        tops = [start] if start else self.roots
        hits: list[str] = []
        visited = 0
        for top in tops:
            for dirpath, dirnames, filenames in os.walk(top, onerror=lambda e: None):
                visited += len(filenames) + len(dirnames)
                for f in filenames:
                    if fnmatch.fnmatch(f.lower(), pattern.lower()):
                        hits.append(str(Path(dirpath) / f))
                        if len(hits) >= MAX_FIND_RESULTS:
                            return "\n".join(hits) + "\n(stopped at the result limit)"
                if visited > MAX_FIND_VISITED:
                    return "\n".join(hits) + "\n(stopped: too many files; search a smaller folder)"
        return "\n".join(hits) or f"No files named {pattern}"


def _size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.0f} TB"


def _age(mtime: float) -> str:
    s = max(0, time.time() - mtime)
    for unit, secs in (("d", 86400), ("h", 3600), ("min", 60)):
        if s >= secs:
            return f"{s // secs:.0f} {unit}"
    return f"{s:.0f} s"
