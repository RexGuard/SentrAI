"""Use ClamAV too, when it is installed on the machine.

ClamAV (Cisco Talos) has millions of signatures, updated several times a day by its own freshclam.
SentrAI does not ship or copy any of it (ClamAV is GPL): when ``clamdscan`` or ``clamscan`` is on the
machine, a threat scan runs it as a separate program on the same folders and adds what it reports.

  SENTRAI_CLAMAV   auto (default: use it when found) | off | the path to clamscan or clamdscan

``clamdscan`` is preferred: it asks the running clamd service, which already has the signatures
loaded, so a scan takes seconds instead of the minute clamscan needs to load them. Standard library only.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Callable, Iterable

TIMEOUT_S = 3600
FOUND = re.compile(r"^(?P<path>.+?): (?P<name>\S.*?) FOUND$")

Runner = Callable[[list[str], float], tuple[int, str]]


def _run(cmd: list[str], timeout: float) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired) as e:
        return 2, f"{type(e).__name__}"


def find() -> str | None:
    """The ClamAV scanner to use, or None (not installed, or turned off)."""
    want = os.environ.get("SENTRAI_CLAMAV", "auto").strip()
    if want.lower() in ("off", "0", "no", "false"):
        return None
    if want and want.lower() != "auto":
        return want if Path(want).is_file() else None
    return shutil.which("clamdscan") or shutil.which("clamscan")


def scan(roots: Iterable[str], skip: Iterable[str] = (), run: Runner = _run, exe: str | None = None) -> dict[str, Any]:
    """{"engine": ..., "findings": [...]} or {"engine": None} when ClamAV is not there. Findings are in
    the threat scan's shape (``real_path`` included; the caller hides it)."""
    exe = exe or find()
    roots = [os.path.expanduser(r) for r in roots if r]
    if not exe or not roots:
        return {"engine": None, "findings": []}
    daemon = Path(exe).name.lower().startswith("clamdscan")
    cmd = [exe, "--no-summary", "--infected", "--stdout"]
    cmd += ["--multiscan", "--fdpass"] if daemon else ["-r"]
    if not daemon:
        for d in skip:
            cmd.append(f"--exclude-dir=^{re.escape(str(d))}")
    code, out = run(cmd + roots, TIMEOUT_S)
    if code not in (0, 1):  # 0 clean, 1 found something, 2 an error
        return {"engine": Path(exe).name, "findings": [], "error": f"ClamAV could not scan (exit {code})"}
    findings = []
    for line in out.splitlines():
        m = FOUND.match(line.strip())
        if not m:
            continue
        p = Path(m["path"])
        if any(str(p).startswith(str(d)) for d in skip):
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        name = m["name"][:80]
        findings.append({"real_path": str(p), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                         "key": "clamav", "kind": "known_malware", "severity": "critical",
                         "label": f"ClamAV: {name}", "line": None, "snippet": ""})
    return {"engine": Path(exe).name, "findings": findings}
