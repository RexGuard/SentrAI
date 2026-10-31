"""Dependency scan: which installed packages have known vulnerabilities, and which update fixes them.

It reads what is installed, asks OSV (osv.dev, the open vulnerability database behind pip-audit and
npm audit) about each package and version, and returns one finding per vulnerable package with the
lowest version that fixes all its known vulnerabilities. It only reads; ``apply_update`` and
``rollback`` change things, and only when a person pressed Update for one finding.

What it reads:

* ``python``   SentrAI's own Python environment, and every virtualenv (a folder with pyvenv.cfg)
               under the chosen folders. Packages come from their *.dist-info folders.
* ``npm``      every package-lock.json under the chosen folders (not inside node_modules).
* ``pinned``   ``name==version`` lines in requirements*.txt under the chosen folders.
* ``os``       Debian and Ubuntu packages (/var/lib/dpkg/status), unless SENTRAI_DEP_OS=off.

Only the package names and versions go to OSV (SENTRAI_OSV_URL moves it). Folders come from
``dep_scan.paths`` in the system profile, or SENTRAI_DEP_PATHS (OS path separator).

Updates. A finding is ``safe`` to update with one press when the fix keeps the same major version
(for 0.x, the same minor) and SentrAI can undo it: a virtualenv's package (pip installs the fixed
version; undo reinstalls the old one) or an npm project's direct dependency (package.json and
package-lock.json are copied first; undo puts them back and runs npm ci). Everything else is
``manual`` with the step to take: SentrAI's own environment (bump the pin in SentrAI, or the next
sentrai-update undoes it), pinned files, npm packages pulled in by another one, OS packages (apt
cannot reliably go back) and fixes that cross a major version.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import sysconfig
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .procscan import _homes, hide_home, mask

OSV_URL = "https://api.osv.dev"
BATCH = 500             # OSV's querybatch takes up to 1000 queries
MAX_DETAILS = 400       # vulnerability records fetched per scan (each one is a request)
MAX_SOURCES = 50
MAX_FINDINGS = 300
WALK_DEPTH = 4
SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".hg", ".svn", ".tox", ".cache"}
SEVERITY = ("critical", "high", "medium", "low")
UPDATE_TIMEOUT_S = 600

# What may reach pip or npm: package names and versions as their registries allow, nothing else.
NAME = {"PyPI": re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
        "npm": re.compile(r"^(@[a-z0-9][a-z0-9._~-]{0,63}/)?[a-z0-9][a-z0-9._~-]{0,127}$")}
VERSION = re.compile(r"^[0-9][0-9A-Za-z.+!_-]{0,63}$")

Fetch = Callable[[str, str, Any], Any]  # (method, path, body) -> parsed JSON
Run = Callable[..., Any]                # subprocess.run


def _iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts if ts is not None else time.time(), timezone.utc).isoformat(timespec="seconds")


def _id(*parts: Any) -> str:
    return hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:16]


# ------------------------------------------------------------------ versions

_PRE = re.compile(r"(a|b|c|rc|alpha|beta|pre|preview|dev)", re.I)


def vkey(v: str) -> tuple:
    """A sort key good enough for PyPI and npm versions: the release numbers, then pre < final < post."""
    v = str(v).strip().lower().lstrip("v")
    v = v.split("!", 1)[-1].split("+", 1)[0]
    m = re.match(r"(\d+(?:\.\d+)*)(.*)", v)
    if not m:
        return ((0,), -1, v)
    nums = tuple(int(x) for x in m.group(1).split("."))
    while len(nums) > 1 and nums[-1] == 0:
        nums = nums[:-1]
    rest = m.group(2).lstrip(".-_")
    tag = 0 if not rest else -1 if _PRE.match(rest) else 1
    return (nums, tag, rest)


def same_major(a: str, b: str) -> bool:
    """Whether going from a to b stays inside one major version (0.x: inside one minor)."""
    x, y = vkey(a)[0] + (0, 0), vkey(b)[0] + (0, 0)
    return x[0] == y[0] and (x[0] != 0 or x[1] == y[1])


# ------------------------------------------------------------------ inventory

def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _dist_packages(site: Path) -> list[tuple[str, str]]:
    out = {}
    for d in site.glob("*.dist-info"):
        name = version = None
        try:
            with open(d / "METADATA", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        break
                    if line.startswith("Name:"):
                        name = line[5:].strip()
                    elif line.startswith("Version:"):
                        version = line[8:].strip()
        except OSError:
            continue
        if name and version:
            out[_norm(name)] = (name, version)
    return sorted(out.values())


def _venv_parts(venv: Path) -> tuple[Path | None, Path | None]:
    """(site-packages, python) of one virtualenv."""
    sites = [venv / "Lib" / "site-packages", *sorted(venv.glob("lib/python*/site-packages"))]
    site = next((s for s in sites if s.is_dir()), None)
    exe = next((p for p in (venv / "Scripts" / "python.exe", venv / "bin" / "python") if p.exists()), None)
    return site, exe


def _npm_packages(lock: Path) -> tuple[list[tuple[str, str]], set[str]]:
    """(name, version) from a package-lock.json, and the names the project depends on directly."""
    data = json.loads(lock.read_text(encoding="utf-8"))
    pkgs = data.get("packages")
    found: set[tuple[str, str]] = set()
    if isinstance(pkgs, dict):  # lockfile v2 and v3
        root = pkgs.get("") or {}
        direct = set(root.get("dependencies") or {}) | set(root.get("devDependencies") or {}) \
            | set(root.get("optionalDependencies") or {})
        for key, p in pkgs.items():
            if "node_modules/" in key and isinstance(p, dict) and p.get("version") and not p.get("link"):
                found.add((key.rsplit("node_modules/", 1)[1], str(p["version"])))
    else:  # lockfile v1: the top level only
        deps = data.get("dependencies") or {}
        direct = set(deps)
        found = {(n, str(p["version"])) for n, p in deps.items() if isinstance(p, dict) and p.get("version")}
    return sorted(found), direct


PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][0-9A-Za-z.+!_-]*)\s*(?:;.*)?(?:#.*)?$")


def _pinned(req: Path) -> list[tuple[str, str]]:
    out = []
    for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
        m = PIN.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    out = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    except OSError:
        pass
    return out


def os_ecosystem(release: dict[str, str]) -> str | None:
    """OSV's name for this Linux release: Debian:12, Ubuntu:22.04:LTS; None for anything else."""
    vid = release.get("VERSION_ID", "")
    if release.get("ID") == "debian" and vid:
        return f"Debian:{vid.split('.')[0]}"
    if release.get("ID") == "ubuntu" and vid:
        return f"Ubuntu:{vid}" + (":LTS" if "LTS" in release.get("VERSION", "") else "")
    return None


def _dpkg_packages(status: Path) -> list[tuple[str, str, list[str]]]:
    """(source package, source version, its installed binary packages): OSV knows Debian and
    Ubuntu by source package."""
    groups: dict[tuple[str, str], list[str]] = {}
    for para in status.read_text(encoding="utf-8", errors="replace").split("\n\n"):
        f: dict[str, str] = {}
        for line in para.splitlines():
            if line[:1] not in (" ", "\t") and ":" in line:
                k, _, v = line.partition(":")
                f[k] = v.strip()
        if not f.get("Package") or not f.get("Version") or "installed" not in f.get("Status", "").split():
            continue
        src, ver = f.get("Source") or f["Package"], f["Version"]
        m = re.match(r"(\S+)\s+\(([^)]+)\)", src)
        if m:
            src, ver = m.group(1), m.group(2)
        groups.setdefault((src, ver), []).append(f["Package"])
    return [(s, v, sorted(b)) for (s, v), b in sorted(groups.items())]


def _walk(root: Path, depth: int = WALK_DEPTH) -> Iterable[Path]:
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    yield root
    if depth <= 0:
        return
    for e in entries:
        if e.is_dir(follow_symlinks=False) and e.name not in SKIP_DIRS:
            yield from _walk(Path(e.path), depth - 1)


def inventory(roots: Iterable[str] = (), own_env: bool = True, os_packages: bool | None = None,
              dpkg_status: Path = Path("/var/lib/dpkg/status"),
              os_release: Path = Path("/etc/os-release")) -> tuple[list[dict[str, Any]], list[str]]:
    """What is installed: (sources, missing folders). Each source has its own packages."""
    sources: list[dict[str, Any]] = []
    missing: list[str] = []
    if own_env:
        site = Path(sysconfig.get_paths()["purelib"])
        sources.append({"kind": "python", "own": True, "ecosystem": "PyPI", "real_path": sys.prefix,
                        "python": sys.executable, "packages": _dist_packages(site)})
    for r in roots:
        root = Path(r).expanduser().resolve()
        if not root.is_dir():
            missing.append(str(r))
            continue
        for d in _walk(root):
            if len(sources) >= MAX_SOURCES:
                break
            if (d / "pyvenv.cfg").is_file():
                site, exe = _venv_parts(d)
                if site and not (own_env and os.path.samefile(d, sys.prefix)):
                    sources.append({"kind": "python", "ecosystem": "PyPI", "real_path": str(d),
                                    "python": str(exe) if exe else None, "packages": _dist_packages(site)})
            lock = d / "package-lock.json"
            if lock.is_file():
                try:
                    pkgs, direct = _npm_packages(lock)
                    sources.append({"kind": "npm", "ecosystem": "npm", "real_path": str(d), "packages": pkgs,
                                    "direct": sorted(direct)})
                except (OSError, ValueError):
                    pass
            for req in sorted(d.glob("requirements*.txt")):
                pkgs = _pinned(req)
                if pkgs:
                    sources.append({"kind": "pinned", "ecosystem": "PyPI", "real_path": str(req), "packages": pkgs})
    if os_packages is None:
        os_packages = os.environ.get("SENTRAI_DEP_OS", "").lower() not in ("off", "0", "no", "false")
    eco = os_ecosystem(_os_release(os_release)) if os_packages and dpkg_status.is_file() else None
    if eco:
        try:
            groups = _dpkg_packages(dpkg_status)
            sources.append({"kind": "os", "ecosystem": eco, "real_path": "dpkg", "packages": [(s, v) for s, v, _ in groups],
                            "binaries": {s: b for s, _, b in groups}})
        except OSError:
            pass
    return sources, missing


# ------------------------------------------------------------------ OSV

def osv_fetch(method: str, path: str, body: Any = None) -> Any:
    url = os.environ.get("SENTRAI_OSV_URL", OSV_URL).rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": "SentrAI-depscan"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (a fixed https address, or the operator's)
        return json.loads(r.read().decode("utf-8"))


def _severity(vuln: dict[str, Any]) -> str:
    """GitHub's rating where OSV has it (critical/high/moderate/low), else medium (unrated)."""
    for where in [vuln.get("database_specific") or {}] + [a.get("database_specific") or {}
                                                         for a in vuln.get("affected") or [] if isinstance(a, dict)]:
        s = str(where.get("severity") or "").lower()
        if s in ("critical", "high", "low"):
            return s
        if s in ("moderate", "medium"):
            return "medium"
    return "medium"


def fixed_in(vuln: dict[str, Any], ecosystem: str, name: str, version: str) -> tuple[bool, str | None]:
    """(whether this record names a fix for this version, the lowest fixed version above it)."""
    best = None
    seen = False
    for a in vuln.get("affected") or []:
        p = a.get("package") or {}
        if p.get("ecosystem") != ecosystem or _norm(str(p.get("name"))) != _norm(name):
            continue
        for rng in a.get("ranges") or []:
            for ev in rng.get("events") or []:
                fix = ev.get("fixed")
                if fix and vkey(fix) > vkey(version):
                    seen = True
                    if best is None or vkey(fix) < vkey(best):
                        best = fix
    return seen, best


def lookup(sources: list[dict[str, Any]], fetch: Fetch = osv_fetch) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Ask OSV about every package. Returns (findings, counts)."""
    queries = [(s, n, v) for s in sources for n, v in s["packages"]]
    vuln_ids: list[list[str]] = []
    for i in range(0, len(queries), BATCH):
        part = queries[i:i + BATCH]
        out = fetch("POST", "/v1/querybatch", {"queries": [
            {"package": {"name": n, "ecosystem": s["ecosystem"]}, "version": v} for s, n, v in part]})
        results = (out or {}).get("results") or []
        vuln_ids += [[x["id"] for x in (r or {}).get("vulns") or [] if x.get("id")] for r in results]
        vuln_ids += [[] for _ in range(len(part) - len(results))]
    wanted = list(dict.fromkeys(i for ids in vuln_ids for i in ids))
    with ThreadPoolExecutor(max_workers=8) as pool:
        details = dict(zip(wanted[:MAX_DETAILS], pool.map(_safe_detail(fetch), wanted[:MAX_DETAILS])))
    findings, no_fix = [], 0
    for (s, name, version), ids in zip(queries, vuln_ids):
        if not ids:
            continue
        vulns, fixes, unknown, sev, cves = [], [], False, [], set()
        for vid in ids:
            d = details.get(vid) or {}
            names = {vid, *(d.get("aliases") or [])}
            if cves & names:
                continue  # the same flaw from another database
            cves |= names
            vulns.append({"id": vid, "aliases": sorted(a for a in names if a.startswith("CVE-"))[:3],
                          "summary": str(d.get("summary") or "")[:200]})
            sev.append(_severity(d) if d else "medium")
            _, fix = fixed_in(d, s["ecosystem"], name, version) if d else (False, None)
            if fix:
                fixes.append(fix)
            else:
                unknown = True
        fixed = max(fixes, key=vkey) if fixes and not unknown else None
        if s["kind"] == "os" and not fixed:
            no_fix += 1  # distributions list many flaws they have not patched yet; counted, not listed
            continue
        severity = min(sev, key=SEVERITY.index)
        update, how = plan(s, name, version, fixed)
        findings.append({"id": _id(s["real_path"], s["ecosystem"], name, version), "kind": s["kind"],
                         "ecosystem": s["ecosystem"], "name": name, "version": version, "fixed": fixed,
                         "severity": severity, "vulns": vulns[:10], "vuln_count": len(vulns),
                         "update": update, "how": how, "real_path": s["real_path"],
                         **({"python": s.get("python")} if s["kind"] == "python" else {})})
    findings.sort(key=lambda f: (SEVERITY.index(f["severity"]), f["name"].lower()))
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in SEVERITY}
    counts["no_fix_os"] = no_fix
    return findings, counts


def _safe_detail(fetch: Fetch) -> Callable[[str], dict[str, Any] | None]:
    def get(vid: str) -> dict[str, Any] | None:
        try:
            return fetch("GET", f"/v1/vulns/{vid}", None)
        except Exception:  # one record that will not load still leaves the package flagged
            return None
    return get


def plan(source: dict[str, Any], name: str, version: str, fixed: str | None) -> tuple[str, str]:
    """("safe" | "manual" | "none", what to do) for one vulnerable package."""
    if not fixed:
        return "none", "No fixed version is known yet; watch for one or replace the package."
    if source["kind"] == "os":
        bins = " ".join((source.get("binaries") or {}).get(name) or [name])
        return "manual", f"Run: sudo apt-get update && sudo apt-get install --only-upgrade {bins}"
    if source["kind"] == "pinned":
        return "manual", f"Change the pin to {name}=={fixed} in this file, then reinstall."
    if source.get("own"):
        return "manual", (f"This is SentrAI's own environment: bump {name} to {fixed} in SentrAI's requirements; "
                          "an update here would be undone by the next sentrai-update.")
    if not same_major(version, fixed):
        return "manual", f"The fix ({fixed}) is a new major version; update by hand and test, it may break things."
    if not NAME[source["ecosystem"]].match(name) or not VERSION.match(fixed):
        return "manual", f"Update {name} to {fixed} by hand."
    if source["kind"] == "npm" and name not in (source.get("direct") or ()):
        return "manual", f"{name} comes in through another package: update that one, or run npm audit fix here."
    if source["kind"] == "python" and not source.get("python"):
        return "manual", f"Update {name} to {fixed} with this environment's pip."
    return "safe", f"Update {name} {version} → {fixed} (SentrAI can undo it)."


def scan(roots: Iterable[str] = (), fetch: Fetch | None = None, own_env: bool = True,
         os_packages: bool | None = None, **where: Any) -> dict[str, Any]:
    """Inventory plus lookup. Findings keep their real paths (``real_path``, ``python``) for this
    machine's own use; ``shown`` drops them for anything that leaves it."""
    started = time.time()
    roots = [str(r) for r in roots]
    sources, missing = inventory(roots, own_env, os_packages, **where)
    homes = _homes()
    base = {"scanned_at": _iso(started), "roots": [hide_home(r, homes) for r in roots],
            "missing": [hide_home(m, homes) for m in missing],
            "sources": [{"kind": s["kind"], "ecosystem": s["ecosystem"], "path": hide_home(s["real_path"], homes),
                         "packages": len(s["packages"])} for s in sources],
            "packages_checked": sum(len(s["packages"]) for s in sources)}
    try:
        findings, counts = lookup(sources, fetch or osv_fetch)
    except Exception as exc:  # offline, or OSV refused: say so instead of reporting "all clear"
        return {**base, "findings": [], "counts": {}, "took_s": round(time.time() - started, 2),
                "note": f"Could not reach the vulnerability database (OSV): {mask(str(exc))[:200]}"}
    for f in findings:
        f["path"] = hide_home(f["real_path"], homes)
    return {**base, "findings": findings[:MAX_FINDINGS], "counts": counts, "took_s": round(time.time() - started, 2),
            "note": None}


def shown(result: dict[str, Any]) -> dict[str, Any]:
    """The scan without this machine's real paths, for the panel."""
    return {**result, "findings": [{k: v for k, v in f.items() if k not in ("real_path", "python")}
                                   for f in result.get("findings") or []]}


# ------------------------------------------------------------------ updates (a person pressed Update)

class UpdateError(Exception):
    pass


def _run(run: Run | None, cmd: list[str], cwd: str | None = None) -> str:
    try:
        p = (run or subprocess.run)(cmd, cwd=cwd, capture_output=True, text=True, timeout=UPDATE_TIMEOUT_S, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UpdateError(f"{Path(cmd[0]).name} could not finish: {exc}") from exc
    tail = mask(((p.stdout or "") + (p.stderr or "")).strip())[-400:]
    if p.returncode != 0:
        raise UpdateError(f"{Path(cmd[0]).name} failed ({p.returncode}): {tail}")
    return tail


def _npm() -> str:
    exe = shutil.which("npm")
    if not exe:
        raise UpdateError("npm is not installed on this machine")
    return exe


def _check(f: dict[str, Any], version_key: str) -> None:
    if f.get("update") != "safe":
        raise UpdateError(f"{f.get('name')} is not a one-press update: {f.get('how')}")
    if f.get("kind") not in ("python", "npm") or not NAME[f["ecosystem"]].match(str(f.get("name"))) \
            or not VERSION.match(str(f.get(version_key))):
        raise UpdateError("this finding does not name a package SentrAI may update")


def apply_update(f: dict[str, Any], store: Path, run: Run | None = None) -> dict[str, Any]:
    """Update one ``safe`` finding from this machine's own last scan. Returns the record undo needs."""
    _check(f, "fixed")
    uid = f"u-{secrets.token_hex(4)}"
    rec = {"id": uid, "finding": f["id"], "kind": f["kind"], "name": f["name"], "from": f["version"],
           "to": f["fixed"], "path": f.get("path"), "real_path": f["real_path"], "python": f.get("python"),
           "at": _iso(), "status": "applied"}
    if f["kind"] == "python":
        exe = Path(str(f.get("python")))
        # a venv's bin/python is a link out of it, so compare where it sits, not where it points
        if not exe.is_file() or Path(os.path.abspath(f["real_path"])) not in Path(os.path.abspath(exe)).parents:
            raise UpdateError("the environment's python is gone or not inside it")
        rec["output"] = _run(run, [str(exe), "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                                   f"{f['name']}=={f['fixed']}"])
    else:
        project = Path(f["real_path"])
        keep = store / uid
        keep.mkdir(parents=True, exist_ok=True)
        for n in ("package.json", "package-lock.json"):
            if (project / n).is_file():
                shutil.copy2(project / n, keep / n)
        try:
            rec["output"] = _run(run, [_npm(), "install", "--no-audit", "--no-fund", f"{f['name']}@{f['fixed']}"],
                                 cwd=str(project))
        except UpdateError:
            _put_back(keep, project)  # leave the project as it was
            raise
        rec["backup"] = str(keep)
    return rec


def _put_back(keep: Path, project: Path) -> None:
    for n in ("package.json", "package-lock.json"):
        if (keep / n).is_file():
            shutil.copy2(keep / n, project / n)


def rollback(rec: dict[str, Any], run: Run | None = None) -> dict[str, Any]:
    """Undo one update made by apply_update."""
    if rec.get("status") != "applied":
        raise UpdateError(f"update {rec.get('id')} is {rec.get('status')}, not applied")
    _check({**rec, "update": "safe", "ecosystem": "PyPI" if rec.get("kind") == "python" else "npm"}, "from")
    if rec["kind"] == "python":
        out = _run(run, [str(rec["python"]), "-m", "pip", "install", "--disable-pip-version-check", "--no-input",
                         f"{rec['name']}=={rec['from']}"])
    else:
        keep, project = Path(rec["backup"]), Path(rec["real_path"])
        if not (keep / "package.json").is_file():
            raise UpdateError("the copy of package.json taken before the update is gone")
        _put_back(keep, project)
        out = _run(run, [_npm(), "ci", "--no-audit", "--no-fund"], cwd=str(project))
    return {**rec, "status": "rolled_back", "rolled_back_at": _iso(), "output": out}
