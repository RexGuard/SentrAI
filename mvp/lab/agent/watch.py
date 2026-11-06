"""The file watch: the agent's always-on antivirus, between the scans a person asks for.

A full threat scan (tasks.py) reads every file in the watched folders, when someone presses Scan.
This runs on its own, every SENTRAI_WATCH_EVERY_S seconds (default 30), and looks only at what
changed since the last look, the way an antivirus's real-time shield does:

* **New or changed files** in the watched folders (SENTRAI_THREAT_PATHS, or SENTRAI_WATCH_PATHS) are
  scanned right away with the threat scan's signatures, its checks for disguised programs and the
  shared fingerprint list from the panel.
* **Important files** that attackers change to stay in: SSH login keys, sudo rules, cron jobs,
  startup programs, /etc/ld.so.preload, the Windows Startup folders (and SENTRAI_WATCH_FILES). Their
  fingerprints are kept in threats/baseline.json, so a change made while the agent was stopped is
  still noticed when it starts again. Any change is reported with the old and new fingerprint.
* **Ransomware**: many files rewritten into scrambled-looking data, or renamed to a new ending
  (report.docx -> report.docx.locked), within one look; a ransom note appearing; or a decoy file
  touched (SENTRAI_DECOYS=on places one in each watched folder; nobody has a reason to open it).
  The alert says to take the machine off the network and restore from its latest backup.
* **Hostile programs running** (every 5 minutes): crypto miners, reverse shells, programs started
  from /tmp or whose file was deleted (the process scan's signs).

What it finds goes to the panel (POST /fleet/threats), which opens a malware incident for critical
and high finds and tells the person on duty. It never deletes, moves or stops anything itself: a
person locks a file away from the panel (quarantine.py). While the panel cannot be reached, finds
wait here and are sent when it answers. SENTRAI_WATCH=off turns all of this off.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from glob import glob
from pathlib import Path
from typing import Any, Callable, Iterable

import requests

import sentrai_paths  # noqa: E402
from app import procscan, signatures, threatscan  # noqa: E402
from agent import quarantine  # noqa: E402

EVERY_S = 30.0
PROCS_EVERY_S = 300.0
SIGS_EVERY_S = 1800.0
MAX_FILES = 20_000            # per look; more than that and the rest waits for the next full scan
MAX_PENDING = 300             # finds kept while the panel is unreachable
RANSOM_BURST = 20             # scrambled or renamed files in one look that mean ransomware
SCRAMBLED = 7.5               # bits per byte; text is 4-5, compressed or encrypted data near 8
DECOY_NAME = "0000-sentrai-decoy-do-not-open.txt"

# Already compressed or encrypted on purpose: rewriting one is not a sign of anything.
PACKED_EXT = {".zip", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".7z", ".rar", ".jar", ".war", ".whl", ".apk",
              ".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".mp4", ".mkv", ".mov", ".avi", ".ogg", ".flac",
              ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".woff", ".woff2", ".gpg", ".pgp", ".age",
              ".db", ".sqlite", ".mca", ".dat", ".pack", ".idx", ".bin", ".iso", ".img", ".vhd", ".vhdx", ".qcow2",
              ".enc", ".key", ".pem", ".p12", ".pfx", ".kdbx", ".mcworld", ".lock"}
RANSOM_NOTE = re.compile(
    r"^(_*|!*)(how[\s_-]?to|help|read[\s_-]?me|restore|recover|decrypt|unlock|your[\s_-]?files)[\w\s!.-]{0,40}"
    r"(decrypt|recover|restore|unlock|files?|instructions?|encrypted)[\w\s!.-]{0,20}\.(txt|html?|hta|rtf|url)$", re.I)

# Places attackers write to stay in. "high" opens an incident, "medium" is only listed and audited.
IMPORTANT_POSIX = [
    ("high", "SSH login keys", ["/root/.ssh/authorized_keys", "/home/*/.ssh/authorized_keys"]),
    ("high", "sudo rules", ["/etc/sudoers", "/etc/sudoers.d"]),
    ("high", "scheduled jobs", ["/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs", "/var/spool/cron"]),
    ("high", "a library forced into every program", ["/etc/ld.so.preload"]),
    ("high", "startup scripts", ["/etc/rc.local", "/etc/profile.d"]),
    ("medium", "user accounts", ["/etc/passwd", "/etc/group"]),
    ("medium", "SSH server settings", ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d"]),
    ("medium", "system services", ["/etc/systemd/system"]),
    ("medium", "the hosts file", ["/etc/hosts"]),
]
IMPORTANT_WINDOWS = [
    ("high", "startup programs", [r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
                                  r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"]),
    ("high", "SSH login keys", [r"%ProgramData%\ssh\administrators_authorized_keys",
                                r"C:\Users\*\.ssh\authorized_keys"]),
    ("medium", "the hosts file", [r"%SystemRoot%\System32\drivers\etc\hosts"]),
]


def _on(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip().lower() not in ("0", "off", "false", "no", "")


def _paths(name: str) -> list[str]:
    return [p for p in os.environ.get(name, "").split(os.pathsep) if p.strip()]


def watched_roots() -> list[str]:
    return _paths("SENTRAI_WATCH_PATHS") or _paths("SENTRAI_THREAT_PATHS")


def _digest(p: Path) -> str | None:
    """Fingerprint of a file's contents (a link: of where it points). None when unreadable."""
    try:
        if p.is_symlink():
            return "link:" + hashlib.sha256(os.readlink(p).encode()).hexdigest()
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        try:  # readable by root only (/etc/sudoers when the agent is not root): size and time are enough
            st = p.lstat()
            return f"stat:{st.st_size}:{st.st_mtime_ns}"
        except OSError:
            return None


def _head(p: Path, n: int = 65536) -> bytes:
    try:
        with open(p, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


class FileWatch:
    def __init__(self, data_dir: Path, roots: Iterable[str] | None = None,
                 important: list[tuple[str, str, list[str]]] | None = None,
                 hashes: Callable[[], set[str]] | None = None, clock: Callable[[], float] = time.time,
                 processes: Callable[[], list[procscan.Proc]] | None = None) -> None:
        self.data_dir = data_dir
        self.roots = [Path(os.path.expandvars(os.path.expanduser(r))) for r in (watched_roots() if roots is None else roots)]
        extra = [("high", "a file you asked SentrAI to watch", _paths("SENTRAI_WATCH_FILES"))]
        default = IMPORTANT_WINDOWS if os.name == "nt" else IMPORTANT_POSIX
        self.important = (default if important is None else important) + ([extra[0]] if extra[0][2] else [])
        if not _on("SENTRAI_WATCH_IMPORTANT", "on") and important is None:
            self.important = [extra[0]] if extra[0][2] else []
        self.hashes = hashes or (lambda: set())
        self.clock = clock
        self.processes = processes or procscan.list_processes
        self.homes = procscan._homes()
        self.own = [os.path.normcase(os.path.abspath(d)) for d in threatscan._own_dirs()]
        self.snap: dict[str, tuple[int, int]] | None = None
        self.burst = int(os.environ.get("SENTRAI_RANSOM_BURST", RANSOM_BURST))
        self.decoys_on = _on("SENTRAI_DECOYS", "off")
        self.seen_procs: set[str] = set()
        self.next_procs = 0.0

    # ------------------------------------------------------------ helpers
    @property
    def dir(self) -> Path:
        return quarantine.threats_dir(self.data_dir)

    def _shown(self, p: Path | str) -> str:
        return procscan.hide_home(str(p), self.homes)

    def _finding(self, path: Path | str, key: str, kind: str, severity: str, label: str, sha256: str = "",
                 real: bool = True, **more: Any) -> dict[str, Any]:
        return {"path": self._shown(path), "real_path": str(path) if real and sha256 else None, "sha256": sha256,
                "key": key, "kind": kind, "severity": severity, "label": label, "line": None, "snippet": "",
                "source": "watch", **more}

    def _mine(self, d: str) -> bool:
        n = os.path.normcase(os.path.abspath(d))
        return any(n == o or n.startswith(o + os.sep) for o in self.own)

    # ------------------------------------------------------------ folders
    def _walk(self) -> dict[str, tuple[int, int]]:
        out: dict[str, tuple[int, int]] = {}
        for root in self.roots:
            for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None, followlinks=False):
                if self._mine(dirpath):
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in threatscan.SKIP_DIRS]
                for fn in filenames:
                    if len(out) >= MAX_FILES:
                        return out
                    p = os.path.join(dirpath, fn)
                    try:
                        st = os.lstat(p)
                    except OSError:
                        continue
                    if os.path.islink(p):
                        continue
                    out[p] = (st.st_size, st.st_mtime_ns)
        return out

    def check_folders(self) -> list[dict[str, Any]]:
        now = self._walk()
        before, self.snap = self.snap, now
        if before is None:
            return []  # the first look only learns what is there; the full scan is the Scan button's job
        new = [p for p in now if p not in before]
        changed = [p for p in now if p in before and now[p] != before[p]]
        gone = [p for p in before if p not in now]
        out: list[dict[str, Any]] = []
        bad = self.hashes()
        max_bytes = threatscan.MAX_FILE_BYTES
        for p in new + changed:
            f = Path(p)
            kind = threatscan._wanted(f)
            if kind is None and f.parent.name.lower() in threatscan.CRON_DIRS:
                kind = "text"
            if kind is None and not bad:
                continue
            for x in threatscan.scan_file(f, kind or "maybe", max_bytes, bad, self.homes):
                if x["severity"] in ("critical", "high"):
                    out.append({**x, "source": "watch", "label": f"{x['label']} (new or changed file)"})
        out += self._ransomware(new, changed, gone)
        return out

    def _ransomware(self, new: list[str], changed: list[str], gone: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        notes = [p for p in new if RANSOM_NOTE.match(os.path.basename(p))]
        gone_set = set(gone)
        renamed = [p for p in new if any(p.startswith(g + ".") for g in _prefixes(p, gone_set))]
        scrambled = []
        for p in (changed + renamed)[:400]:
            if Path(p).suffix.lower() in PACKED_EXT and p not in renamed:
                continue
            head = _head(Path(p))
            if len(head) >= 512 and threatscan.entropy(head) > SCRAMBLED:
                scrambled.append(p)
        hits = set(renamed) | set(scrambled)
        stamp = time.strftime("%Y-%m-%dT%H:%M", time.localtime(self.clock()))
        where = os.path.commonpath(sorted(hits)) if len(hits) > 1 else (next(iter(hits)) if hits else "")
        if len(hits) >= self.burst:
            out.append(self._finding(where or self.roots[0], "ransomware-burst", "ransomware", "critical",
                                     f"{len(hits)} files rewritten into scrambled data or renamed in "
                                     f"{EVERY_S:.0f} s: likely ransomware. Take this machine off the network "
                                     f"and restore from its latest backup", real=False,
                                     sha256=hashlib.sha256(f"{where}|{stamp}".encode()).hexdigest(),
                                     examples=[self._shown(p) for p in sorted(hits)[:5]]))
        for p in notes[:3]:
            out.append(self._finding(p, "ransom-note", "ransomware", "critical" if hits else "high",
                                     "a ransom note appeared", sha256=_digest(Path(p)) or ""))
        return out

    # ------------------------------------------------------------ decoys
    def place_decoys(self) -> list[str]:
        if not self.decoys_on:
            return []
        f = self.dir / "decoys.json"
        known: dict[str, str] = quarantine._load(f, {})
        made = []
        text = ("This file was placed by SentrAI as a tripwire. Nobody needs to open or change it.\n"
                "If it is changed, renamed or deleted, SentrAI raises a ransomware alarm.\n"
                "To stop placing it: SENTRAI_DECOYS=off on this machine's agent.\n") * 40
        for root in self.roots:
            p = root / DECOY_NAME
            if str(p) in known or not root.is_dir():
                continue
            try:
                p.write_text(text, encoding="utf-8")
            except OSError:
                continue
            known[str(p)] = _digest(p) or ""
            made.append(str(p))
        if made:
            quarantine._store(f, known)
        return made

    def check_decoys(self) -> list[dict[str, Any]]:
        if not self.decoys_on:
            return []
        f = self.dir / "decoys.json"
        known: dict[str, str] = quarantine._load(f, {})
        out = []
        for p, want in list(known.items()):
            got = _digest(Path(p))
            if got == want:
                continue
            what = "was deleted or renamed" if got is None else "was changed"
            out.append(self._finding(p, "decoy-touched", "ransomware", "critical",
                                     f"a decoy file nobody should touch {what}: likely ransomware or someone "
                                     f"going through the files. Take this machine off the network and check it",
                                     sha256=got or hashlib.sha256(f"{p}|gone".encode()).hexdigest(), real=False))
            del known[p]  # placed again on the next look, so a second attack is noticed too
        if out:
            quarantine._store(f, known)
        return out

    # ------------------------------------------------------------ important files
    def _important_now(self) -> dict[str, dict[str, Any]]:
        """path -> {"h": fingerprint, "s": severity, "w": what it is}."""
        out: dict[str, dict[str, Any]] = {}
        for severity, what, patterns in self.important:
            for pat in patterns:
                for m in glob(os.path.expandvars(pat)) or []:
                    p = Path(m)
                    try:
                        files = [c for c in sorted(p.rglob("*"))[:500] if c.is_file() or c.is_symlink()] \
                            if p.is_dir() else [p]
                    except OSError:
                        files = []
                    for c in files:
                        out[str(c)] = {"h": _digest(c), "s": severity, "w": what}
        return out

    def check_important(self) -> list[dict[str, Any]]:
        f = self.dir / "baseline.json"
        first = not f.exists()
        before: dict[str, dict[str, Any]] = quarantine._load(f, {})
        now = self._important_now()
        out: list[dict[str, Any]] = []
        for p, cur in ([] if first else now.items()):
            old = (before.get(p) or {}).get("h")
            h = cur["h"]
            if old == h or h is None:
                continue
            label = f"new file in {cur['w']}" if old is None else f"{cur['w']} changed"
            sha = h if len(h) == 64 else ""
            x = self._finding(p, "watched-file-changed", "persistence", cur["s"], label,
                              sha256=sha or hashlib.sha256(f"{p}|{h}".encode()).hexdigest(), real=bool(sha),
                              old=(old or "")[:16] or None, new=h[:16])
            out.append(x)
            if sha:  # the new content is read with the signatures too (a cron line that downloads code)
                for hit in threatscan.scan_file(Path(p), "text", threatscan.MAX_FILE_BYTES, self.hashes(), self.homes):
                    if hit["severity"] in ("critical", "high"):
                        out.append({**hit, "source": "watch"})
        for p, old in ([] if first else before.items()):
            if p not in now or now[p]["h"] is None:
                out.append(self._finding(p, "watched-file-removed", "persistence", old.get("s", "medium"),
                                         f"{old.get('w', 'a watched file')}: a file was removed",
                                         sha256=hashlib.sha256(f"{p}|gone|{old.get('h')}".encode()).hexdigest(),
                                         real=False))
        quarantine._store(f, {p: v for p, v in now.items() if v["h"]})
        return out

    # ------------------------------------------------------------ programs
    def check_processes(self) -> list[dict[str, Any]]:
        if self.clock() < self.next_procs:
            return []
        self.next_procs = self.clock() + PROCS_EVERY_S
        try:
            procs = self.processes()
        except Exception:  # noqa: BLE001  (a process list that fails is not worth stopping the watch)
            return []
        out = []
        own = os.getpid()
        for p in procs:
            if p.pid == own:
                continue
            for hit in threatscan.check_process(p):
                if hit["severity"] not in ("critical", "high"):
                    continue
                exe = p.exe.replace(" (deleted)", "") if p.exe else ""
                key = f"{hit['key']}|{exe or p.name}"
                if key in self.seen_procs:
                    continue
                self.seen_procs.add(key)
                sha = _digest(Path(exe)) if exe and Path(exe).is_file() else None
                sha = sha if sha and len(sha) == 64 else ""
                out.append(self._finding(exe or p.name, f"process-{hit['key']}", "process", hit["severity"],
                                         f"running program: {hit['label']} ({p.name}, pid {p.pid}, account "
                                         f"{procscan.account(p.user) or 'unknown'})",
                                         sha256=sha or hashlib.sha256(key.encode()).hexdigest(), real=bool(sha)))
        return out

    # ------------------------------------------------------------ one look
    def tick(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for step in (self.check_decoys, self.check_folders, self.check_important, self.check_processes):
            try:
                out += step()
            except Exception as e:  # noqa: BLE001  (one failing check must not stop the others)
                print(f"[agent] file watch: {step.__name__} failed: {type(e).__name__}: {e}", flush=True)
        self.place_decoys()
        return out


def _prefixes(p: str, gone: set[str]) -> list[str]:
    """Files that disappeared and whose name the new file starts with (report.docx -> report.docx.locked)."""
    out = []
    base = p
    while "." in os.path.basename(base):
        base = base.rsplit(".", 1)[0]
        if base in gone:
            out.append(base)
    return out


# ------------------------------------------------------------------ talking to the panel
class SignatureCopy:
    """The panel's shared fingerprint list, fetched now and then and kept on this machine."""

    def __init__(self, data_dir: Path) -> None:
        self.file = quarantine.threats_dir(data_dir) / "signatures.json"
        self._cache: tuple[float, set[str]] | None = None

    def hashes(self) -> set[str]:
        try:
            mtime = self.file.stat().st_mtime
        except OSError:
            return set()
        if self._cache is None or self._cache[0] != mtime:
            data = signatures.load_copy(self.file)
            self._cache = (mtime, {h for h in (data.get("sha256") or []) + (data.get("md5") or []) if isinstance(h, str)})
        return self._cache[1]

    def fetch(self, data: dict[str, Any], session: requests.Session, verify: Any) -> str | None:
        """Gets the newest list. Returns an error line, or None."""
        have = signatures.load_copy(self.file).get("version")
        try:
            r = session.get(f"{data['panel']}/fleet/signatures", params={"have": have} if have is not None else None,
                            headers={"Authorization": f"Bearer {data['key']}"}, timeout=30, verify=verify)
        except requests.RequestException as e:
            return f"signatures: panel unreachable ({type(e).__name__}); keeping the copy here"
        if r.status_code == 404:
            return None  # an older panel without the list
        if r.status_code != 200:
            return f"signatures: panel answered {r.status_code}"
        body = r.json()
        if body.get("unchanged"):
            return None
        signatures.save_copy(self.file, body)
        return None


def send(data: dict[str, Any], session: requests.Session, verify: Any, findings: list[dict[str, Any]]) -> bool:
    try:
        r = session.post(f"{data['panel']}/fleet/threats", json={"findings": findings}, timeout=15, verify=verify,
                         headers={"Authorization": f"Bearer {data['key']}"})
        return r.status_code == 200 or 400 <= r.status_code < 500 and r.status_code != 429
    except requests.RequestException:
        return False


def on() -> bool:
    return _on("SENTRAI_WATCH", "on")


def loop(data: dict[str, Any], verify: Any, data_dir: Path, stop: threading.Event,
         session: requests.Session | None = None, log: Callable[[str], None] = lambda s: print(f"[agent] {s}", flush=True),
         every_s: float | None = None) -> None:
    """Runs beside the block list and the jobs, as its own thread."""
    session = session or requests.Session()
    sigs = SignatureCopy(data_dir)
    watch = FileWatch(data_dir, hashes=sigs.hashes)
    every = every_s or float(os.environ.get("SENTRAI_WATCH_EVERY_S", EVERY_S))
    log(f"file watch on: {len(watch.roots)} folder(s), important files, running programs, every {every:.0f} s"
        + ("; decoys on" if watch.decoys_on else ""))
    pending: list[dict[str, Any]] = []
    next_sigs = 0.0
    while not stop.is_set():
        if time.monotonic() >= next_sigs:
            err = sigs.fetch(data, session, verify)
            if err:
                log(err)
            next_sigs = time.monotonic() + SIGS_EVERY_S
        found = watch.tick()
        if found:
            found = quarantine.remember(data_dir, found)
            for x in found:
                log(f"file watch: {x['severity']} {x['kind']}: {x['label']} in {x['path']}")
            pending = (pending + found)[-MAX_PENDING:]
        if pending and send(data, session, verify, pending):
            pending = []
        stop.wait(every)


def status(data_dir: Path) -> dict[str, Any]:
    """For `python -m agent status`: what the watch keeps here."""
    d = quarantine.threats_dir(data_dir)
    sig = signatures.load_copy(d / "signatures.json")
    return {"watch": "on" if on() else "off", "folders": [procscan.hide_home(r, procscan._homes()) for r in watched_roots()],
            "important_files": len(quarantine._load(d / "baseline.json", {})),
            "decoys": len(quarantine._load(d / "decoys.json", {})),
            "fingerprints": len(sig.get("sha256") or []) + len(sig.get("md5") or []),
            "fingerprints_fetched": sig.get("fetched_at"), "quarantined": len(quarantine.listed(data_dir))}


def dump(data_dir: Path) -> str:
    return json.dumps(status(data_dir), indent=2)
