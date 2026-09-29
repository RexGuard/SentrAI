"""Process scanner: find the programs running on this computer and where they keep their logs.

Scout (``lab/scout``) finds log files by following a technician through the folders. This is
the automatic half: list the running processes, recognise the known ones (web servers,
databases, app servers, remote access, SentrAI's own lab), and point at their log files.
The result is only a list of *suggestions*. Nothing is watched until an operator approves a
path (``POST /log-sources``), which the collector then picks up.

Safety rules, all enforced here rather than left to the model:
- Read-only. It lists processes and checks whether files exist; it never starts, stops,
  signals or writes anything, and never reads log contents.
- Protected processes (``process_scan.skip_processes`` in the system profile, plus a default
  list such as lsass and password managers) are counted but not described.
- Sensitive details are hidden: command lines are cut to the program and its log options with
  secrets masked, home folders become ``~``, and personal accounts become ``(user)``.

Windows uses PowerShell/CIM (``Win32_Process`` and ``Win32_Service``); Linux reads ``/proc``;
macOS and other Unix systems use ``ps``. Standard library only.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import platform
import re
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

MAX_PROCESSES = 400          # processes reported back
MAX_SUGGESTIONS = 40
MAX_FILES_PER_DIR = 8        # log files listed per suggested folder
SCAN_TIMEOUT_S = 20

# Never described, whatever the profile says: credential stores and security-sensitive
# system processes. Their names are counted as "skipped (protected)".
DEFAULT_SKIP = ["lsass", "lsaiso", "csrss", "winlogon", "smss", "wininit", "keepass*", "1password*",
                "bitwarden*", "lastpass*", "dashlane*", "ssh-agent", "gpg-agent", "gnome-keyring*",
                "securityd", "secd", "keychain*"]

SERVICE_ACCOUNTS = {"root", "system", "local service", "network service", "localsystem", "nt authority\\system",
                    "nt authority\\local service", "nt authority\\network service", "www-data", "apache", "nginx",
                    "http", "mysql", "postgres", "mongodb", "redis", "daemon", "nobody", "sshd", "syslog",
                    "_www", "_mysql", "_postgres", "mssqlserver", "nt service\\mssqlserver"}

SECRET = re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|auth|credential|key)[\w-]*\s*[=:]\s*|"
                    r"--?(?:password|passwd|pwd|secret|token|api[_-]?key|auth)[\w-]*[= ])(\S+)")
URL_CREDS = re.compile(r"(\w+://)[^/\s:@]+:[^/\s@]+@")
LOG_OPTION = re.compile(r"(?i)^--?[\w.-]*log[\w.-]*(?:=(.+))?$")
LOG_EXT = ("*.log", "*.jsonl", "*.txt", "*.log.*", "*.out", "*.err", "access*", "error*", "*.csv", "ERRORLOG*")


# ----------------------------------------------------------------- catalogue
@dataclass
class Program:
    key: str
    label: str
    names: list[str]             # process names (lower case, without .exe); fnmatch patterns
    layer: str                   # collector layer: web | db | os | network | cloud
    windows: list[str] = field(default_factory=list)
    unix: list[str] = field(default_factory=list)
    mac: list[str] = field(default_factory=list)
    near_exe: list[str] = field(default_factory=list)  # relative to the program's install folder
    fmt: str = "text"
    note: str = ""


# Paths may use %ENV% (Windows), ~ and glob patterns. {install} is the program's install
# folder (the folder above bin/ when the executable lives in bin/).
CATALOGUE: list[Program] = [
    Program("nginx", "nginx web server", ["nginx"], "web",
            windows=[r"C:\nginx*\logs"], unix=["/var/log/nginx"], mac=["/usr/local/var/log/nginx",
                                                                       "/opt/homebrew/var/log/nginx"],
            near_exe=["logs"]),
    Program("apache", "Apache web server", ["httpd", "apache2", "apache"], "web",
            windows=[r"C:\Apache24\logs", r"C:\xampp\apache\logs"], unix=["/var/log/apache2", "/var/log/httpd"],
            mac=["/usr/local/var/log/httpd", "/opt/homebrew/var/log/httpd", "/private/var/log/apache2"],
            near_exe=["logs", "../logs"]),
    Program("iis", "IIS web server (Windows)", ["w3wp", "inetinfo"], "web",
            windows=[r"%SystemDrive%\inetpub\logs\LogFiles\W3SVC*", r"%SystemRoot%\System32\LogFiles\HTTPERR"],
            note="W3C text logs; the first lines starting with # describe the columns."),
    Program("tomcat", "Tomcat / Java app server", ["tomcat*"], "web",
            windows=[r"C:\Program Files\Apache Software Foundation\Tomcat*\logs"],
            unix=["/var/log/tomcat*", "/opt/tomcat*/logs"], near_exe=["../logs", "logs"]),
    Program("mysql", "MySQL / MariaDB database", ["mysqld", "mariadbd", "mysqld-nt"], "db",
            windows=[r"%ProgramData%\MySQL\MySQL Server*\Data\*.err", r"%ProgramData%\MySQL\MySQL Server*\Data\*.log",
                     r"C:\xampp\mysql\data\*.err"],
            unix=["/var/log/mysql", "/var/log/mariadb", "/var/log/mysqld.log"],
            mac=["/usr/local/var/mysql/*.err", "/opt/homebrew/var/mysql/*.err"],
            note="The error log shows failed logins only when log_error_verbosity is 3."),
    Program("postgres", "PostgreSQL database", ["postgres", "postmaster", "pg_ctl"], "db",
            windows=[r"%ProgramFiles%\PostgreSQL\*\data\log", r"%ProgramFiles%\PostgreSQL\*\data\pg_log"],
            unix=["/var/log/postgresql", "/var/lib/pgsql/data/log", "/var/lib/postgresql/*/main/log"],
            mac=["/usr/local/var/log/postgres*", "/opt/homebrew/var/log/postgres*"], near_exe=["../data/log"],
            note="Set log_connections = on to see who logs in."),
    Program("mssql", "Microsoft SQL Server", ["sqlservr"], "db",
            windows=[r"%ProgramFiles%\Microsoft SQL Server\MSSQL*\MSSQL\Log"], unix=["/var/opt/mssql/log"],
            note="ERRORLOG holds failed logins (UTF-16 text on Windows)."),
    Program("mongodb", "MongoDB database", ["mongod"], "db",
            windows=[r"%ProgramFiles%\MongoDB\Server\*\log"], unix=["/var/log/mongodb"],
            mac=["/usr/local/var/log/mongodb", "/opt/homebrew/var/log/mongodb"], fmt="jsonl"),
    Program("redis", "Redis", ["redis-server", "redis"], "db",
            windows=[r"%ProgramFiles%\Redis\*.log"], unix=["/var/log/redis"],
            mac=["/usr/local/var/log/redis.log", "/opt/homebrew/var/log/redis.log"]),
    Program("sshd", "SSH server", ["sshd"], "os",
            windows=[r"%ProgramData%\ssh\logs"], unix=["/var/log/auth.log", "/var/log/secure"],
            note="On Windows, OpenSSH logs to the Event Log unless SyslogFacility LOCAL0 is set."),
    Program("rdp", "Remote Desktop", ["termsrv", "rdpclip"], "os",
            note="Remote Desktop logins are in the Windows Event Log (Security, event 4624/4625), not a text file."),
    Program("fail2ban", "fail2ban", ["fail2ban-server"], "network", unix=["/var/log/fail2ban.log"]),
    Program("docker", "Docker", ["dockerd", "com.docker.backend", "docker desktop"], "cloud",
            windows=[r"%LOCALAPPDATA%\Docker\log\host"], unix=["/var/lib/docker/containers/*/*-json.log"],
            fmt="jsonl", note="One JSON log per container."),
    Program("syslog", "System log daemon", ["rsyslogd", "syslog-ng", "syslogd"], "os",
            unix=["/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure"],
            mac=["/var/log/system.log"]),
    Program("node", "Node.js app", ["node", "pm2*"], "web", unix=["~/.pm2/logs"], windows=[r"~\.pm2\logs"]),
    Program("python", "Python app", ["python*", "py", "pythonw*", "uvicorn", "gunicorn", "flask", "streamlit"], "web"),
]

INTERPRETERS = {"python", "node", "tomcat"}  # the app, not the interpreter, decides where logs go


# ------------------------------------------------------------ process list
@dataclass
class Proc:
    pid: int
    name: str
    exe: str = ""
    cmdline: list[str] = field(default_factory=list)
    user: str = ""
    cwd: str = ""
    service: str = ""
    open_logs: list[str] = field(default_factory=list)  # log files the process has open (Linux only)


def _short(name: str) -> str:
    n = Path(name).name.lower()
    return n[:-4] if n.endswith(".exe") else n


def list_processes(system: str | None = None, runner: Callable[..., str] | None = None) -> list[Proc]:
    system = system or platform.system()
    if system == "Windows":
        return _windows(runner or _run)
    if system == "Linux" and Path("/proc").is_dir():
        return _linux()
    return _ps(runner or _run)


def _run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT_S,
                          encoding="utf-8", errors="replace", check=False).stdout


PS_SCRIPT = ("$p = Get-CimInstance Win32_Process | Select-Object ProcessId,Name,ExecutablePath,CommandLine; "
             "$s = Get-CimInstance Win32_Service | Where-Object { $_.ProcessId -gt 0 } | "
             "Select-Object Name,ProcessId,StartName; "
             "@{processes=@($p); services=@($s)} | ConvertTo-Json -Depth 3 -Compress")


def _windows(run: Callable[..., str]) -> list[Proc]:
    raw = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", PS_SCRIPT])
    data = json.loads(raw or "{}")
    services: dict[int, dict] = {}
    for s in data.get("services") or []:
        services.setdefault(int(s.get("ProcessId") or 0), s)
    out = []
    for p in data.get("processes") or []:
        pid = int(p.get("ProcessId") or 0)
        svc = services.get(pid, {})
        cmd = p.get("CommandLine") or ""
        try:
            args = shlex.split(cmd, posix=False) if cmd else []
        except ValueError:
            args = cmd.split()
        out.append(Proc(pid, str(p.get("Name") or ""), str(p.get("ExecutablePath") or ""),
                        [a.strip('"') for a in args], str(svc.get("StartName") or ""), "", str(svc.get("Name") or "")))
    return out


def _linux() -> list[Proc]:
    try:
        import pwd
        user_of: Callable[[int], str] = lambda uid: pwd.getpwuid(uid).pw_name  # noqa: E731
    except (ImportError, KeyError):
        user_of = str
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            name = (d / "comm").read_text().strip()
            cmd = [a for a in (d / "cmdline").read_bytes().decode("utf-8", "replace").split("\0") if a]
            uid = next(int(line.split()[1]) for line in (d / "status").read_text().splitlines()
                       if line.startswith("Uid:"))
        except (OSError, StopIteration, ValueError):
            continue  # exited, or a kernel thread
        exe = cwd = ""
        logs = []
        try:
            exe = os.readlink(d / "exe")
            cwd = os.readlink(d / "cwd")
            for fd in (d / "fd").iterdir():
                target = os.readlink(fd)
                if target.startswith("/") and any(fnmatch.fnmatch(Path(target).name, g) for g in LOG_EXT[:5]):
                    logs.append(target)
        except OSError:
            pass  # another user's process: name and command line only
        try:
            user = user_of(uid)
        except KeyError:
            user = str(uid)
        out.append(Proc(int(d.name), name, exe, cmd, user, cwd, "", sorted(set(logs))[:MAX_FILES_PER_DIR]))
    return out


def _ps(run: Callable[..., str]) -> list[Proc]:
    """macOS and other Unix: two ps calls, because the program path may contain spaces."""
    comm = {}
    for line in run(["ps", "-axww", "-o", "pid=,comm="]).splitlines():
        pid, _, path = line.strip().partition(" ")
        if pid.isdigit():
            comm[int(pid)] = path.strip()
    out = []
    for line in run(["ps", "-axww", "-o", "pid=,user=,args="]).splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit():
            continue
        exe = comm.get(int(parts[0]), "")
        out.append(Proc(int(parts[0]), Path(exe).name, exe, parts[2].split() if len(parts) > 2 else [], parts[1]))
    return out


# ----------------------------------------------------------------- privacy
def _homes() -> list[str]:
    homes = {str(Path.home())}
    for base in ("/home", "/Users", r"C:\Users"):
        try:
            homes |= {str(p) for p in Path(base).iterdir() if p.is_dir()}
        except OSError:
            pass
    return sorted(homes, key=len, reverse=True)


def hide_home(path: str, homes: list[str]) -> str:
    for h in homes:
        if path.lower().startswith(h.lower()) and (len(path) == len(h) or path[len(h)] in "/\\"):
            return "~" + path[len(h):]
    return path


def mask(text: str) -> str:
    return URL_CREDS.sub(r"\1[hidden]@", SECRET.sub(lambda m: m.group(1) + "[hidden]", text))


def account(user: str) -> str:
    if not user:
        return ""
    return user if user.lower() in SERVICE_ACCOUNTS or user.lower().startswith(("nt ", "_")) else "(user)"


def is_protected(name: str, skip: list[str]) -> bool:
    n = _short(name)
    return any(fnmatch.fnmatch(n, pat.lower().removesuffix(".exe")) for pat in skip)


# ------------------------------------------------------------- discovery
WIN_VAR = re.compile(r"%(\w+)%")


def _expand(pattern: str) -> str:
    """~, $VAR and %VAR% (looked up case-insensitively, as Windows does). Unknown %VAR% stays as is."""
    env = {k.lower(): v for k, v in os.environ.items()}
    pattern = WIN_VAR.sub(lambda m: env.get(m.group(1).lower(), m.group(0)), pattern)
    pattern = os.path.expanduser(os.path.expandvars(pattern))
    return pattern.replace("\\", "/") if os.sep == "/" else pattern  # Windows patterns in tests on Linux


def _install_dir(exe: str) -> Path | None:
    if not exe:
        return None
    d = Path(exe).parent
    return d.parent if d.name.lower() in ("bin", "sbin", "scripts") else d


def _project_dir(p: Proc) -> Path | None:
    """For an interpreter: the app's folder (the folder holding its .venv, its script, or its cwd)."""
    for exe in [Path(x) for x in (p.exe, p.cmdline[0] if p.cmdline else "") if x]:
        for parent in exe.parents:
            if parent.name.lower() in (".venv", "venv", "env"):
                return parent.parent
    for a in p.cmdline[1:]:
        if not a.startswith("-") and a.lower().endswith((".py", ".js", ".jar")):
            s = Path(a)
            if not s.is_absolute() and p.cwd:
                s = Path(p.cwd) / s
            if s.is_absolute():
                return s.parent
    cwd = Path(p.cwd) if p.cwd else None
    return cwd if cwd and len(cwd.parts) > 2 else None  # not / or C:\ or /usr


def _log_options(args: list[str]) -> list[str]:
    """Values of --log-file style options (``--access-logfile x``, ``--log=x``, ``-e x.log``)."""
    found: list[str] = []
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        m = LOG_OPTION.match(a)
        if m:
            val = m.group(1)
            if not val and i + 1 < len(args) and not args[i + 1].startswith("-"):
                val, skip_next = args[i + 1], True
            if val and val not in ("-", "stdout", "stderr") and ("/" in val or "\\" in val or "." in val):
                found.append(val)
        elif a.lower().endswith((".log", ".jsonl")) and not a.startswith("-"):
            found.append(a)
    return list(dict.fromkeys(found))


def _files_in(d: Path) -> list[Path]:
    files: list[Path] = []
    try:
        for g in LOG_EXT:
            files += [f for f in d.glob(g) if f.is_file()]
    except OSError:
        return []
    uniq = sorted(set(files), key=lambda f: f.stat().st_mtime if f.exists() else 0, reverse=True)
    return uniq[:MAX_FILES_PER_DIR]


def _candidates(prog: Program | None, p: Proc, system: str) -> list[tuple[Path, str]]:
    """(path, why) pairs that may hold this process's logs. Nothing is checked yet."""
    out: list[tuple[Path, str]] = []
    if prog:
        known = prog.windows if system == "Windows" else (prog.mac or prog.unix) if system == "Darwin" else prog.unix
        for pat in known:
            out += [(Path(x), "usual place for " + prog.label) for x in glob.glob(_expand(pat))]
        inst = _install_dir(p.exe)
        if inst:
            out += [((inst / rel).resolve(), "next to the program") for rel in prog.near_exe]
    for val in _log_options(p.cmdline):
        path = Path(_expand(val))
        if not path.is_absolute() and p.cwd:
            path = Path(p.cwd) / path
        out.append((path, "named on its command line"))
    if prog and prog.key in INTERPRETERS:
        proj = _project_dir(p)
        if proj:
            out += [(proj / d, "logs folder of the app") for d in ("logs", "log", "var/log")]
    out += [(Path(f), "open by the process right now") for f in p.open_logs]
    return out


def match(p: Proc) -> Program | None:
    n = _short(p.name or p.exe)
    for prog in CATALOGUE:
        if any(fnmatch.fnmatch(n, pat) for pat in prog.names):
            return prog
    return None


# SentrAI's own parts: listed, but their logs are not suggested (they are not the systems it defends).
OWN = ("SentrAI core", "SentrAI collector", "SentrAI dashboard", "SentrAI notifier")


def _describe(prog: Program | None, p: Proc) -> str:
    if prog and prog.key == "python":
        args = " ".join([p.exe, *p.cmdline[:6]]).lower().replace("\\", "/")
        for key, text in (("target_app", "SentrAI lab: fake student portal"), ("app.main:app", "SentrAI core"),
                          ("collector.collector", "SentrAI collector"), ("dashboard/", "SentrAI dashboard"),
                          ("notifier.py", "SentrAI notifier"), ("uvicorn", "Python web server (uvicorn)"),
                          ("streamlit", "Python dashboard (Streamlit)"),
                          ("gunicorn", "Python web server (gunicorn)"), ("flask", "Python web app (Flask)")):
            if key in args or key in _short(p.name):
                return text
    return prog.label if prog else _short(p.name)


def scan(profile: dict[str, Any] | None = None, watched: set[str] | None = None,
         system: str | None = None, processes: list[Proc] | None = None) -> dict[str, Any]:
    """Scan once. Returns the processes (privacy-filtered) and suggested log paths.

    ``watched`` holds the paths the collector already reads; they are flagged, not repeated.
    """
    system = system or platform.system()
    cfg = (profile or {}).get("process_scan") or {}
    if cfg.get("enabled") is False:
        return {"platform": system, "enabled": False, "processes": [], "suggestions": [],
                "note": "Process scanning is turned off in the system profile (process_scan.enabled)."}
    skip = DEFAULT_SKIP + list(cfg.get("skip_processes") or [])
    started = time.time()
    try:
        procs = processes if processes is not None else list_processes(system)
        error = None
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError) as e:
        procs, error = [], f"{type(e).__name__}: {e}"[:200]
    homes = _homes()
    watched_norm = {os.path.normcase(os.path.abspath(w)) for w in (watched or set())}
    skipped = 0
    rows: list[dict[str, Any]] = []
    found: dict[str, dict[str, Any]] = {}
    notes: list[str] = []
    own_pid = os.getpid()
    for p in sorted(procs, key=lambda x: x.pid):
        if is_protected(p.name or p.exe, skip):
            skipped += 1
            continue
        prog = match(p)
        what = _describe(prog, p)
        if prog and prog.note:
            notes.append(f"{prog.label}: {prog.note}")
        if prog or p.pid == own_pid:
            rows.append({"pid": p.pid, "name": p.name, "program": what, "layer": prog.layer if prog else "",
                         "path": hide_home(p.exe, homes) if p.exe else "", "account": account(p.user),
                         "service": p.service,
                         "log_options": [hide_home(mask(v), homes) for v in _log_options(p.cmdline)]})
        if p.pid == own_pid or what in OWN:
            continue
        for path, why in _candidates(prog, p, system):
            _add(found, path, why, prog, what, p.pid, homes, watched_norm)
    _merge_into_folders(found)
    suggestions = sorted(found.values(), key=lambda s: (s["already_watched"], not s["recognised"],
                                                         -s["files_found"], s["path"]))
    return {"platform": system, "enabled": True, "scanned": len(procs), "skipped_protected": skipped,
            "recognised": len(rows), "processes": rows[:MAX_PROCESSES],
            "suggestions": suggestions[:MAX_SUGGESTIONS], "notes": sorted(set(notes)), "error": error,
            "took_s": round(time.time() - started, 2)}


def _add(found: dict[str, dict[str, Any]], path: Path, why: str, prog: Program | None, what: str, pid: int,
         homes: list[str], watched_norm: set[str]) -> None:
    try:
        if not path.exists():
            return
        is_dir = path.is_dir()
        files = _files_in(path) if is_dir else [path]
    except OSError:
        return  # no permission: skip quietly
    if not files:
        return
    key = os.path.normcase(os.path.abspath(path))
    entry = found.get(key)
    if entry is None:
        watched_files = [f for f in files if os.path.normcase(os.path.abspath(f)) in watched_norm]
        entry = found[key] = {
            "path": hide_home(str(path), homes), "real_path": str(path), "kind": "folder" if is_dir else "file",
            "program": what, "recognised": prog is not None, "layer": prog.layer if prog else "web", "format": _fmt(prog, files), "reasons": [],
            "pids": [], "files_found": len(files),
            "files": [{"name": f.name if is_dir else hide_home(str(f), homes), "path": str(f),
                       "size": _size(f), "modified": _mtime(f),
                       "watched": os.path.normcase(os.path.abspath(f)) in watched_norm} for f in files],
            "already_watched": bool(watched_files) and len(watched_files) == len(files) or key in watched_norm}
    if why not in entry["reasons"]:
        entry["reasons"].append(why)
    if pid not in entry["pids"]:
        entry["pids"].append(pid)


def _merge_into_folders(found: dict[str, dict[str, Any]]) -> None:
    """A file that is also listed through its folder is shown once, under the folder."""
    for key, entry in list(found.items()):
        if entry["kind"] != "file":
            continue
        folder = found.get(os.path.normcase(os.path.dirname(key)))
        if folder and any(os.path.normcase(f["path"]) == key for f in folder["files"]):
            folder["reasons"] += [r for r in entry["reasons"] if r not in folder["reasons"]]
            del found[key]


def _fmt(prog: Program | None, files: list[Path]) -> str:
    if prog and prog.fmt != "text":
        return prog.fmt
    return "jsonl" if files and all(f.suffix.lower() == ".jsonl" for f in files) else "text"


def _size(f: Path) -> int:
    try:
        return f.stat().st_size
    except OSError:
        return 0


def _mtime(f: Path) -> str:
    try:
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(f.stat().st_mtime))
    except OSError:
        return ""
