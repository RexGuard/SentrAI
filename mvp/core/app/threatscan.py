"""Threat scan: look inside files and at running programs for signs of a break-in that already happened.

The process scan (``procscan``) finds where programs keep their logs. This is the other half of a
check-up: a web shell left in an upload folder, a reverse shell or downloader in a startup script,
a crypto miner, or a tool for breaking out of a container (common on shared game-server hosts).

Safety rules, all enforced here:
- Read-only. Files are opened for reading and hashed; nothing is run, moved or deleted. Moving a
  file into quarantine is a separate step an operator approves by id (``threats.py``).
- Only folders the operator chose are walked (``threat_scan.paths`` in the system profile, or the
  ones passed to a scan). SentrAI's own folders are always skipped, since its signature lists would
  match themselves.
- Sensitive details are hidden: the matched line is cut short with secrets masked, home folders
  become ``~``.

Signatures are grouped by kind and severity. ``critical`` and ``high`` findings become events that
the rules classify as ``malware``; ``medium`` ones are only listed. Standard library only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import CORE_DIR
from . import procscan
from .procscan import Proc, hide_home, mask

MVP_DIR = CORE_DIR.parent
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_FILES = 50_000             # per scan; the rest is reported as not checked
MAX_FINDINGS = 300
MAX_HITS_PER_FILE = 5
MAX_JAR_ENTRY_BYTES = 2 * 1024 * 1024
SNIPPET = 160

# Text files worth reading. JavaScript and Java archives are included on purpose: game-server
# malware lives in plugin .jar files and Node bots, and other scanners skip both.
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".py", ".pl", ".rb", ".lua",
              ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar", ".inc", ".jsp", ".jspx", ".asp",
              ".aspx", ".ashx", ".cgi", ".js", ".mjs", ".cjs", ".ts"}
CONFIG_EXT = {".yml", ".yaml", ".conf", ".cfg", ".ini", ".properties", ".service", ".timer", ".desktop",
              ".htaccess", ".env", ".txt", ".json", ".toml", ".xml"}
ARCHIVE_EXT = {".jar"}
# Extensionless files are read when they start with "#!" (scripts) or sit in a cron folder.
CRON_DIRS = ("cron", "cron.d", "cron.hourly", "cron.daily", "crontabs")

# Never walked into: package caches and VCS data (huge, rarely the hiding place). Note that tmp/,
# logs/ and config.yml are *not* skipped: attackers like exactly those places.
SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
             ".pytest_cache", "site-packages"}
# Bundled or generated files where a "suspicious" call is nearly always a library.
SKIP_FILES = ("*.min.js", "*.bundle.js", "*.map", "package-lock.json", "yarn.lock", "pnpm-lock.yaml")


@dataclass(frozen=True)
class Signature:
    key: str
    kind: str          # webshell | backdoor | reverse_shell | miner | dropper | obfuscation | container_escape | persistence
    severity: str      # critical | high | medium
    label: str
    rx: re.Pattern[str]


def _sig(key: str, kind: str, severity: str, label: str, pattern: str) -> Signature:
    return Signature(key, kind, severity, label, re.compile(pattern, re.I | re.M))


# Bounded gaps ({0,200}) instead of .* so a long minified line cannot make a pattern crawl.
SIGNATURES: list[Signature] = [
    # Code that runs whatever it is sent, hidden behind an encoding: the classic PHP backdoor.
    _sig("php-eval-decoded", "backdoor", "critical", "runs hidden (encoded) code",
         r"\b(eval|assert)\s*\(\s*(@\s*)?(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin)\s*\("),
    _sig("php-eval-request", "webshell", "critical", "runs code sent in a web request",
         r"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(@\s*)?(stripslashes\s*\(\s*)?"
         r"\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b"),
    _sig("php-call-request", "webshell", "critical", "calls a function named in a web request",
         r"\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"),
    _sig("php-input-exec", "webshell", "critical", "runs the raw request body",
         r"\b(eval|assert|system|exec|shell_exec|passthru)\s*\([^;\n]{0,200}php://input"),
    _sig("php-preg-e", "backdoor", "high", "regex replace that runs code (/e)",
         r"preg_replace\s*\(\s*['\"](.).{0,200}\1[imsxu]*e[imsxu]*['\"]"),
    _sig("php-create-function", "backdoor", "high", "builds a function from encoded text",
         r"create_function\s*\([^;\n]{0,200}(base64_decode|gzinflate|str_rot13|\$_(GET|POST|REQUEST))"),
    _sig("known-webshell", "webshell", "critical", "name of a known web shell kit",
         r"\b(c99shell|r57shell|b374k|wso\s?shell|FilesMan|PHPJackal|AnonymousFox|weevely|China\s?Chopper)\b"),
    _sig("jsp-exec-param", "webshell", "critical", "JSP page runs a command from the request",
         r"Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter"),
    _sig("asp-exec-request", "webshell", "critical", "ASP page runs code from the request",
         r"\b(eval|execute)\s*\(?\s*request(\.form|\.querystring)?\s*\("),
    _sig("upload-to-php", "dropper", "high", "saves an upload as a runnable .php file",
         r"move_uploaded_file\s*\([^;\n]{0,200}\.ph(p\d?|tml)\b"),
    _sig("write-decoded", "dropper", "high", "writes decoded hidden content to disk",
         r"\b(file_put_contents|fwrite|fputs)\s*\([^;\n]{0,200}(base64_decode|gzinflate|str_rot13)\s*\("),

    # Reverse shells: the machine dials out and hands its shell to someone else.
    _sig("bash-dev-tcp", "reverse_shell", "critical", "shell connected to a remote address (/dev/tcp)",
         r"\b(ba)?sh\b[^\n]{0,80}(>&|0>&1|<>)\s*/dev/(tcp|udp)/"),
    _sig("dev-tcp-exec", "reverse_shell", "critical", "opens a raw network socket from a shell",
         r"\bexec\s+\d+\s*<>\s*/dev/(tcp|udp)/"),
    _sig("nc-exec", "reverse_shell", "critical", "netcat handing out a shell",
         r"\b(nc|ncat|netcat)\b[^\n]{0,60}\s-(e|c)\s*['\"]?(/bin/(ba)?sh|cmd(\.exe)?|powershell)"),
    _sig("mkfifo-nc", "reverse_shell", "critical", "named pipe wired to netcat",
         r"mkfifo\s+\S+[^\n]{0,120}\|\s*(nc|ncat|netcat)\b"),
    _sig("py-socket-shell", "reverse_shell", "critical", "Python socket wired to a shell",
         r"socket\.socket\([^\n]{0,300}(subprocess\.(call|Popen)|pty\.spawn|os\.dup2)"),
    _sig("php-fsock-shell", "reverse_shell", "critical", "PHP socket wired to a shell",
         r"fsockopen\s*\([^\n]{0,300}(/bin/(ba)?sh|proc_open|shell_exec)"),
    _sig("perl-socket-shell", "reverse_shell", "critical", "Perl socket wired to a shell",
         r"use\s+Socket[^\n]{0,400}exec\s*\(?\s*['\"]/bin/(ba)?sh"),
    _sig("ps-tcpclient", "reverse_shell", "critical", "PowerShell TCP client running received commands",
         r"Net\.Sockets\.TCPClient[^\n]{0,400}(iex|Invoke-Expression)"),

    # Download and run: a one-line installer for whatever the attacker wants next.
    _sig("curl-pipe-sh", "dropper", "high", "downloads a script and runs it at once",
         r"\b(curl|wget)\b[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
    _sig("dl-chmod-run", "dropper", "high", "downloads a file, makes it runnable and starts it",
         r"\b(curl|wget)\b[^\n]{0,200}(/tmp|/dev/shm|/var/tmp)/[^\n]{0,200}chmod\s+\+?[0-7]*x[^\n]{0,200}(\./|/tmp/|/dev/shm/)"),
    _sig("ps-download-run", "dropper", "high", "PowerShell downloads and runs code",
         r"(DownloadString|DownloadFile|Invoke-WebRequest|iwr)\b[^\n]{0,200}(\|\s*)?(iex|Invoke-Expression)\b"),
    _sig("ps-encoded", "obfuscation", "high", "PowerShell running an encoded command",
         r"powershell(\.exe)?\b[^\n]{0,80}\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}"),

    # Crypto miners: someone else's code spending this machine's power.
    _sig("miner-pool", "miner", "critical", "crypto-mining pool address",
         r"\bstratum\d?\+(tcp|ssl|tls)://"),
    _sig("miner-name", "miner", "critical", "known crypto miner program",
         r"\b(xmrig|xmr-stak|ethminer|cgminer|bfgminer|cpuminer|minerd|nbminer|lolminer|phoenixminer|nanominer|srbminer)\b"),
    _sig("miner-config", "miner", "high", "crypto miner settings",
         r"[\"'](donate-level|randomx|cpu-max-threads-hint|nicehash)[\"']\s*:"),

    # Escaping the box: running a whole other system inside a hosted server (Harbor, Ptero-VM style).
    _sig("proot-root", "container_escape", "high", "fake root system (proot)",
         r"\bproot\b[^\n]{0,120}\s(-0|--root-id|-S\s|-r\s)"),
    _sig("minirootfs", "container_escape", "high", "downloads a mini Linux system to run inside the server",
         r"(alpine|ubuntu|debian)[^\n]{0,80}minirootfs|minirootfs[^\n]{0,80}\.tar"),
    _sig("container-tool", "container_escape", "high", "known container escape tool",
         r"\b(RealTriassic|triassic\.dev|ptero-vm|harbor\.sh)\b"),
    _sig("unshare-root", "container_escape", "high", "makes itself root in a new namespace",
         r"\bunshare\b[^\n]{0,80}(--map-root-user|\s-r\b)"),
    _sig("qemu-kvm", "container_escape", "medium", "starts a virtual machine",
         r"\bqemu-system-\w+[^\n]{0,200}(-enable-kvm|-hda|-drive)"),
    _sig("privileged-container", "container_escape", "medium", "starts a privileged container",
         r"\b(docker|podman)\s+run\b[^\n]{0,200}--privileged"),
    _sig("setcap-admin", "container_escape", "high", "grants a program admin powers",
         r"\bsetcap\b[^\n]{0,80}cap_sys_admin"),
    _sig("ld-preload", "persistence", "high", "forces a library into every program (rootkit trick)",
         r"(/etc/ld\.so\.preload|\bLD_PRELOAD=\S+\.so)"),

    # Staying on: added to cron, an SSH key, or a startup service that fetches code.
    _sig("cron-fetch", "persistence", "high", "scheduled job that downloads and runs code",
         r"^\s*([\d*/,-]+\s+){5}[^\n]{0,200}\b(curl|wget)\b[^\n]{0,200}\|\s*(ba)?sh"),
    _sig("ssh-key-append", "persistence", "high", "adds a key to SSH authorized_keys",
         r"(echo|printf|cat)\b[^\n]{0,400}>>\s*\S*\.ssh/authorized_keys"),

    # Hidden code: long encoded blobs fed into a decoder or a run call.
    _sig("long-b64-decode", "obfuscation", "medium", "long encoded blob being decoded",
         r"(base64_decode|atob|b64decode|FromBase64String)\s*\(\s*['\"][A-Za-z0-9+/=]{400,}"),
    _sig("hex-escapes", "obfuscation", "medium", "long run of hex-escaped text",
         r"(\\x[0-9a-f]{2}){60,}"),
    _sig("js-eval-decode", "obfuscation", "high", "JavaScript running decoded hidden code",
         r"\beval\s*\(\s*(atob|unescape|Buffer\.from)\s*\("),
]

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2}
# Inside a Java archive only strong signs count; a plugin calling exec() or decoding base64 is normal.
JAR_KINDS = {"reverse_shell", "miner", "container_escape", "webshell"}


# --------------------------------------------------------------- processes
@dataclass(frozen=True)
class ProcSign:
    key: str
    label: str
    severity: str
    rx: re.Pattern[str]
    where: str  # name | cmdline | exe


def _ps(key: str, label: str, severity: str, where: str, pattern: str) -> ProcSign:
    return ProcSign(key, label, severity, re.compile(pattern, re.I), where)


PROC_SIGNS: list[ProcSign] = [
    _ps("miner-name", "known crypto miner program", "critical", "name",
        r"^(xmrig|xmr-stak|ethminer|cgminer|bfgminer|cpuminer|minerd|nbminer|t-rex|lolminer|phoenixminer|nanominer|srbminer)"),
    _ps("miner-pool", "connected to a crypto-mining pool", "critical", "cmdline", r"stratum\d?\+(tcp|ssl|tls)://"),
    _ps("miner-args", "crypto miner options", "high", "cmdline", r"(--donate-level|--randomx|-a\s+(rx/0|cn/r|kawpow|ethash))\b"),
    _ps("bash-dev-tcp", "shell connected to a remote address", "critical", "cmdline", r"/dev/(tcp|udp)/\S+"),
    _ps("nc-exec", "netcat handing out a shell", "critical", "cmdline",
        r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s*(/bin/(ba)?sh|cmd|powershell)"),
    _ps("py-pty", "Python shell wired to a socket", "critical", "cmdline", r"python\d?(\.\d+)?\s+-c\s.*socket.*(pty\.spawn|subprocess|dup2)"),
    _ps("ps-encoded", "PowerShell running an encoded command", "high", "cmdline",
        r"powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{40,}"),
    _ps("curl-pipe-sh", "downloads a script and runs it", "high", "cmdline", r"\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b"),
    _ps("tmp-exe", "program running from a temporary folder", "high", "exe", r"^(/tmp|/dev/shm|/var/tmp)/"),
    _ps("deleted-exe", "program whose file was deleted after it started", "high", "exe", r"\(deleted\)$"),
    _ps("proot", "fake root system (proot)", "high", "name", r"^proot$"),
]


def check_process(p: Proc) -> list[dict[str, str]]:
    """Signs that a running program is hostile. The command line is matched, never shown whole."""
    name = Path(p.name or p.exe).name.lower()
    name = name[:-4] if name.endswith(".exe") else name
    cmd = " ".join(p.cmdline)
    hits = []
    for s in PROC_SIGNS:
        text = {"name": name, "cmdline": cmd, "exe": p.exe or ""}[s.where]
        if text and s.rx.search(text):
            hits.append({"key": s.key, "label": s.label, "severity": s.severity})
    return hits


# ------------------------------------------------------------------- files
def _glob_match(path: str, patterns: Iterable[str]) -> bool:
    p = path.replace("\\", "/")
    return any(fnmatch.fnmatch(p, pat.replace("\\", "/")) for pat in patterns)


def _own_dirs() -> list[str]:
    """SentrAI's own install and data folders: never scanned (its signature lists match themselves)."""
    dirs = [MVP_DIR, Path(os.environ.get("CACTAI_QUARANTINE", CORE_DIR / "data" / "quarantine"))]
    return [os.path.normcase(os.path.abspath(d)) for d in dirs]


def _wanted(f: Path) -> str | None:
    """'text', 'jar' or None for a file name. Extensionless files are checked later for a shebang."""
    name = f.name.lower()
    if any(fnmatch.fnmatch(name, pat) for pat in SKIP_FILES):
        return None
    ext = f.suffix.lower()
    if ext in ARCHIVE_EXT:
        return "jar"
    if ext in SCRIPT_EXT or ext in CONFIG_EXT or name in (".htaccess", ".user.ini", "crontab", ".bashrc", ".profile"):
        return "text"
    if not ext or ext in (".bin", ".run"):
        return "maybe"
    return None


def walk(roots: Iterable[str], allow: Iterable[str] = (), limit: int = MAX_FILES) -> tuple[list[tuple[Path, str]], int]:
    """Files to check under the roots, with how many more were left unchecked because of the limit."""
    own = _own_dirs()
    allow = list(allow)
    out: list[tuple[Path, str]] = []
    seen: set[str] = set()
    over = 0
    for root in roots:
        root_p = Path(os.path.expandvars(os.path.expanduser(root)))
        if root_p.is_file():
            kind = _wanted(root_p) or "maybe"
            out.append((root_p, kind))
            continue
        for dirpath, dirnames, filenames in os.walk(root_p, onerror=lambda e: None, followlinks=False):
            here = os.path.normcase(os.path.abspath(dirpath))
            if any(here == o or here.startswith(o + os.sep) for o in own):
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            in_cron = Path(dirpath).name.lower() in CRON_DIRS
            for fn in filenames:
                f = Path(dirpath) / fn
                kind = _wanted(f)
                if kind is None and in_cron:
                    kind = "text"
                if kind is None or f.is_symlink():
                    continue
                key = os.path.normcase(str(f))
                if key in seen or (allow and _glob_match(str(f), allow)):
                    continue
                seen.add(key)
                if len(out) >= limit:
                    over += 1
                    continue
                out.append((f, kind))
    return out, over


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _snippet(text: str, start: int, end: int, homes: list[str]) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line = text[line_start:line_end if line_end != -1 else len(text)].strip()
    if len(line) > SNIPPET:
        at = max(0, start - line_start - 40)
        line = ("…" if at else "") + line[at:at + SNIPPET] + "…"
    return _hide_homes_in(mask(line), homes)


def _hide_homes_in(text: str, homes: list[str]) -> str:
    """Home folders anywhere in a line (not only at the start) become ~."""
    for h in sorted(homes, key=len, reverse=True):
        if h:
            text = re.sub(re.escape(h) + r"(?=$|[/\\\s'\"])", "~", text, flags=re.I)
    return text


def match_text(text: str, kinds: set[str] | None = None) -> list[tuple[Signature, re.Match[str]]]:
    hits = []
    for s in SIGNATURES:
        if kinds is not None and s.kind not in kinds:
            continue
        m = s.rx.search(text)
        if m:
            hits.append((s, m))
    hits.sort(key=lambda h: SEVERITY_RANK[h[0].severity])
    return hits[:MAX_HITS_PER_FILE]


def _read(f: Path, max_bytes: int) -> bytes | None:
    try:
        if f.stat().st_size > max_bytes or f.stat().st_size == 0:
            return None
        return f.read_bytes()
    except OSError:
        return None


def scan_file(f: Path, kind: str, max_bytes: int, bad_hashes: set[str], homes: list[str]) -> list[dict[str, Any]]:
    data = _read(f, max_bytes)
    if data is None:
        return []
    digest = hashlib.sha256(data).hexdigest()
    shown = hide_home(str(f), homes)
    base = {"path": shown, "real_path": str(f), "sha256": digest, "size": len(data)}
    out: list[dict[str, Any]] = []
    if digest in bad_hashes:
        out.append({**base, "key": "known-bad-hash", "kind": "known_malware", "severity": "critical",
                    "label": "file matches a known malware fingerprint", "line": None, "snippet": ""})
    if kind == "jar":
        return out + _scan_jar(f, base)
    if kind == "maybe" and not (data.startswith(b"#!") or f.parent.name.lower() in CRON_DIRS):
        return out
    if b"\x00" in data[:8192]:
        return out  # binary
    text = data.decode("utf-8", errors="replace")
    for s, m in match_text(text):
        out.append({**base, "key": s.key, "kind": s.kind, "severity": s.severity, "label": s.label,
                    "line": _line_of(text, m.start()), "snippet": _snippet(text, m.start(), m.end(), homes)})
    return out


def _scan_jar(f: Path, base: dict[str, Any]) -> list[dict[str, Any]]:
    """Read the text and class files inside a Java archive for strong signs only."""
    out: list[dict[str, Any]] = []
    try:
        with zipfile.ZipFile(f) as z:
            for info in z.infolist()[:5000]:
                if info.is_dir() or info.file_size > MAX_JAR_ENTRY_BYTES:
                    continue
                n = info.filename.lower()
                if not n.endswith((".class", ".yml", ".yaml", ".properties", ".sh", ".js", ".json", ".txt")):
                    continue
                with z.open(info) as fh:
                    text = fh.read(MAX_JAR_ENTRY_BYTES).decode("latin-1")
                for s, m in match_text(text, JAR_KINDS):
                    out.append({**base, "key": s.key, "kind": s.kind, "severity": s.severity, "label": s.label,
                                "line": None, "entry": info.filename[:200],
                                "snippet": mask(re.sub(r"[^\x20-\x7e]", "·", m.group(0)))[:SNIPPET]})
                    if len(out) >= MAX_HITS_PER_FILE:
                        return out
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError):
        pass  # unreadable or encrypted archive: nothing to say
    return out


def scan(roots: Iterable[str], cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Scan the given folders once. ``cfg`` is ``threat_scan`` from the system profile."""
    cfg = cfg or {}
    roots = [r for r in roots if r]
    started = time.time()
    homes = procscan._homes()
    max_bytes = int(float(cfg.get("max_file_mb", MAX_FILE_BYTES / 1024 / 1024)) * 1024 * 1024)
    bad = {h.lower() for h in cfg.get("known_bad_sha256") or [] if isinstance(h, str)}
    files, over = walk(roots, cfg.get("allow") or [])
    findings: list[dict[str, Any]] = []
    missing = [hide_home(r, homes) for r in roots if not Path(os.path.expanduser(r)).exists()]
    for f, kind in files:
        findings += scan_file(f, kind, max_bytes, bad, homes)
        if len(findings) >= MAX_FINDINGS:
            break
    findings.sort(key=lambda x: (SEVERITY_RANK.get(x["severity"], 9), x["path"]))
    counts = {s: sum(1 for x in findings if x["severity"] == s) for s in SEVERITY_RANK}
    return {"roots": [hide_home(r, homes) for r in roots], "missing": missing, "files_checked": len(files),
            "files_not_checked": over, "findings": findings[:MAX_FINDINGS], "counts": counts,
            "took_s": round(time.time() - started, 2)}
