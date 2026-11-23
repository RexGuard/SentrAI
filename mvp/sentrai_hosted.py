"""`sentrai-hosted`: SentrAI as a hosted service, many companies on one server, each kept apart.

Every company gets its own data folder and its own core process: its machines, incidents, audit record, Coach data,
Company Rules and accounts are files only that process opens, and no request can name another company's data. One
gateway (web/gateway.py) answers for all of them and sends each request to the right core by its address:

    https://acme.sentrai.pro            Acme's web panel (the same React console as a company's own panel)
    https://acme.sentrai.pro:8443       Acme's agents (the machines Acme installed the agent on)

The cores run in hosted mode (core/app/hosted.py): nothing scans, backs up or changes SentrAI's own server, and a
company cannot point SentrAI at a private address. See docs/hosted.md for the set-up and how to run it.

    python sentrai_hosted.py add "Acme Pte Ltd" [--slug acme] [--owner owner@acme.com]
    python sentrai_hosted.py list
    python sentrai_hosted.py pause SLUG | resume SLUG
    python sentrai_hosted.py remove SLUG            set its folder aside (never deleted), take its address off
    python sentrai_hosted.py setup-code SLUG        a new one-time code for the company's first Owner
    python sentrai_hosted.py sentrai SLUG ARGS...   the `sentrai` team command line, for that company
    python sentrai_hosted.py run                    start every company's core and the gateway (systemd runs this)
    python sentrai_hosted.py check                  is each company's core answering?

Settings (environment):
    SENTRAI_HOSTED_HOME     where the companies' folders and companies.json live (default /var/lib/sentrai-hosted
                            when it exists, else ~/.sentrai-hosted)
    SENTRAI_HOSTED_DOMAIN   the domain under which each company gets its own name (default sentrai.pro)
    SENTRAI_HOSTED_FIRST_PORT  the first local port for the companies' cores (default 9100; 127.0.0.1 only)
    SENTRAI_HOSTED_SHARE    variables every company's core gets from this server's environment (default
                            ANTHROPIC_API_KEY,SENTRAI_AI_MONTHLY_BUDGET_USD), comma-separated
    SENTRAI_HOSTED_PYTHON   the Python that runs the cores (default core/.venv's, else this one)
    SENTRAI_HOSTED_NOTIFIER on (default when notifier/.venv exists) | off: one notifier per company for its alerts
    and for `run`, the gateway's: SENTRAI_HOSTED_WEB_PORT (8080), SENTRAI_HOSTED_AGENT_PORT (8443),
    SENTRAI_HOSTED_BIND (0.0.0.0), SENTRAI_HOSTED_TLS_CERT / SENTRAI_HOSTED_TLS_KEY (a certificate for
    *.<domain>: the web listener and the agents' listener both use it, and agents pin it).

Stdlib only, like sentrai_config.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

MVP_DIR = Path(__file__).resolve().parent
REGISTRY = "companies.json"
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$")
# Names that are SentrAI's own, or that a person could mistake for SentrAI's.
RESERVED = frozenset({"www", "api", "app", "apps", "panel", "admin", "administrator", "root", "signup", "sign-up",
                      "login", "signin", "sign-in", "account", "accounts", "billing", "mail", "email", "smtp", "status",
                      "docs", "help", "support", "security", "sentrai", "sentry", "hosted", "static", "assets",
                      "cdn", "dashboard", "console", "agents", "agent", "test", "demo", "staging", "dev"})
STATUSES = ("active", "paused", "removed")
DEFAULT_SHARE = "ANTHROPIC_API_KEY,SENTRAI_AI_MONTHLY_BUDGET_USD"
# The only variables a company's processes get from this server, besides SENTRAI_HOSTED_SHARE.
BASE_KEEP = ("PATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TZ", "PYTHONUTF8", "SYSTEMROOT", "SystemRoot",
             "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
             "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")


class HostedError(ValueError):
    pass


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def home(env: dict[str, str] | None = None) -> Path:
    env = os.environ if env is None else env
    if env.get("SENTRAI_HOSTED_HOME"):
        return Path(env["SENTRAI_HOSTED_HOME"]).expanduser()
    server = Path("/var/lib/sentrai-hosted")
    return server if server.is_dir() else Path.home() / ".sentrai-hosted"


def domain(env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    return (env.get("SENTRAI_HOSTED_DOMAIN") or "sentrai.pro").strip().strip(".").lower()


def slug_for(name: str) -> str:
    """A web-address name from a company name: "Acme Pte. Ltd." -> "acme-pte-ltd"."""
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:30].strip("-")


def check_slug(slug: str) -> str:
    slug = (slug or "").strip().lower()
    if not SLUG_RE.match(slug) or "--" in slug:
        raise HostedError("The web address name must be 3 to 30 letters, numbers or dashes, like acme or acme-sg.")
    if slug in RESERVED:
        raise HostedError(f"{slug} is kept for SentrAI itself. Pick another name.")
    return slug


@dataclass
class Company:
    slug: str
    name: str
    port: int
    status: str = "active"
    owner_email: str = ""
    created_at: str = field(default_factory=_now)
    changed_at: str = ""
    source: str = "cli"  # cli | signup
    note: str = ""

    def public(self, reg: "Registry") -> dict[str, Any]:
        return {**asdict(self), "web": web_address(self.slug, reg.domain, reg.web_port),
                "agents": agents_address(self.slug, reg.domain, reg.agent_port)}


def web_address(slug: str, dom: str, port: int | None = None) -> str:
    return f"https://{slug}.{dom}" + (f":{port}" if port and port != 443 else "")


def agents_address(slug: str, dom: str, port: int = 8443) -> str:
    return f"https://{slug}.{dom}:{port}"


class Registry:
    """companies.json: who is on this server, at which local port, and whether they are on. Written whole each time
    (it is small), under a lock, readable only by the service account."""

    def __init__(self, root: Path | None = None, env: dict[str, str] | None = None) -> None:
        self.env = dict(os.environ if env is None else env)
        self.root = Path(root) if root is not None else home(self.env)
        self.path = self.root / REGISTRY
        self.domain = domain(self.env)
        self.first_port = int(self.env.get("SENTRAI_HOSTED_FIRST_PORT") or 9100)
        # The ports the world uses (a proxy in front may differ from the gateway's own listeners).
        self.web_port = int(self.env.get("SENTRAI_HOSTED_PUBLIC_WEB_PORT") or 443)
        self.agent_port = int(self.env.get("SENTRAI_HOSTED_PUBLIC_AGENT_PORT") or self.env.get("SENTRAI_HOSTED_AGENT_PORT") or 8443)
        self._lock = threading.Lock()

    # -- storage
    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 1, "companies": {}}
        if not isinstance(data, dict) or not isinstance(data.get("companies"), dict):
            raise HostedError(f"{self.path} is not a SentrAI companies list")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def companies(self, include_removed: bool = False) -> list[Company]:
        rows = [Company(**{k: v for k, v in c.items() if k in Company.__dataclass_fields__})
                for c in self._read()["companies"].values()]
        return sorted((c for c in rows if include_removed or c.status != "removed"), key=lambda c: c.slug)

    def get(self, slug: str) -> Company | None:
        c = self._read()["companies"].get((slug or "").strip().lower())
        return Company(**{k: v for k, v in c.items() if k in Company.__dataclass_fields__}) if c else None

    def folder(self, slug: str) -> Path:
        return self.root / "companies" / slug

    # -- changes
    def add(self, name: str, slug: str = "", owner_email: str = "", source: str = "cli", note: str = "") -> Company:
        name = " ".join((name or "").split())[:80]
        if len(name) < 2:
            raise HostedError("Give the company's name.")
        slug = check_slug(slug or slug_for(name))
        owner_email = (owner_email or "").strip().lower()
        if owner_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", owner_email):
            raise HostedError(f"{owner_email} is not an email address.")
        with self._lock:
            data = self._read()
            if slug in data["companies"]:
                raise HostedError(f"{slug}.{self.domain} is taken. Pick another name.")
            used = {int(c.get("port", 0)) for c in data["companies"].values()}
            port = next(p for p in range(self.first_port, self.first_port + 50000) if p not in used)
            company = Company(slug=slug, name=name, port=port, owner_email=owner_email, source=source, note=note)
            make_folder(self.folder(slug), self.env)
            data["companies"][slug] = asdict(company)
            self._write(data)
        return company

    def set_status(self, slug: str, status: str) -> Company:
        if status not in STATUSES:
            raise HostedError(f"status is one of {', '.join(STATUSES)}")
        with self._lock:
            data = self._read()
            c = data["companies"].get((slug or "").strip().lower())
            if c is None:
                raise HostedError(f"No company called {slug} on this server.")
            if c["status"] == "removed" and status != "removed":
                raise HostedError(f"{slug} was removed. Its folder was set aside in {self.root / 'removed'}.")
            c["status"], c["changed_at"] = status, _now()
            if status == "removed":
                gone = self.folder(c["slug"])
                if gone.exists():
                    dest = self.root / "removed" / f"{c['slug']}-{time.strftime('%Y%m%d-%H%M%S')}"
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(gone), str(dest))
                    c["note"] = (c.get("note") or "") + f" folder kept in {dest}"
                # The address is free again for a new company; the old record stays under another key.
                data["companies"][f"{c['slug']}~removed~{int(time.time())}"] = c
                del data["companies"][c["slug"]]
            self._write(data)
            return Company(**{k: v for k, v in c.items() if k in Company.__dataclass_fields__})

    def mtime(self) -> float:
        try:
            return self.path.stat().st_mtime
        except FileNotFoundError:
            return 0.0


def make_folder(folder: Path, env: dict[str, str] | None = None) -> None:
    """A new company's data root, with its own API token in its own settings file."""
    folder.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(folder, 0o700)
    except OSError:
        pass
    for sub in ("core", "logs", "run"):
        (folder / sub).mkdir(exist_ok=True)
    run_tool(folder, ["sentrai_config.py", "token"], env)  # makes and saves the company's own token


def run_tool(folder: Path, args: list[str], env: dict[str, str] | None = None,
             stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run one of mvp/'s stdlib tools as that company (its settings file, its accounts file)."""
    out = subprocess.run([sys.executable, *args], cwd=str(MVP_DIR), env=tool_env(folder, env), input=stdin,
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise HostedError((out.stderr or out.stdout).strip() or f"{args[0]} failed")
    return out


def tool_env(folder: Path, env: dict[str, str] | None = None) -> dict[str, str]:
    base = os.environ if env is None else env
    keep = {k: v for k, v in base.items() if k in BASE_KEEP}
    return {**keep, "HOME": str(folder), "USERPROFILE": str(folder), "SENTRAI_HOME": str(folder),
            "SENTRAI_CONFIG": str(folder / "config.json"), "SENTRAI_MIGRATE": "0", "PYTHONUTF8": "1"}


def company_env(reg: Registry, c: Company, base: dict[str, str] | None = None) -> dict[str, str]:
    """Everything one company's core and notifier get: their own folder, port and addresses, and nothing of this
    server's except the few variables in BASE_KEEP and SENTRAI_HOSTED_SHARE."""
    base = dict(os.environ if base is None else base)
    folder = reg.folder(c.slug)
    share = [s.strip() for s in (base.get("SENTRAI_HOSTED_SHARE") or DEFAULT_SHARE).split(",") if s.strip()]
    env = {**tool_env(folder, base), **{k: base[k] for k in share if base.get(k)}}
    core_url = f"http://127.0.0.1:{c.port}"
    env.update({
        "SENTRAI_HOSTED": "1", "SENTRAI_COMPANY": c.slug,
        "SENTRAI_DB": str(folder / "core" / "sentrai.db"),
        "SENTRAI_LAB_LOGS": str(folder / "logs"),
        "SENTRAI_CORE_HOST": "127.0.0.1", "SENTRAI_CORE_PORT": str(c.port), "SENTRAI_CORE_URL": core_url,
        "SENTRAI_PANEL_PORT": "",  # agents reach this core through the gateway, never directly
        "SENTRAI_PANEL_URL": agents_address(c.slug, reg.domain, reg.agent_port),
        "SENTRAI_PUBLIC_URL": web_address(c.slug, reg.domain, reg.web_port),
        "SENTRAI_FIREWALL": "off",  # the core never changes this server's firewall; agents block on their machines
        "SENTRAI_RISK_SCOPE": "host",
        "SENTRAI_THREAT_PATHS": "", "SENTRAI_DEP_PATHS": "",
        "NOTIFIER_WITNESS_FILE": str(folder / "notifier" / "last_witness.txt"),
        "DEMO_SPEED": "1",
    })
    cert = base.get("SENTRAI_HOSTED_TLS_CERT", "")
    if cert:
        env["SENTRAI_PANEL_CERT"] = cert  # only read for the pin new machines get with their join code
    return env


def company_token(reg: Registry, slug: str) -> str:
    return run_tool(reg.folder(slug), ["sentrai_config.py", "token"], reg.env).stdout.strip()


def setup_code(reg: Registry, slug: str) -> str:
    """A one-time code for the company's first Owner (the panel's first screen asks for it)."""
    out = run_tool(reg.folder(slug), ["-c", "import sentrai_accounts as a; print('' if a.has_accounts() else a.new_setup_code())"], reg.env)
    code = out.stdout.strip()
    if not code:
        raise HostedError("This company already has an Owner. They invite everyone else on the Team page; "
                          f"`sentrai-hosted sentrai {slug} team reset EMAIL` gives an Owner a new password.")
    return code


def make_owner(reg: Registry, slug: str, email: str, password: str, name: str = "") -> dict[str, Any]:
    """The company's first Owner, from a sign-up form (the password never touches the command line)."""
    code = ("import json, sys, sentrai_accounts as a; p = sys.stdin.readline().rstrip('\\r\\n'); "
            f"print(json.dumps(a.make_owner({email!r}, p, {name!r})))")
    try:
        return json.loads(run_tool(reg.folder(slug), ["-c", code], reg.env, stdin=password + "\n").stdout)
    except HostedError as e:
        raise HostedError(str(e).splitlines()[-1].split(": ", 1)[-1]) from None


# -- the processes ------------------------------------------------------------------------------------------------

def core_python(env: dict[str, str] | None = None) -> str:
    env = os.environ if env is None else env
    if env.get("SENTRAI_HOSTED_PYTHON"):
        return env["SENTRAI_HOSTED_PYTHON"]
    for p in (MVP_DIR / "core" / ".venv" / "bin" / "python", MVP_DIR / "core" / ".venv" / "Scripts" / "python.exe"):
        if p.exists():
            return str(p)
    return sys.executable


def notifier_python(env: dict[str, str] | None = None) -> str | None:
    env = os.environ if env is None else env
    if (env.get("SENTRAI_HOSTED_NOTIFIER") or "").lower() in ("off", "0", "no", "false"):
        return None
    for p in (MVP_DIR / "notifier" / ".venv" / "bin" / "python",
              MVP_DIR / "notifier" / ".venv" / "Scripts" / "python.exe"):
        if p.exists():
            return str(p)
    return sys.executable if (env.get("SENTRAI_HOSTED_NOTIFIER") or "").lower() in ("on", "1", "yes") else None


@dataclass
class Proc:
    kind: str
    slug: str
    popen: subprocess.Popen | None = None
    failures: int = 0
    next_start: float = 0.0
    started_at: float = 0.0


class Supervisor:
    """Keeps one core (and one notifier) running per active company; follows companies.json as it changes."""

    def __init__(self, reg: Registry, base_env: dict[str, str] | None = None, log: Callable[[str], None] = print,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.reg = reg
        self.base = dict(os.environ if base_env is None else base_env)
        self.log = log
        self.clock = clock
        self.procs: dict[tuple[str, str], Proc] = {}
        self._stop = threading.Event()

    def wanted(self) -> dict[tuple[str, str], Company]:
        out: dict[tuple[str, str], Company] = {}
        with_notifier = notifier_python(self.base) is not None
        for c in self.reg.companies():
            if c.status == "active":
                out[("core", c.slug)] = c
                if with_notifier:
                    out[("notifier", c.slug)] = c
        return out

    def command(self, kind: str) -> tuple[list[str], Path]:
        if kind == "core":
            return [core_python(self.base), "-m", "app.serve"], MVP_DIR / "core"
        return [notifier_python(self.base) or sys.executable, "notifier.py"], MVP_DIR / "notifier"

    def _start(self, key: tuple[str, str], c: Company) -> None:
        kind, slug = key
        p = self.procs.setdefault(key, Proc(kind, slug))
        if self.clock() < p.next_start:
            return
        cmd, cwd = self.command(kind)
        folder = self.reg.folder(slug)
        (folder / "run").mkdir(parents=True, exist_ok=True)
        out = open(folder / "run" / f"{kind}.log", "ab")
        try:
            p.popen = subprocess.Popen(cmd, cwd=str(cwd), env=company_env(self.reg, c, self.base), stdout=out,
                                       stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        finally:
            out.close()
        p.started_at = self.clock()
        self.log(f"[hosted] started {kind} for {slug} (pid {p.popen.pid}, port {c.port})")

    def _stop_proc(self, p: Proc, why: str) -> None:
        if p.popen is not None and p.popen.poll() is None:
            p.popen.terminate()
            try:
                p.popen.wait(10)
            except subprocess.TimeoutExpired:
                p.popen.kill()
            self.log(f"[hosted] stopped {p.kind} for {p.slug} ({why})")
        p.popen = None

    def step(self) -> None:
        """One look: start what should run, restart what died (waiting longer after each crash), stop the rest."""
        want = self.wanted()
        for key, p in list(self.procs.items()):
            if key not in want:
                self._stop_proc(p, "paused or removed")
                del self.procs[key]
        for key, c in want.items():
            p = self.procs.get(key)
            if p is not None and p.popen is not None:
                code = p.popen.poll()
                if code is None:
                    if self.clock() - p.started_at > 120:
                        p.failures = 0  # it has stayed up: the next crash starts the wait over
                    continue
                p.failures += 1
                p.next_start = self.clock() + min(300, 2 ** p.failures)
                p.popen = None
                self.log(f"[hosted] {key[0]} for {key[1]} stopped (exit {code}); starting again in "
                         f"{min(300, 2 ** p.failures)} s")
                continue
            self._start(key, c)

    def run(self, every: float = 3.0) -> None:
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as e:  # noqa: BLE001 - a bad companies.json must not stop the companies that run
                self.log(f"[hosted] could not check the companies: {e}")
            self._stop.wait(every)
        for p in list(self.procs.values()):
            self._stop_proc(p, "shutting down")

    def stop(self) -> None:
        self._stop.set()


def check(reg: Registry, timeout: float = 3.0) -> list[dict[str, Any]]:
    rows = []
    for c in reg.companies():
        ok = False
        if c.status == "active":
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{c.port}/health", timeout=timeout) as r:
                    ok = json.loads(r.read()).get("ok") is True
            except (OSError, ValueError):
                ok = False
        rows.append({"slug": c.slug, "status": c.status, "port": c.port, "answering": ok})
    return rows


# -- command line -------------------------------------------------------------------------------------------------

def _table(rows: Iterable[list[Any]], head: list[str]) -> str:
    rows = [[str(x) for x in r] for r in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) if rows else len(h) for i, h in enumerate(head)]
    line = lambda r: "  ".join(x.ljust(w) for x, w in zip(r, widths)).rstrip()  # noqa: E731
    return "\n".join([line(head), *(line(r) for r in rows)])


def main(argv: list[str] | None = None, out=None) -> int:
    out = out or sys.stdout
    p = argparse.ArgumentParser(prog="sentrai-hosted", description=__doc__.splitlines()[0])
    p.add_argument("--json", action="store_true", help="print the raw answer")
    sub = p.add_subparsers(dest="cmd", required=True)
    a_add = sub.add_parser("add", help="a new company: its folder, its token, its address")
    a_add.add_argument("name")
    a_add.add_argument("--slug", default="")
    a_add.add_argument("--owner", default="", help="the owner's email, for the record")
    a_add.add_argument("--note", default="")
    sub.add_parser("list", help="the companies on this server")
    for name in ("pause", "resume", "remove", "setup-code", "token"):
        sp = sub.add_parser(name)
        sp.add_argument("slug")
    a_cli = sub.add_parser("sentrai", help="the sentrai team command line, for one company")
    a_cli.add_argument("slug")
    a_cli.add_argument("args", nargs=argparse.REMAINDER)
    sub.add_parser("run", help="start every company's core and the gateway")
    sub.add_parser("check", help="is each company's core answering?")
    a = p.parse_args(argv)
    reg = Registry()
    show = (lambda obj, text: print(json.dumps(obj, indent=2) if a.json else text, file=out))  # noqa: E731
    try:
        if a.cmd == "add":
            c = reg.add(a.name, a.slug, a.owner, note=a.note)
            code = setup_code(reg, c.slug)
            info = {**c.public(reg), "setup_code": code}
            show(info, f"Added {c.name}.\n  Web panel:  {info['web']}\n  Agents:     {info['agents']}\n"
                       f"  Owner's one-time setup code: {code}\n"
                       "  Send the owner the web address and the code: the panel's first screen creates their account."
                       "\n  (`sentrai-hosted run` picks the new company up within a few seconds.)")
        elif a.cmd == "list":
            rows = [c.public(reg) for c in reg.companies()]
            show(rows, _table([[r["slug"], r["name"], r["status"], r["port"], r["owner_email"] or "-",
                                r["created_at"][:10]] for r in rows],
                              ["NAME", "COMPANY", "STATUS", "PORT", "OWNER", "SINCE"]) if rows else "No companies yet.")
        elif a.cmd in ("pause", "resume", "remove"):
            c = reg.set_status(a.slug, {"pause": "paused", "resume": "active", "remove": "removed"}[a.cmd])
            show(asdict(c), f"{c.slug}: {c.status}" + (f" ({c.note.strip()})" if a.cmd == "remove" else ""))
        elif a.cmd == "setup-code":
            if reg.get(a.slug) is None:
                raise HostedError(f"No company called {a.slug} on this server.")
            code = setup_code(reg, a.slug)
            show({"setup_code": code}, f"Owner's one-time setup code for {a.slug}: {code}")
        elif a.cmd == "token":
            if reg.get(a.slug) is None:
                raise HostedError(f"No company called {a.slug} on this server.")
            show({"token": company_token(reg, a.slug)}, company_token(reg, a.slug))
        elif a.cmd == "sentrai":
            c = reg.get(a.slug)
            if c is None:
                raise HostedError(f"No company called {a.slug} on this server.")
            args = a.args[1:] if a.args[:1] == ["--"] else a.args
            return subprocess.call([sys.executable, str(MVP_DIR / "sentrai_cli.py"), *args], cwd=str(MVP_DIR),
                                   env=company_env(reg, c))
        elif a.cmd == "check":
            rows = check(reg)
            show(rows, _table([[r["slug"], r["status"], r["port"], "yes" if r["answering"] else "NO"] for r in rows],
                              ["NAME", "STATUS", "PORT", "ANSWERING"]) if rows else "No companies yet.")
            return 0 if all(r["answering"] for r in rows if r["status"] == "active") else 1
        elif a.cmd == "run":
            return run(reg)
    except HostedError as e:
        print(f"sentrai-hosted: {e}", file=sys.stderr)
        return 2
    return 0


def run(reg: Registry) -> int:
    sys.path.insert(0, str(MVP_DIR / "web"))
    import gateway  # web/gateway.py

    sup = Supervisor(reg)
    servers = gateway.start(reg, os.environ)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: sup.stop())
        except ValueError:
            pass
    print(f"[hosted] {len(reg.companies())} companies under {reg.root}; domain {reg.domain}", flush=True)
    try:
        sup.run()
    finally:
        for s in servers:
            s.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
