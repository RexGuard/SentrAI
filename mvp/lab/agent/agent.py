"""The SentrAI agent: what runs on each machine that reports to a central SentrAI panel.

It does these jobs and nothing else:

  * sends this machine's approved logs to the panel (the collector, with this machine's own key)
  * puts the panel's blocks for this machine into the local firewall, and takes them out again
  * once a minute, tells the panel which services listen here (names and ports only, services.py)
  * runs the threat scans and backups the panel asks for, on folders set here (tasks.py)

The panel does the scoring and decides; the agent only makes outgoing HTTPS calls, so no port is
opened on the machine. If the panel cannot be reached, blocks already in place stay for
CACTAI_AGENT_OFFLINE_HOLD_H hours (default 24) and are then removed, so a lost panel never leaves
a block in force forever.

  python -m agent join --panel https://panel.example.com:8000 --code ABCD-EFGH-JKLM [--name web-01]
  python -m agent run                 send logs and enforce blocks (dry run unless CACTAI_FIREWALL_ENFORCE=1)
  python -m agent status              what this machine joined as, and what it has blocked

Settings: CACTAI_FIREWALL (auto | nftables | iptables | netsh | off), CACTAI_FIREWALL_ENFORCE (0 = only
log the commands), PROTECTED_IPS (never blocked; the panel's own address is always added),
CACTAI_AGENT_FILE (where the key is kept, default next to the settings file, mode 0600),
CACTAI_AGENT_CA (the panel's certificate when it is self-signed).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests

LAB_DIR = Path(__file__).resolve().parents[1]
MVP_DIR = LAB_DIR.parent
sys.path.insert(0, str(LAB_DIR))
sys.path.append(str(MVP_DIR))
sys.path.append(str(MVP_DIR / "core"))
import cactai_config  # noqa: E402
from app import firewall, protect  # noqa: E402  (the core's firewall commands and safety checks)

POLL_S = 5.0
SERVICES_EVERY_S = 60.0
OFFLINE_HOLD_H = float(os.environ.get("CACTAI_AGENT_OFFLINE_HOLD_H", "24") or 24)


class AgentError(Exception):
    pass


def agent_file() -> Path:
    env = os.environ.get("CACTAI_AGENT_FILE", "").strip()
    return Path(env) if env else cactai_config.config_path().parent / "agent.json"


def load() -> dict[str, Any]:
    try:
        return json.loads(agent_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save(data: dict[str, Any]) -> Path:
    path = agent_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path


def check_panel_url(url: str, allow_http: bool = False) -> str:
    """The panel's address. HTTPS only, so the key and the logs never cross the network in clear text;
    plain http is accepted for this machine itself, or with --allow-http on a private test network."""
    url = (url or "").strip().rstrip("/")
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise AgentError(f"panel address must look like https://panel.example.com:8000 (got {url!r})")
    if u.scheme == "http" and not allow_http and u.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise AgentError("the panel must be reached over https:// (use --allow-http only on a private test network)")
    return url


def panel_ips(url: str) -> set[str]:
    """The panel's own addresses: never blocked, or the agent would cut itself off."""
    host = urlparse(url).hostname or ""
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return set()


def _verify(data: dict[str, Any]) -> str | bool:
    return data.get("ca") or os.environ.get("CACTAI_AGENT_CA") or True


def join(panel: str, code: str, name: str | None = None, allow_http: bool = False, ca: str | None = None,
         post: Callable[..., Any] = requests.post) -> dict[str, Any]:
    """Swap a one-time join code for this machine's own key and keep it in the agent file."""
    panel = check_panel_url(panel, allow_http)
    host = (name or os.environ.get("CACTAI_HOST") or socket.gethostname() or "").strip()
    verify = ca or os.environ.get("CACTAI_AGENT_CA") or True
    try:
        r = post(f"{panel}/fleet/enrol", json={"code": code, "host": host}, timeout=10, verify=verify)
    except requests.RequestException as exc:
        raise AgentError(f"could not reach the panel at {panel}: {exc.__class__.__name__}") from exc
    if r.status_code != 200:
        try:
            detail = r.json().get("detail")
        except ValueError:
            detail = r.text[:200]
        raise AgentError(f"the panel refused to join this machine ({r.status_code}): {detail}")
    got = r.json()
    data = {"panel": panel, "agent_id": got["agent_id"], "host": got["host"], "key": got["key"],
            "allow_http": allow_http, "ca": ca or None, "blocked": [], "last_ok": time.time()}
    save(data)
    return data


class Enforcer:
    """Keeps the local firewall equal to the panel's block list for this machine."""

    def __init__(self, backend: str | None, enforce: bool, protected: set[str],
                 runner: firewall.Runner = firewall.run_command, hold_s: float = OFFLINE_HOLD_H * 3600,
                 applied: list[str] | None = None, last_ok: float | None = None, clock: Callable[[], float] = time.time):
        self.backend = backend
        self.enforce = enforce
        self.protected = protected
        self.runner = runner
        self.hold_s = hold_s
        self.clock = clock
        self.applied: set[str] = set(applied or [])
        self.last_ok = last_ok if last_ok is not None else clock()
        self.log: list[str] = []
        self._ready = False

    def _run(self, args: list[str], probe: bool = False) -> int:
        if not self.enforce:
            self.log.append("dry run: " + " ".join(args))
            return 0
        rc, out = self.runner(args)
        if rc != 0 and not probe:
            self.log.append(f"failed ({rc}): {' '.join(args)}: {out[:200]}")
        return rc

    def _setup(self) -> bool:
        if not self._ready:
            self._ready = all(self._run(cmd) == 0 for cmd in firewall.setup_commands(self.backend))
        return self._ready

    def _add(self, ip: str) -> bool:
        reason = firewall.unsafe_reason(ip, self.protected)
        if reason:
            self.log.append(f"not blocking {ip}: {reason}")
            return False
        if self.backend is None:
            self.log.append(f"would block {ip} (no firewall chosen: CACTAI_FIREWALL=off)")
            return True
        add, check, _ = firewall.block_commands(self.backend, ip)
        if not self._setup():
            return False
        if self.enforce and self._run(check, probe=True) == 0:
            return True  # already there (e.g. after a restart)
        return self._run(add) == 0 and (not self.enforce or self._run(check) == 0)

    def _remove(self, ip: str) -> None:
        if self.backend is not None:
            self._run(firewall.block_commands(self.backend, ip)[2])

    def sync(self, wanted: set[str] | None) -> dict[str, list[str]]:
        """Bring the firewall in line with the panel's list; None means the panel could not be reached."""
        now = self.clock()
        if wanted is None:
            if self.applied and now - self.last_ok > self.hold_s:
                self.log.append(f"panel unreachable for over {self.hold_s / 3600:g} h: removing all blocks")
                wanted = set()
            else:
                return {"added": [], "removed": []}
        else:
            self.last_ok = now
        added = [ip for ip in sorted(wanted - self.applied) if self._add(ip)]
        removed = sorted(self.applied - wanted)
        for ip in removed:
            self._remove(ip)
        self.applied = (self.applied | set(added)) - set(removed)
        return {"added": added, "removed": removed}


def make_enforcer(data: dict[str, Any], runner: firewall.Runner = firewall.run_command) -> Enforcer:
    backend = firewall.resolve_backend(os.environ.get("CACTAI_FIREWALL", "auto"))
    enforce = os.environ.get("CACTAI_FIREWALL_ENFORCE", "0").strip().lower() in ("1", "true", "yes", "on")
    protected = (protect.split(os.environ.get("PROTECTED_IPS", "127.0.0.1,::1,localhost"))
                 | protect.split(os.environ.get("INFRA_ALLOWLIST", "")) | panel_ips(data["panel"]))
    return Enforcer(backend, enforce, protected, runner, applied=data.get("blocked"), last_ok=data.get("last_ok"))


def fetch_blocklist(data: dict[str, Any], session: requests.Session) -> set[str] | None:
    """This machine's blocked addresses from the panel, or None when it cannot be reached.
    A revoked key raises, so the agent stops instead of guessing."""
    try:
        r = session.get(f"{data['panel']}/blocklist", headers={"Authorization": f"Bearer {data['key']}"},
                        timeout=5, verify=_verify(data))
    except requests.RequestException:
        return None
    if r.status_code == 401:
        raise AgentError("the panel no longer accepts this machine's key (revoked?): join again")
    if r.status_code != 200:
        return None
    return {str(ip) for ip in r.json().get("ips", [])}


def report_services(data: dict[str, Any], session: requests.Session,
                    found: Callable[[], list[dict[str, Any]]] | None = None) -> bool:
    """Tell the panel what runs on this machine (names and ports only). True when it was accepted."""
    from agent import services

    try:
        r = session.post(f"{data['panel']}/fleet/services", json={"services": (found or services.listening)()},
                         headers={"Authorization": f"Bearer {data['key']}"}, timeout=5, verify=_verify(data))
    except requests.RequestException:
        return False
    return r.status_code == 200


def enforce_loop(data: dict[str, Any], enforcer: Enforcer, stop: threading.Event, poll_s: float = POLL_S) -> None:
    session = requests.Session()
    next_services = 0.0
    while not stop.is_set():
        if time.monotonic() >= next_services:
            next_services = time.monotonic() + (SERVICES_EVERY_S if report_services(data, session) else poll_s * 2)
        change = enforcer.sync(fetch_blocklist(data, session))
        for line in enforcer.log:
            print(f"[agent] {line}", flush=True)
        enforcer.log.clear()
        if change["added"] or change["removed"]:
            print(f"[agent] blocked {change['added'] or '-'}, unblocked {change['removed'] or '-'}", flush=True)
        if change["added"] or change["removed"] or data.get("last_ok") != enforcer.last_ok:
            data.update(blocked=sorted(enforcer.applied), last_ok=enforcer.last_ok)
            save(data)  # blocks in force survive an agent restart
        stop.wait(poll_s)


def run(data: dict[str, Any]) -> None:
    from collector.collector import Collector
    from collector import paths

    enforcer = make_enforcer(data)
    mode = (f"{enforcer.backend}, {'enforcing' if enforcer.enforce else 'dry run'}" if enforcer.backend
            else "no firewall (CACTAI_FIREWALL=off)")
    print(f"[agent] {data['host']} -> {data['panel']} (blocks: {mode})", flush=True)
    collector = Collector(data["panel"], paths.logs_dir(), token=data["key"], host=data["host"])
    collector.session.verify = _verify(data)
    stop = threading.Event()
    threading.Thread(target=collector.run, name="collector", daemon=True).start()
    from agent import tasks
    threading.Thread(target=tasks.job_loop, args=(data, _verify(data), agent_file().parent, stop),
                     name="jobs", daemon=True).start()
    try:
        enforce_loop(data, enforcer, stop)
    finally:
        stop.set()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent", description="SentrAI agent for a central panel")
    sub = ap.add_subparsers(dest="cmd", required=True)
    j = sub.add_parser("join", help="join this machine to a panel with a one-time code")
    j.add_argument("--panel", required=True, help="the panel's core address, e.g. https://panel.example.com:8000")
    j.add_argument("--code", required=True, help="the join code from the panel's Machines page")
    j.add_argument("--name", help="this machine's name on the panel (default: its host name)")
    j.add_argument("--ca", help="the panel's certificate file, when it is self-signed")
    j.add_argument("--allow-http", action="store_true", help="accept plain http (private test networks only)")
    sub.add_parser("run", help="send logs and enforce this machine's blocks")
    sub.add_parser("status", help="show what this machine joined as")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "join":
            data = join(args.panel, args.code, args.name, args.allow_http, args.ca)
            print(f"[agent] joined {data['panel']} as {data['host']}; key saved in {agent_file()}")
            print("[agent] start it with: python -m agent run")
            return 0
        data = load()
        if not data.get("key"):
            print("[agent] this machine has not joined a panel yet: python -m agent join --panel URL --code CODE")
            return 1
        if args.cmd == "status":
            print(json.dumps({k: v for k, v in data.items() if k != "key"}, indent=2))
            return 0
        check_panel_url(data["panel"], data.get("allow_http", False))
        run(data)
        return 0
    except AgentError as exc:
        print(f"[agent] {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[agent] stopped.")
        return 0
