"""Hosted mode: one core per company on SentrAI's own servers (sentrai_hosted.py starts them).

In a company's own panel the core also looks after the machine it runs on: it scans that machine's processes,
folders and packages, backs up its folders, restores into any folder, and reads its log files. On SentrAI's
hosted service that machine is SentrAI's shared server, so none of that may happen there: a company's core only
works through the agents on the company's own computers. SENTRAI_HOSTED=1 (set by sentrai_hosted.py) turns this on:

  - the panel-machine endpoints answer 409 with a plain reason, for everyone (the token too);
  - the threat scan, process scan and backups refuse to run on this machine, also from Sentry's chat and the
    schedules;
  - the settings that point at this machine's files cannot be changed from the web panel, and the addresses the
    core will call (AI service, health page, email server, Slack) must be on the public internet, so a company
    cannot use our server to reach another company's core or anything else inside it.

Everything a company keeps (machines, incidents, the audit record, Coach data, Company Rules, accounts) already sits
in its own data root, read by its own process: hosted mode adds no shared state.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

ENV = "SENTRAI_HOSTED"

NOT_HERE = ("SentrAI's hosted service does not scan, back up or change the server it runs on: it only works "
            "on your own computers. Open the computer's page and use Check now, Back up or Look for threats there.")

# (method, path pattern) of the work that happens on the panel's own machine.
PANEL_WORK: tuple[tuple[str, re.Pattern[str]], ...] = tuple((m, re.compile(p)) for m, p in (
    ("POST", r"/system/scan"),                     # process scan of this machine
    ("POST", r"/threats/scan"),                    # threat scan of this machine's folders (any path in the body)
    ("POST", r"/threats/[^/]+/quarantine"),        # moves a file on this machine
    ("POST", r"/quarantine/[^/]+/restore"),        # puts it back
    ("POST", r"/deps/scan"),                       # this machine's packages
    ("POST", r"/backups"),                         # backs up this machine's folders
    ("POST", r"/backups/[^/]+/restore"),           # unpacks into any folder here
    ("POST", r"/log-sources"),                     # makes the collector here read a file here
    ("POST", r"/log-sources/pending/[^/]+"),
))

# Settings that name files or services on this machine: the SentrAI team sets them, never a company.
LOCKED_SETTINGS = frozenset({"SENTRAI_LAB_LOGS", "SENTRAI_LOG_ACCESS", "SENTRAI_LOG_AUTH", "SENTRAI_LOG_DB",
                             "SENTRAI_LOG_OS", "SENTRAI_CORE_URL"})
# Settings that make the core call an address: allowed only to the public internet.
OUTSIDE_SETTINGS = frozenset({"SENTRAI_LLM_BASE_URL", "SENTRAI_HEALTH_URL", "SMTP_HOST", "SLACK_WEBHOOK_URL"})


def on(env: dict[str, str] | None = None) -> bool:
    return (os.environ if env is None else env).get(ENV, "").strip().lower() in ("1", "true", "yes", "on")


def panel_work(method: str, path: str) -> bool:
    return any(method == m and p.fullmatch(path) for m, p in PANEL_WORK)


def install(app: Any) -> None:
    """Refuse the panel-machine endpoints (outermost, so no token or cookie gets past it)."""

    @app.middleware("http")
    async def hosted_guard(request: Any, call_next: Callable[..., Any]) -> Any:
        if panel_work(request.method, request.url.path):
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": NOT_HERE, "hosted": True}, status_code=409)
        return await call_next(request)


def lock_local_work(threats: Any, backups: Any, discovery: Any) -> None:
    """The same rule for what calls these directly (Sentry's chat, the schedules): nothing runs on this machine."""

    def no_threat_scan(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"findings": [], "scanned_at": None, "scanned_files": 0, "error": NOT_HERE, "hosted": True}

    def no_process_scan(*_a: Any, **_k: Any) -> dict[str, Any]:
        return {"suggestions": [], "processes": [], "scanned": 0, "recognised": 0, "skipped_protected": 0,
                "scanned_at": None, "error": NOT_HERE, "hosted": True}

    def refuse(*_a: Any, **_k: Any) -> Any:
        raise ValueError(NOT_HERE)

    if threats is not None:
        threats.scan = no_threat_scan
        threats.quarantine = refuse
        threats.restore = refuse
        threats.every_s = lambda: 0.0  # no scheduled scan of this machine
    if backups is not None:
        backups.make = refuse
        backups.restore = refuse
        backups.due = lambda: False  # no scheduled backup of this machine
    if discovery is not None:
        discovery.scan = no_process_scan
        discovery.approve = refuse


def _host_of(env: str, value: str) -> str:
    text = value.strip()
    if env == "SMTP_HOST":
        return text.split(":")[0].strip("[]")
    return (urlsplit(text if "//" in text else "//" + text).hostname or "").rstrip(".")


def public_host(host: str, resolve: Callable[[str], Iterable[str]] | None = None) -> bool:
    """True when every address the name has is on the public internet (a bare address is checked as it is)."""
    if not host or host.lower() in ("localhost",) or host.lower().endswith((".localhost", ".local", ".internal")):
        return False
    try:
        addrs = [str(ipaddress.ip_address(host))]
    except ValueError:
        try:
            addrs = list((resolve or _resolve)(host))
        except OSError:
            return True  # a name that does not resolve here reaches nothing here; the save's own checks still apply
    for a in addrs:
        try:
            ip = ipaddress.ip_address(a.split("%")[0])
        except ValueError:
            return False
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global or ip.is_multicast:
            return False
    return True


def _resolve(host: str) -> list[str]:
    return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})


def setting_refused(env: str, value: str, resolve: Callable[[str], Iterable[str]] | None = None) -> str | None:
    """Why a company may not save this value in hosted mode (None: it may)."""
    if not on():
        return None
    if env in LOCKED_SETTINGS:
        return "This setting belongs to SentrAI's hosted service and cannot be changed here."
    if env in OUTSIDE_SETTINGS and value.strip() and not public_host(_host_of(env, value), resolve):
        return "This address must be a public service on the internet, not a private or local one."
    return None


def status() -> dict[str, Any]:
    """For /health and the CLI: whether this core is one company on the hosted service."""
    return {"hosted": on(), "company": os.environ.get("SENTRAI_COMPANY", "") or None}


def dumps_refusal() -> bytes:
    return json.dumps({"detail": NOT_HERE, "hosted": True}).encode()
