"""The hosted service's front door: one address per company, each sent to that company's own core.

sentrai_hosted.py starts it next to the companies' cores. It runs two listeners:

  web     (SENTRAI_HOSTED_WEB_PORT, default 8080)  https://acme.sentrai.pro: the React console, its /api calls sent
          to Acme's core (serve.py's handler, with the core picked by the Host header). An address that is no
          active company gets a plain "No SentrAI panel here" page and reaches no core.
  agents  (SENTRAI_HOSTED_AGENT_PORT, default 8443)  https://acme.sentrai.pro:8443: what Acme's agents send, sent
          to Acme's core, and only what a machine key may do (core/app/agent_routes.py, the same list a company's
          own panel applies on its agents' port), plus joining with a code. The operator token never gets through.

Each core listens on 127.0.0.1 only, so the gateway is the only way in. A company is picked by its name in the
address and nothing else: a machine key or a cookie from one company sent to another company's address is
checked by that other company's core, which does not know it.

TLS: SENTRAI_HOSTED_TLS_CERT / SENTRAI_HOSTED_TLS_KEY, a certificate for *.<domain>. Agents pin it (the pin comes
with each join code), so a renewal needs `python -m agent pin NEW` on each machine, as on a company's own panel.
Without them both listeners are plain http, for a test or behind a proxy that does TLS (then set
SENTRAI_HOSTED_BEHIND_TLS=1 so sign-in cookies are marked secure).
"""
from __future__ import annotations

import http.client
import importlib.util
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import serve  # noqa: E402  (the web console's own server: its handler does the web side)

KEY_PREFIX = "sa_"  # a machine key (core/app/fleet.py)
HOP = serve.HOP


def _agent_routes() -> Any:
    spec = importlib.util.spec_from_file_location("sentrai_agent_routes", HERE.parent / "core" / "app" / "agent_routes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


ROUTES = _agent_routes()


def slug_of(host: str, domain: str) -> str | None:
    """"acme.sentrai.pro:8443" -> "acme"; None for any other address (the bare domain, deeper names, numbers)."""
    name = (host or "").strip().lower()
    if name.startswith("["):
        return None  # an IPv6 address
    name = name.rsplit(":", 1)[0] if ":" in name else name
    name = name.rstrip(".")
    suffix = "." + domain.strip(".").lower()
    if not name.endswith(suffix):
        return None
    label = name[: -len(suffix)]
    return label if label and "." not in label else None


class Directory:
    """Which local port answers for which company: companies.json, read again when it changes (at most once a
    second), so a company added, paused or removed takes effect without a restart."""

    def __init__(self, reg: Any, clock: Callable[[], float] = time.monotonic) -> None:
        self.reg = reg
        self.clock = clock
        self._lock = threading.Lock()
        self._seen = (-1.0, -1.0)
        self._ports: dict[str, int] = {}

    def ports(self) -> dict[str, int]:
        with self._lock:
            now = self.clock()
            if now - self._seen[1] >= 1.0:
                mtime = self.reg.mtime()
                if mtime != self._seen[0]:
                    self._ports = {c.slug: c.port for c in self.reg.companies() if c.status == "active"}
                self._seen = (mtime, now)
            return self._ports

    def core_for(self, host: str) -> str | None:
        slug = slug_of(host, self.reg.domain)
        port = self.ports().get(slug or "")
        return f"http://127.0.0.1:{port}" if port else None


def agent_allowed(method: str, path: str, auth: str) -> bool:
    want = (method, path.split("?", 1)[0])
    if want in ROUTES.AGENT_OPEN:
        return True
    machine_key = auth[:7].lower() == "bearer " and auth[7:].strip().startswith(KEY_PREFIX)
    return want in ROUTES.AGENT_ROUTES and machine_key


def make_agents_handler(directory: Directory, max_bytes: int):
    class Agents(BaseHTTPRequestHandler):
        server_version = "sentrai-gateway"
        protocol_version = "HTTP/1.1"
        timeout = 120

        def log_message(self, fmt, *args):
            sys.stderr.write("agents %s %s\n" % (self.address_string(), fmt % args))

        def _json(self, code: int, detail: str) -> None:
            body = json.dumps({"detail": detail}).encode()
            self.close_connection = True  # a body we did not read must not be taken for the next request
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _route(self) -> None:
            base = directory.core_for(self.headers.get("Host") or "")
            if base is None:
                return self._json(404, "no SentrAI panel at this address")
            if not agent_allowed(self.command, self.path, self.headers.get("Authorization") or ""):
                return self._json(404, "not on the agents' port")
            n = int(self.headers.get("Content-Length") or 0)
            if n > max_bytes:
                return self._json(413, "too large")
            port = int(base.rsplit(":", 1)[1])
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
            headers["X-Forwarded-For"] = self.client_address[0]
            headers["X-Forwarded-Proto"] = "https" if getattr(self.server, "tls", False) else "http"
            headers["Content-Length"] = str(n)
            try:
                conn.putrequest(self.command, self.path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", f"127.0.0.1:{port}")
                for k, v in headers.items():
                    conn.putheader(k, v)
                conn.endheaders()
                left = n
                while left > 0:  # a sealed backup copy can be large: pass it on in pieces
                    chunk = self.rfile.read(min(65536, left))
                    if not chunk:
                        break
                    conn.send(chunk)
                    left -= len(chunk)
                resp = conn.getresponse()
            except OSError:
                conn.close()
                return self._json(502, "the panel is starting or not answering; the agent tries again")
            try:
                if left > 0:
                    self.close_connection = True
                self.send_response(resp.status)
                length = resp.getheader("Content-Length")
                for k, v in resp.getheaders():
                    if k.lower() not in HOP and k.lower() not in ("server", "date"):
                        self.send_header(k, v)
                if length is not None:
                    self.send_header("Content-Length", length)
                else:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except OSError:
                pass
            finally:
                conn.close()

        do_GET = do_POST = do_PUT = do_DELETE = lambda self: self._route()  # noqa: E731

    return Agents


def start(reg: Any, env: dict[str, str] | None = None, dist: Path | None = None) -> list[ThreadingHTTPServer]:
    """Start both listeners in background threads; returns them (call .shutdown() to stop)."""
    env = dict(os.environ if env is None else env)
    directory = Directory(reg)
    bind = env.get("SENTRAI_HOSTED_BIND") or "0.0.0.0"
    cert, key = env.get("SENTRAI_HOSTED_TLS_CERT", ""), env.get("SENTRAI_HOSTED_TLS_KEY", "")
    tls = bool(cert and key)
    https = tls or (env.get("SENTRAI_HOSTED_BEHIND_TLS", "").lower() in ("1", "yes", "on", "true"))
    max_bytes = int(env.get("SENTRAI_HOSTED_AGENT_MAX_MB") or 2048) * 1024 * 1024
    web = ThreadingHTTPServer((bind, int(env.get("SENTRAI_HOSTED_WEB_PORT") or 8080)),
                              serve.make_handler(dist or HERE / "app" / "dist", directory.core_for, https))
    agents = ThreadingHTTPServer((bind, int(env.get("SENTRAI_HOSTED_AGENT_PORT") or 8443)),
                                 make_agents_handler(directory, max_bytes))
    for s in (web, agents):
        s.daemon_threads = True
        s.tls = tls  # type: ignore[attr-defined]
        if tls:
            serve.use_tls(s, cert, key)
        threading.Thread(target=s.serve_forever, name=f"gateway-{s.server_address[1]}", daemon=True).start()
    scheme = "https" if tls else "http"
    print(f"[gateway] web {scheme}://{bind}:{web.server_address[1]}  agents {scheme}://{bind}:"
          f"{agents.server_address[1]}  (*.{reg.domain})", flush=True)
    return [web, agents]
