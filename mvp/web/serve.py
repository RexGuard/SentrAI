#!/usr/bin/env python3
"""Serves the built web console (app/dist) and passes /api to the core: the production counterpart of
`vite preview` (run-web.sh), with nothing but the standard library, so a server needs no Node to run it.

    python serve.py [--host 127.0.0.1] [--port 5173] [--core http://127.0.0.1:8000] [--dist app/dist]

Settings from the environment (sentrai.env) when the flags are missing: SENTRAI_DASHBOARD_HOST,
SENTRAI_DASHBOARD_PORT, SENTRAI_CORE_URL, and SENTRAI_WEB_TLS_CERT / SENTRAI_WEB_TLS_KEY (or the
STREAMLIT_SERVER_SSL_* pair the installer already makes) for HTTPS.

The core takes the sign-in address from X-Forwarded-For when the caller is local, so this sets it to the
address that connected here (never what the browser sent) and says whether the page came over HTTPS.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import re
import mimetypes
import os
import posixpath
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
       "transfer-encoding", "upgrade", "host", "content-length", "x-forwarded-for", "x-forwarded-proto"}
MAX_BODY = 32 * 1024 * 1024


def script_hashes(index: Path) -> str:
    """CSP hashes of the page's own inline scripts (the theme set-up), so only those run inline."""
    try:
        html = index.read_text(encoding="utf-8")
    except OSError:
        return ""
    return "".join(" 'sha256-%s'" % base64.b64encode(hashlib.sha256(m.encode()).digest()).decode()
                   for m in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I) if m.strip())


def security_headers(dist: Path) -> dict:
    """The console runs its own scripts and the canvas components' styles; nothing is loaded from elsewhere."""
    return {
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; script-src 'self'%s; img-src 'self' data:; "
                                   "style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; "
                                   "frame-ancestors 'none'" % script_hashes(dist / "index.html"),
    }


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # the core's redirects belong to the browser, not to this proxy
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def make_handler(dist: Path, core: str, https: bool):
    root = dist.resolve()
    HEADERS = security_headers(root)

    class Handler(BaseHTTPRequestHandler):
        server_version = "sentrai-web"
        protocol_version = "HTTP/1.1"
        timeout = 65  # an idle or half-open connection (browsers open spare ones) is dropped, never waited on forever

        def log_message(self, fmt, *args):  # one line per request, to the journal
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None, head: bool = False) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def _static(self, head: bool) -> None:
            path = posixpath.normpath(urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)).lstrip("/")
            target = (root / path).resolve()
            try:
                target.relative_to(root)
            except ValueError:
                return self._send(404, b"not found", "text/plain", head=head)
            if not target.is_file():
                # A page address (/incidents, /machines/srv-01, /machines/web.example.com) is the app's own.
                # Only a missing build file (under assets/, or a top-level name like favicon.ico) is a 404:
                # a machine name with dots in it must still open its page.
                if path.startswith("assets/") or ("/" not in path and "." in path):
                    return self._send(404, b"not found", "text/plain", head=head)
                target = root / "index.html"
            if not target.is_file():
                return self._send(503, b"The web console is not built (npm run build in mvp/web/app).", "text/plain", head=head)
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json", "image/svg+xml"):
                ctype += "; charset=utf-8"
            cache = "public, max-age=31536000, immutable" if "/assets/" in "/" + path else "no-cache"
            self._send(200, target.read_bytes(), ctype, {"Cache-Control": cache}, head)

        def _proxy(self) -> None:
            url = core.rstrip("/") + self.path[len("/api"):]
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self._send(413, b"too large", "text/plain")
            body = self.rfile.read(n) if n else None
            req = urllib.request.Request(url, data=body, method=self.command)
            for k, v in self.headers.items():
                if k.lower() not in HOP:
                    req.add_header(k, v)
            req.add_header("X-Forwarded-For", self.client_address[0])
            req.add_header("X-Forwarded-Proto", "https" if https else "http")
            try:
                resp = OPENER.open(req, timeout=120)
            except urllib.error.HTTPError as e:
                resp = e  # an error answer is still the core's answer
            except OSError:
                return self._send(502, b'{"detail":"The core is not answering."}', "application/json")
            data = resp.read()
            self.send_response(resp.status if hasattr(resp, "status") else resp.code)
            for k, v in resp.headers.items():
                if k.lower() not in HOP and k.lower() != "server" and k.lower() != "date":
                    self.send_header(k, v)  # incl. every Set-Cookie
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def _route(self, head: bool = False) -> None:
            if self.path == "/api" or self.path.startswith("/api/") or self.path.startswith("/api?"):
                return self._proxy()
            if self.command in ("GET", "HEAD"):
                return self._static(head)
            self._send(405, b"method not allowed", "text/plain")

        do_GET = lambda self: self._route()  # noqa: E731
        do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = lambda self: self._route()  # noqa: E731
        do_HEAD = lambda self: self._route(head=True)  # noqa: E731

    return Handler


def use_tls(server: ThreadingHTTPServer, cert: str, key: str, handshake_in_accept: bool = False) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    # The handshake must happen in the request's own thread (on its first read, under the handler's timeout). With
    # the default it runs inside accept(), so one connection that never says hello would stop every sign-in.
    server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=handshake_in_accept)


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    env = os.environ.get
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default=env("SENTRAI_DASHBOARD_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(env("SENTRAI_DASHBOARD_PORT", "5173")))
    p.add_argument("--core", default=env("SENTRAI_CORE_URL", "http://127.0.0.1:8000"))
    p.add_argument("--dist", default=str(here / "app" / "dist"))
    a = p.parse_args(argv)
    cert = env("SENTRAI_WEB_TLS_CERT") or env("STREAMLIT_SERVER_SSL_CERT_FILE")
    key = env("SENTRAI_WEB_TLS_KEY") or env("STREAMLIT_SERVER_SSL_KEY_FILE")
    server = ThreadingHTTPServer((a.host, a.port), make_handler(Path(a.dist), a.core, bool(cert and key)))
    server.daemon_threads = True
    if cert and key:
        use_tls(server, cert, key)
    print(f"SentrAI web console on {'https' if cert and key else 'http'}://{a.host}:{a.port} (core {a.core})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
