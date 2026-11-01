"""web/serve.py: the stdlib server that serves the built console and passes /api to the core."""
import http.client
import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("web_serve", Path(__file__).resolve().parents[2] / "web" / "serve.py")
serve = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(serve)


class FakeCore(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        FakeCore.seen.append({"path": self.path, "method": self.command, "body": body, "headers": dict(self.headers)})
        if self.path == "/auth/me":
            out, code = b'{"detail":"not signed in"}', 401
        else:
            out, code = json.dumps({"ok": True}).encode(), 200
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Set-Cookie", "sentrai_session=abc; HttpOnly; Path=/")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = _answer


HANDSHAKE_IN_ACCEPT = False  # True is the old behaviour: the test below must then fail


def start(handler_cls, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def make(tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html><script>var theme=1</script><script src='/assets/a.js'></script></html>")
    (dist / "assets" / "a.js").write_text("console.log(1)")
    (tmp_path / "secret.txt").write_text("secret")
    core = start(FakeCore)
    web = start(serve.make_handler(dist, f"http://127.0.0.1:{core.server_address[1]}", https=False))
    return core, web


def get(web, path, method="GET", body=None, headers=None):
    c = http.client.HTTPConnection("127.0.0.1", web.server_address[1], timeout=5)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    return r.status, dict(r.getheaders()), r.read()


def test_pages_files_and_unknown_paths(tmp_path):
    core, web = make(tmp_path)
    try:
        code, headers, body = get(web, "/")
        assert code == 200 and b"<html>" in body and headers["Cache-Control"] == "no-cache"
        assert get(web, "/machines/srv-01")[0] == 200  # an app address: the page, which draws it
        code, headers, _ = get(web, "/assets/a.js")
        assert code == 200 and "immutable" in headers["Cache-Control"]
        assert get(web, "/assets/missing.js")[0] == 404
        for evil in ("/../secret.txt", "/%2e%2e/secret.txt", "/..%2fsecret.txt"):
            code, _, body = get(web, evil)
            assert b"secret" not in body
        assert "frame-ancestors 'none'" in get(web, "/")[1]["Content-Security-Policy"]
    finally:
        core.shutdown(); web.shutdown()


def test_csp_allows_only_the_pages_own_inline_script(tmp_path):
    core, web = make(tmp_path)
    try:
        csp = get(web, "/")[1]["Content-Security-Policy"]
        assert csp.count("'sha256-") == 1 and "unsafe-inline'" not in csp.split("style-src")[0]
    finally:
        core.shutdown(); web.shutdown()


def test_api_goes_to_the_core_with_the_real_address(tmp_path):
    core, web = make(tmp_path)
    FakeCore.seen.clear()
    try:
        code, headers, body = get(web, "/api/ui/machines?x=1", headers={"X-Forwarded-For": "6.6.6.6", "Cookie": "a=b"})
        assert code == 200 and json.loads(body) == {"ok": True}
        assert "sentrai_session=abc" in headers["Set-Cookie"]
        seen = FakeCore.seen[-1]
        assert seen["path"] == "/ui/machines?x=1"
        assert seen["headers"]["X-Forwarded-For"] == "127.0.0.1"  # what connected, not what the browser claimed
        assert seen["headers"]["Cookie"] == "a=b" and seen["headers"]["X-Forwarded-Proto"] == "http"
        code, _, body = get(web, "/api/chat", "POST", b'{"message":"hi"}', {"Content-Type": "application/json"})
        assert code == 200 and FakeCore.seen[-1]["body"] == b'{"message":"hi"}' and FakeCore.seen[-1]["method"] == "POST"
        assert get(web, "/api/auth/me")[0] == 401  # the core's errors pass through as they are
    finally:
        core.shutdown(); web.shutdown()


def test_a_down_core_is_a_502_not_a_crash(tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html></html>")
    web = start(serve.make_handler(dist, "http://127.0.0.1:9", https=False))
    try:
        assert get(web, "/api/health")[0] == 502
        assert get(web, "/")[0] == 200
    finally:
        web.shutdown()


def test_a_silent_https_connection_does_not_block_the_others(tmp_path):
    """Browsers open spare connections and say nothing. Over TLS that once froze the whole server (the handshake ran in accept())."""
    import shutil
    import socket
    import ssl
    import subprocess
    if not shutil.which("openssl"):
        import pytest
        pytest.skip("openssl is not installed")
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<html>ok</html>")
    web = start(serve.make_handler(dist, "http://127.0.0.1:9", https=True), 0)
    serve.use_tls(web, str(cert), str(key), handshake_in_accept=HANDSHAKE_IN_ACCEPT)
    port = web.server_address[1]
    silent = socket.create_connection(("127.0.0.1", port))  # connects, never sends a hello
    try:
        client = ssl.create_default_context()
        client.check_hostname, client.verify_mode = False, ssl.CERT_NONE
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        tls = client.wrap_socket(raw, server_hostname="localhost")
        tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        assert b"200 OK" in tls.recv(4096)
        tls.close()
    finally:
        silent.close()
        web.shutdown()
