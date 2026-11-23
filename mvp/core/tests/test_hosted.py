"""Hosted service: many companies on one server, each with its own core, kept apart (sentrai_hosted.py,
web/gateway.py, app/hosted.py)."""

import http.client
import json
import os
import subprocess
import sys
import threading
import time
import types
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import sentrai_hosted as sh
from app import hosted
from app.config import Settings
from app.main import create_app

from .conftest import AUTH

MVP = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(MVP / "web"))
import gateway  # noqa: E402


# -- the core in hosted mode ---------------------------------------------------------------------------------------

@pytest.fixture
def hosted_client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_HOSTED", "1")
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    saved = dict(os.environ)  # a settings save copies values into os.environ: keep them out of later tests
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False))
    try:
        with TestClient(app, headers=AUTH) as c:
            c.app_state = app.state
            yield c
    finally:
        os.environ.clear()
        os.environ.update(saved)


@pytest.mark.parametrize("method,path", [
    ("POST", "/system/scan"), ("POST", "/threats/scan"), ("POST", "/threats/abc123/quarantine"),
    ("POST", "/quarantine/q1/restore"), ("POST", "/deps/scan"), ("POST", "/backups"),
    ("POST", "/backups/b1/restore"), ("POST", "/log-sources"), ("POST", "/log-sources/pending/p1")])
def test_hosted_core_refuses_work_on_the_shared_server(hosted_client, method, path):
    r = hosted_client.request(method, path, json={"operator": "t", "paths": ["/etc"], "file_id": "x", "reason": "x",
                                                  "confirm": True, "in_place": True, "target": "/tmp"})
    assert r.status_code == 409, r.text
    assert r.json()["hosted"] is True and "your own computers" in r.json()["detail"]


def test_hosted_core_still_answers_everything_else(hosted_client):
    assert hosted_client.get("/health").json() == {"ok": True}
    assert hosted_client.get("/machines").status_code == 200
    assert hosted_client.get("/backups").status_code == 200  # reading is fine; only making one here is refused
    assert hosted_client.post("/fleet/join-codes", json={"name": "web-01", "operator": "t"}).status_code == 200


def test_chat_and_schedules_cannot_scan_the_shared_server(hosted_client):
    chat = hosted_client.app_state.chat
    assert chat.threats.scan(by="Sentry (chat)")["hosted"] is True
    assert chat.threats.every_s() == 0
    assert chat.discovery.scan(by="Sentry (chat)")["suggestions"] == []
    with pytest.raises(ValueError):
        chat.threats.quarantine("x", "t", "r")


def test_hosted_settings_lock_this_servers_files_and_private_addresses(hosted_client):
    r = hosted_client.post("/ui/settings", json={"values": {"SENTRAI_LAB_LOGS": "/etc"}})
    assert r.status_code == 403 and "hosted service" in r.json()["detail"]
    r = hosted_client.post("/ui/settings", json={"values": {"SENTRAI_HEALTH_URL": "http://127.0.0.1:9101/health"}})
    assert r.status_code == 403 and "public service" in r.json()["detail"]
    r = hosted_client.post("/ui/settings", json={"values": {"SMTP_HOST": "10.0.0.5"}})
    assert r.status_code == 403
    assert hosted_client.post("/ui/settings", json={"values": {"BRUTE_FORCE_COUNT": "6"}}).status_code == 200


def test_own_panel_is_unchanged(client):
    """Without SENTRAI_HOSTED a company's own panel scans and backs up its own machine as before."""
    assert not hosted.on()
    assert client.post("/system/scan", json={"operator": "t"}).status_code == 200


def test_public_host_check():
    assert not hosted.public_host("localhost")
    assert not hosted.public_host("127.0.0.1") and not hosted.public_host("10.1.2.3")
    assert not hosted.public_host("169.254.169.254")  # cloud metadata
    assert not hosted.public_host("db.internal")
    assert hosted.public_host("8.8.8.8")
    assert not hosted.public_host("evil.example", resolve=lambda h: ["127.0.0.1"])
    assert hosted.public_host("smtp.example", resolve=lambda h: ["93.184.216.34"])
    assert hosted._host_of("SMTP_HOST", "smtp.gmail.com:587") == "smtp.gmail.com"
    assert hosted._host_of("SENTRAI_LLM_BASE_URL", "https://api.example.com/v1") == "api.example.com"


# -- the companies list ---------------------------------------------------------------------------------------------

@pytest.fixture
def reg(tmp_path):
    return sh.Registry(tmp_path / "hosted", env={**os.environ, "SENTRAI_HOSTED_DOMAIN": "example.test",
                                                  "SENTRAI_HOSTED_FIRST_PORT": "19500"})


def test_slugs():
    assert sh.slug_for("Acme Pte. Ltd.") == "acme-pte-ltd"
    assert sh.check_slug("acme-sg") == "acme-sg"
    for bad in ("ab", "-acme", "acme-", "ac--me", "Acme!", "www", "sentrai", "x" * 31):
        with pytest.raises(sh.HostedError):
            sh.check_slug(bad)


def test_each_company_gets_its_own_folder_token_and_port(reg):
    a = reg.add("Acme Pte Ltd", owner_email="Boss@Acme.com")
    b = reg.add("Beta Co", slug="beta")
    assert (a.slug, a.port, a.owner_email) == ("acme-pte-ltd", 19500, "boss@acme.com")
    assert b.port == 19501
    ta, tb = sh.company_token(reg, a.slug), sh.company_token(reg, b.slug)
    assert ta and tb and ta != tb
    assert (reg.folder(a.slug) / "config.json").exists() and not (reg.folder(a.slug) / "accounts.json").exists()
    with pytest.raises(sh.HostedError, match="taken"):
        reg.add("Acme again", slug="acme-pte-ltd")
    assert [c.slug for c in reg.companies()] == ["acme-pte-ltd", "beta"]


def test_first_owner_setup_code_then_never_again(reg):
    c = reg.add("Gamma", slug="gamma")
    code = sh.setup_code(reg, c.slug)
    assert len(code.replace("-", "")) >= 8
    sh.make_owner(reg, c.slug, "owner@gamma.test", "a long enough password 1")
    with pytest.raises(sh.HostedError, match="already has an Owner"):
        sh.setup_code(reg, c.slug)
    assert json.loads((reg.folder(c.slug) / "accounts.json").read_text())["accounts"][0]["email"] == "owner@gamma.test"


def test_remove_sets_the_folder_aside_and_frees_the_name(reg):
    c = reg.add("Delta", slug="delta")
    reg.set_status(c.slug, "paused")
    assert reg.get("delta").status == "paused"
    gone = reg.set_status(c.slug, "removed")
    assert gone.status == "removed" and not reg.folder("delta").exists()
    assert list((reg.root / "removed").iterdir())  # never deleted
    assert reg.get("delta") is None and reg.companies() == []
    again = reg.add("Delta 2", slug="delta")
    assert again.port != c.port  # a new company never inherits an old one's port


def test_company_env_shares_nothing_but_what_is_allowed(reg):
    c = reg.add("Acme", slug="acme")
    base = {"PATH": "/usr/bin", "TELEGRAM_BOT_TOKEN": "ours", "SENTRAI_API_TOKEN": "ours", "SENTRAI_HOME": "/var/lib/x",
            "ANTHROPIC_API_KEY": "sk-shared", "SLACK_WEBHOOK_URL": "https://hooks.example/ours"}
    env = sh.company_env(reg, c, base)
    for leaked in ("TELEGRAM_BOT_TOKEN", "SENTRAI_API_TOKEN", "SLACK_WEBHOOK_URL"):
        assert leaked not in env
    assert env["ANTHROPIC_API_KEY"] == "sk-shared"  # SENTRAI_HOSTED_SHARE's default
    assert env["SENTRAI_HOME"] == str(reg.folder("acme")) and env["HOME"] == str(reg.folder("acme"))
    assert env["SENTRAI_HOSTED"] == "1" and env["SENTRAI_FIREWALL"] == "off"
    assert env["SENTRAI_CORE_HOST"] == "127.0.0.1" and env["SENTRAI_CORE_PORT"] == str(c.port)
    assert env["SENTRAI_PANEL_URL"] == "https://acme.example.test:8443" and env["SENTRAI_PANEL_PORT"] == ""
    assert "ANTHROPIC_API_KEY" not in sh.company_env(reg, c, {**base, "SENTRAI_HOSTED_SHARE": "SENTRAI_LLM_MODEL"})


def test_cli_add_list_pause(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SENTRAI_HOSTED_HOME", str(tmp_path / "h"))
    monkeypatch.setenv("SENTRAI_HOSTED_DOMAIN", "example.test")
    assert sh.main(["add", "Acme Pte Ltd", "--owner", "boss@acme.test"]) == 0
    out = capsys.readouterr().out
    assert "https://acme-pte-ltd.example.test" in out and "setup code" in out
    assert sh.main(["--json", "list"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["slug"] == "acme-pte-ltd" and rows[0]["agents"] == "https://acme-pte-ltd.example.test:8443"
    assert sh.main(["pause", "acme-pte-ltd"]) == 0
    assert sh.main(["pause", "nobody"]) == 2


# -- the gateway -----------------------------------------------------------------------------------------------------

def test_slug_of():
    d = "sentrai.pro"
    assert gateway.slug_of("acme.sentrai.pro", d) == "acme"
    assert gateway.slug_of("ACME.sentrai.pro:8443", d) == "acme"
    assert gateway.slug_of("acme.sentrai.pro.", d) == "acme"
    for other in ("sentrai.pro", "a.b.sentrai.pro", "acme.sentrai.pro.evil.com", "evilsentrai.pro", "1.2.3.4",
                  "[::1]:8443", ""):
        assert gateway.slug_of(other, d) is None


def test_agent_allowed():
    assert gateway.agent_allowed("POST", "/fleet/enrol", "")
    assert gateway.agent_allowed("POST", "/events", "Bearer sa_x.y")
    assert not gateway.agent_allowed("POST", "/events", "Bearer operator-token")
    assert not gateway.agent_allowed("GET", "/incidents", "Bearer sa_x.y")
    assert gateway.agent_allowed("GET", "/blocklist?host=web-01", "Bearer sa_x.y")
    from app.main import AGENT_ROUTES
    assert gateway.ROUTES.AGENT_ROUTES == AGENT_ROUTES


class _FakeCore(BaseHTTPRequestHandler):
    """Says which company it is and what it was asked, so a test can see where the gateway sent a request."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _answer(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.dumps({"company": self.server.company, "path": self.path, "sent": len(self.rfile.read(n)),
                           "xff": self.headers.get("X-Forwarded-For"), "auth": self.headers.get("Authorization")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = _answer


def _serve(handler, company=None):
    s = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    s.company = company
    s.daemon_threads = True
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def _call(port, method, path, host, headers=None, body=b""):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body or None, headers={"Host": host, **(headers or {})})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    return r.status, data


@pytest.fixture
def two_companies(tmp_path):
    cores = {"acme": _serve(_FakeCore, "acme"), "beta": _serve(_FakeCore, "beta")}
    reg = types.SimpleNamespace(domain="example.test", mtime=lambda: 1.0, companies=lambda: [
        types.SimpleNamespace(slug=k, port=v.server_address[1], status="active") for k, v in cores.items()] + [
        types.SimpleNamespace(slug="paused-co", port=1, status="paused")])
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>console</title>")
    servers = gateway.start(reg, {"SENTRAI_HOSTED_BIND": "127.0.0.1", "SENTRAI_HOSTED_WEB_PORT": "0",
                                  "SENTRAI_HOSTED_AGENT_PORT": "0"}, dist=dist)
    yield servers[0].server_address[1], servers[1].server_address[1]
    for s in [*servers, *cores.values()]:
        s.shutdown()


def test_gateway_sends_each_company_to_its_own_core(two_companies):
    web, agents = two_companies
    for company in ("acme", "beta"):
        status, data = _call(web, "GET", "/api/machines", f"{company}.example.test")
        assert status == 200 and json.loads(data)["company"] == company and json.loads(data)["path"] == "/machines"
        status, data = _call(agents, "POST", "/events", f"{company}.example.test:8443",
                             {"Authorization": "Bearer sa_k.1", "Content-Type": "application/json"}, b"[]")
        assert status == 200 and json.loads(data)["company"] == company
    status, data = _call(web, "GET", "/", "acme.example.test")
    assert status == 200 and b"console" in data


def test_gateway_reaches_no_core_for_an_unknown_or_paused_company(two_companies):
    web, agents = two_companies
    for host in ("nobody.example.test", "paused-co.example.test", "example.test", "acme.example.test.evil.com"):
        status, data = _call(web, "GET", "/api/machines", host)
        assert status == 404 and b"No SentrAI panel here" in data
        status, _ = _call(agents, "POST", "/fleet/enrol", host, {"Content-Type": "application/json"}, b"{}")
        assert status == 404


def test_agents_port_only_takes_machine_keys(two_companies):
    _, agents = two_companies
    status, data = _call(agents, "GET", "/incidents", "acme.example.test", {"Authorization": "Bearer operator"})
    assert status == 404 and b"not on the agents' port" in data
    status, _ = _call(agents, "POST", "/events", "acme.example.test", {"Authorization": "Bearer operator"}, b"[]")
    assert status == 404
    status, data = _call(agents, "POST", "/fleet/backup-copies", "acme.example.test",
                         {"Authorization": "Bearer sa_k.1"}, b"x" * 300_000)
    assert status == 200 and json.loads(data)["sent"] == 300_000  # a large copy passes through whole


# -- end to end, real cores ------------------------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform == "win32", reason="starting two real cores is slow on the Windows runners")
def test_two_real_companies_are_kept_apart(tmp_path):
    env = {**os.environ, "SENTRAI_HOSTED_HOME": str(tmp_path / "h"), "SENTRAI_HOSTED_DOMAIN": "example.test",
           "SENTRAI_HOSTED_FIRST_PORT": str(19700 + os.getpid() % 200), "SENTRAI_HOSTED_NOTIFIER": "off",
           "SENTRAI_HOSTED_PYTHON": sys.executable}
    for k in ("SENTRAI_DB", "SENTRAI_CONFIG", "SENTRAI_API_TOKEN", "SENTRAI_BACKGROUND"):
        env.pop(k, None)
    reg = sh.Registry(env=env)
    a, b = reg.add("Acme", slug="acme"), reg.add("Beta", slug="beta")
    sup = sh.Supervisor(reg, env, log=lambda _m: None)
    try:
        sup.step()
        ta, tb = sh.company_token(reg, "acme"), sh.company_token(reg, "beta")

        def call(c, method, path, token, body=None):
            req = urllib.request.Request(f"http://127.0.0.1:{c.port}{path}", method=method,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers={"Authorization": f"Bearer {token}",
                                                  "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"{}")

        deadline = time.time() + 60
        while time.time() < deadline and not all(r["answering"] for r in sh.check(reg, 1.0)):
            time.sleep(0.5)
        assert all(r["answering"] for r in sh.check(reg)), [p.read_text()[-2000:] for p in
                                                             (tmp_path / "h").glob("companies/*/run/core.log")]
        assert call(a, "POST", "/events", ta, [{"host": "acme-web", "layer": "auth", "source": "sshd",
                                                "raw": "Failed password for root from 203.0.113.9"}])[0] == 200
        assert call(a, "GET", "/machines", tb)[0] == 401  # beta's token means nothing to acme's core
        hosts_a = [m["host"] for m in call(a, "GET", "/machines", ta)[1]]
        hosts_b = [m["host"] for m in call(b, "GET", "/machines", tb)[1]]
        assert "acme-web" in hosts_a and "acme-web" not in hosts_b
        assert call(b, "POST", "/threats/scan", tb, {"paths": [str(reg.folder("acme"))]})[0] == 409
        reg.set_status("beta", "paused")
        sup.step()
        assert [r["answering"] for r in sh.check(reg) if r["slug"] == "beta"] == [False]
    finally:
        sup.stop()
        for p in sup.procs.values():
            sup._stop_proc(p, "test over")
