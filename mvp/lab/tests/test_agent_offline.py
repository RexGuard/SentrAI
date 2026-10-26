"""The agent while the panel is out of reach: local rules, their limits, the report back, and pinning."""
from __future__ import annotations

import http.server
import json
import shutil
import ssl
import subprocess
import threading

import pytest
import requests

from agent import agent, offline, pinning
from collector.collector import make_event

PUBLIC = "203.0.113.9"


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def sqli(ip: str = PUBLIC) -> dict:
    return make_event("web", "flask_access", "GET /search?q=' OR 1=1-- 200", src_ip=ip)


def guard(clock: Clock, **kw) -> offline.LocalGuard:
    kw.setdefault("block_at", 80)
    kw.setdefault("ttl_s", 3600)
    kw.setdefault("max_per_hour", 10)
    return offline.LocalGuard({"127.0.0.1", "198.51.100.1"}, clock=clock, private_nets={"10.0.0.0/8"}, **kw)


def go_offline(g: offline.LocalGuard, clock: Clock) -> float:
    last_ok = clock.t
    clock.t += 31
    assert g.link(last_ok) is None and g.offline_since == last_ok
    return last_ok


@pytest.fixture(autouse=True)
def agent_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_AGENT_FILE", str(tmp_path / "agent.json"))
    return tmp_path / "agent.json"


def test_online_the_panel_decides():
    clock = Clock()
    g = guard(clock)
    assert g.link(clock.t) is None and g.offline_since is None
    assert g.observe([sqli() for _ in range(5)]) == []
    assert g.wanted() == set()


def test_offline_blocks_a_clear_attack_for_an_hour():
    clock = Clock()
    g = guard(clock)
    go_offline(g, clock)
    assert g.observe([sqli(), sqli()]) == []  # 2 x 40 points: risk 74, under the line
    made = g.observe([sqli()])
    assert [a["ip"] for a in made] == [PUBLIC] and made[0]["score"] >= 80
    assert made[0]["category"] == "sql_injection" and len(made[0]["event_ids"]) == 3
    assert g.wanted() == {PUBLIC}
    assert g.observe([sqli()]) == []  # already blocked: not twice
    clock.t += 3601
    assert g.wanted() == set() and any("expired" in line for line in g.log)


def test_window_counts_warm_hits_from_before_the_panel_went_away():
    clock = Clock()
    g = guard(clock)
    g.observe([sqli(), sqli()])  # online: scored, not acted on
    go_offline(g, clock)
    assert [a["ip"] for a in g.observe([sqli()])] == [PUBLIC]


def test_never_private_protected_or_panel_held_addresses():
    clock = Clock()
    g = guard(clock)
    go_offline(g, clock)
    assert g.observe([sqli("10.1.2.3") for _ in range(4)]) == []
    assert g.observe([sqli("198.51.100.1") for _ in range(4)]) == []
    assert g.observe([sqli("203.0.113.50") for _ in range(4)], held={"203.0.113.50"}) == []
    assert any("not blocking 10.1.2.3: private" in line for line in g.log)
    assert any("not blocking 198.51.100.1: protected" in line for line in g.log)


def test_hourly_cap_and_switch_off():
    clock = Clock()
    g = guard(clock, max_per_hour=2)
    go_offline(g, clock)
    for n in range(4):
        g.observe([sqli(f"203.0.113.{n + 10}") for _ in range(3)])
    assert len(g.wanted()) == 2 and any("already made this hour" in line for line in g.log)

    off = guard(clock, on=False)
    go_offline(off, clock)
    assert off.observe([sqli() for _ in range(5)]) == [] and off.wanted() == set()


def test_report_on_return_then_cleared():
    clock = Clock()
    g = guard(clock)
    last_ok = go_offline(g, clock)
    g.observe([sqli() for _ in range(3)])
    g.observe([make_event("os", "heartbeat", "collector heartbeat")])  # not counted
    clock.t += 60
    report = g.link(last_ok)  # still out of reach
    assert report is None
    report = g.link(clock.t)  # the panel answered
    assert report["actions"][0]["ip"] == PUBLIC and report["scored"] == 3
    assert report["from"] and report["to"] and g.offline_since is None
    assert g.link(clock.t) is report  # kept until delivered
    g.reported()
    assert g.link(clock.t) is None
    assert g.wanted() == {PUBLIC}  # the block itself runs to its own end


def test_state_survives_a_restart():
    clock = Clock()
    g = guard(clock)
    go_offline(g, clock)
    g.observe([sqli() for _ in range(3)])
    again = guard(clock, saved=json.loads(json.dumps(g.state())))
    assert again.wanted() == {PUBLIC} and again.offline_since == g.offline_since
    assert again.report["actions"][0]["ip"] == PUBLIC


def recorder():
    calls = []

    def run(args):
        calls.append(args)
        return 0, ""

    return calls, run


def test_enforcer_holds_panel_blocks_and_adds_local_ones():
    clock = Clock()
    calls, run = recorder()
    e = agent.Enforcer("iptables", True, {"127.0.0.1"}, runner=run, hold_s=3600, clock=clock)
    assert e.sync({"203.0.113.1"})["added"] == ["203.0.113.1"]
    clock.t += 60
    assert e.sync(None, {PUBLIC}) == {"added": [PUBLIC], "removed": []}  # panel's list held, local added
    clock.t += 3600
    assert e.sync(None, {PUBLIC}) == {"added": [], "removed": ["203.0.113.1"]}  # hold over, local stays
    assert e.sync(None, set()) == {"added": [], "removed": [PUBLIC]}  # local block expired


def test_enforcer_puts_saved_blocks_back_after_a_restart():
    # saved while in dry run (or before a reboot emptied the firewall): the first pass must block for real
    calls, run = recorder()
    e = agent.Enforcer("nftables", True, {"127.0.0.1"}, runner=run, applied=["203.0.113.1"], panel=["203.0.113.1"])
    assert e.sync({"203.0.113.1"})["added"] == ["203.0.113.1"]
    assert any("203.0.113.1" in " ".join(c) for c in calls)  # the firewall was checked, not trusted
    calls.clear()
    assert e.sync({"203.0.113.1"}) == {"added": [], "removed": []} and calls == []  # later passes: no work


def test_enforcer_retries_a_saved_block_it_could_not_put_back():
    fail = [True]

    def run(args):
        return (1, "nft not ready") if fail[0] else (0, "")

    e = agent.Enforcer("nftables", True, set(), runner=run, applied=["203.0.113.1"], panel=["203.0.113.1"])
    assert e.sync({"203.0.113.1"})["added"] == [] and e.applied == set()
    fail[0] = False
    assert e.sync({"203.0.113.1"})["added"] == ["203.0.113.1"]


class FakeSession:
    """A panel that can be switched off; records what the agent posts."""

    def __init__(self):
        self.up = False
        self.posts: list[tuple[str, dict]] = []
        self.verify = True

    def get(self, url, headers, timeout, verify):
        if not self.up:
            raise requests.ConnectionError("down")
        return type("R", (), {"status_code": 200, "json": lambda self: {"ips": []}})()

    def post(self, url, json, headers, timeout, verify):
        if not self.up:
            raise requests.ConnectionError("down")
        self.posts.append((url, json))
        return type("R", (), {"status_code": 200})()


def test_loop_blocks_offline_and_reports_when_the_panel_returns(agent_file, monkeypatch):
    clock = Clock()
    monkeypatch.setattr(agent.time, "time", clock)
    data = {"panel": "https://panel.example.com", "key": "sa_x.y", "host": "web-01", "blocked": [], "last_ok": clock.t}
    calls, run = recorder()
    e = agent.Enforcer("iptables", True, {"127.0.0.1"}, runner=run, last_ok=clock.t, clock=clock)
    g = guard(clock)
    session = FakeSession()

    class Once(threading.Event):
        def wait(self, timeout=None):
            self.set()
            return True

    def tick():
        agent.enforce_loop(data, e, Once(), guard=g, session=session)

    clock.t += 31
    tick()  # panel down for 31 s: local rules take over
    assert g.offline_since is not None
    g.observe([sqli() for _ in range(3)], held=e.panel)
    tick()
    assert PUBLIC in e.applied and any(PUBLIC in c for c in calls)
    saved = json.loads(agent_file.read_text())
    assert saved["local"]["blocks"][PUBLIC]["applied"] is True and saved["blocked"] == [PUBLIC]

    session.up = True
    clock.t += 10
    tick()
    reports = [body for url, body in session.posts if url.endswith("/fleet/offline-report")]
    assert len(reports) == 1 and reports[0]["actions"][0]["ip"] == PUBLIC
    assert "until_ts" not in reports[0]["actions"][0]
    assert g.report is None and PUBLIC in e.applied  # reported; block runs to its own end


# ------------------------------------------------------------------ pinning
def test_pin_format():
    pin = "sha256:" + "ab" * 32
    assert pinning.normalise(pin.upper()) == pin
    assert pinning.normalise(":".join(["AB"] * 32)) == pin
    with pytest.raises(pinning.PinError):
        pinning.normalise("sha256:1234")


def test_join_keeps_the_pin_and_refuses_a_bad_one(agent_file):
    pin = "sha256:" + "cd" * 32
    seen = {}

    def post(url, json, timeout, verify):
        seen["verify"] = verify
        return type("R", (), {"status_code": 200,
                              "json": lambda self: {"agent_id": "a1", "host": "web-01", "key": "sa_a1.k"}})()

    data = agent.join("https://panel.example.com:8443", "ABCD", name="web-01", post=post, pin=pin.upper())
    assert data["pin"] == pin and json.loads(agent_file.read_text())["pin"] == pin
    assert seen["verify"] is False  # the pin replaces the authority check
    with pytest.raises(agent.AgentError, match="64 hex"):
        agent.join("https://panel.example.com", "ABCD", post=post, pin="sha256:nope")
    with pytest.raises(agent.AgentError, match="https"):
        agent.join("http://127.0.0.1:8000", "ABCD", post=post, pin=pin)


@pytest.fixture(scope="module")
def tls_panel(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl is needed to make a test certificate")
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=panel",
                    "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem")], check=True, capture_output=True)

    class Ok(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"ips": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Ok)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", d / "cert.pem"
    srv.shutdown()


@pytest.fixture
def no_proxy(monkeypatch):
    for k in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(k, "127.0.0.1,localhost")


def test_pinned_session_talks_only_to_that_certificate(tls_panel, no_proxy):
    url, cert = tls_panel
    pin = pinning.seen(url)
    from app import fleet  # the panel computes the same pin from its certificate file
    assert fleet.cert_pin(cert) == pin

    assert pinning.session(url, pin).get(f"{url}/blocklist", timeout=5).json() == {"ips": []}
    with pytest.raises(requests.exceptions.SSLError) as wrong:
        pinning.session(url, "sha256:" + "00" * 32).get(f"{url}/blocklist", timeout=5)
    assert "different certificate" in pinning.explain(wrong.value)
    with pytest.raises(requests.exceptions.SSLError) as untrusted:  # self-signed, no pin: refused
        pinning.session(url).get(f"{url}/blocklist", timeout=5)
    assert "--pin" in pinning.explain(untrusted.value)


def test_fetch_blocklist_with_a_wrong_pin_counts_as_unreachable(tls_panel, no_proxy, capsys):
    url, _ = tls_panel
    data = {"panel": url, "key": "sa_x.y", "pin": "sha256:" + "11" * 32}
    assert agent.fetch_blocklist(data, agent.panel_session(data)) is None
    assert "different certificate" in capsys.readouterr().out
    data["pin"] = pinning.seen(url)
    assert agent.fetch_blocklist(data, agent.panel_session(data)) == set()
