"""A central panel's link to its agents: the HTTPS port for agents only, the certificate pin that comes
with a join code, and the report an agent sends after working alone."""

import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from app import fleet, serve
from app.main import AGENT_ROUTES

from .conftest import AUTH
from .test_fleet import as_agent, join, panel  # noqa: F401  (fixture)


@pytest.fixture(scope="module")
def cert(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("openssl is needed to make a test certificate")
    d = tmp_path_factory.mktemp("tls")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=panel",
                    "-keyout", str(d / "key.pem"), "-out", str(d / "cert.pem")], check=True, capture_output=True)
    return d / "cert.pem", d / "key.pem"


def test_pin_from_the_certificate_file(cert):
    pem = cert[0].read_text()
    import base64
    import hashlib
    der = base64.b64decode("".join(pem.split("-----")[2].split()))
    assert fleet.cert_pin(cert[0]) == "sha256:" + hashlib.sha256(der).hexdigest()
    assert fleet.cert_pin(cert[1]) == "" and fleet.cert_pin(None) == "" and fleet.cert_pin("/nope.pem") == ""
    assert fleet.normalise_pin(fleet.cert_pin(cert[0]).upper()) == fleet.cert_pin(cert[0])
    assert fleet.normalise_pin("sha256:12") == ""


def test_join_code_comes_with_the_panel_address_and_pin(panel, cert, monkeypatch):  # noqa: F811
    monkeypatch.setenv("SENTRAI_PANEL_CERT", str(cert[0]))
    monkeypatch.setenv("SENTRAI_PANEL_URL", "https://panel.example.com:8443/")
    made = panel.post("/fleet/join-codes", json={"operator": "erick"}).json()
    assert made["pin"] == fleet.cert_pin(cert[0]) and made["panel_url"] == "https://panel.example.com:8443"
    assert panel.get("/fleet/panel").json() == {"panel_url": made["panel_url"], "pin": made["pin"]}
    assert panel.get("/fleet/panel", headers={"Authorization": ""}).status_code == 401


def test_offline_report_is_recorded_and_alerted(panel):  # noqa: F811
    key = join(panel, host="web-01")["key"]
    body = {"from": "2026-10-26T10:00:00+00:00", "to": "2026-10-26T10:40:00+00:00", "scored": 120,
            "actions": [{"ip": "203.0.113.9", "category": "sql_injection", "reason": "sql_injection: signature",
                         "score": 86, "at": "2026-10-26T10:05:00+00:00", "until": "2026-10-26T11:05:00+00:00",
                         "applied": True, "event_ids": ["evt-1", "evt-2"], "until_ts": 1.0}]}
    r = panel.post("/fleet/offline-report", json=body, headers=as_agent(key))
    assert r.status_code == 200 and r.json()["local_blocks"] == 1
    records = panel.get("/audit").json()["records"]
    local = [x for x in records if x["type"] == "agent_local_block"]
    assert local and local[0]["data"]["host"] == "web-01" and local[0]["data"]["ip"] == "203.0.113.9"
    assert any(x["type"] == "agent_offline_report" for x in records)
    agent = next(a for a in panel.get("/fleet/agents").json() if a["host"] == "web-01")
    assert agent["offline"]["local_blocks"] == 1 and agent["offline"]["scored"] == 120
    notes = panel.core.notifications
    assert any(n["kind"] == "agent_offline_actions" and "203.0.113.9" in n["text"] for n in notes)
    # Only an agent sends one, about itself.
    assert panel.post("/fleet/offline-report", json=body).status_code == 400


def test_agents_port_only_answers_machine_keys(panel):  # noqa: F811
    key = join(panel, host="web-02")["key"]
    guarded = TestClient(serve.agents_only(panel.app, AGENT_ROUTES))
    assert guarded.get("/health").status_code == 200
    assert guarded.get("/blocklist", headers=as_agent(key)).status_code == 200
    assert guarded.get("/blocklist").status_code == 404  # open on the local port, not here
    assert guarded.get("/incidents", headers=AUTH).status_code == 404  # the operator's API stays local
    assert guarded.get("/blocklist", headers=AUTH).status_code == 404
    assert guarded.get("/docs").status_code == 404
    code = panel.post("/fleet/join-codes", json={}).json()["code"]
    assert guarded.post("/fleet/enrol", json={"code": code, "host": "web-03"}).status_code == 200


def test_panel_port_needs_a_certificate(cert):
    assert serve.panel_config(object(), {}) is None
    with pytest.raises(SystemExit, match="SENTRAI_PANEL_CERT"):
        serve.panel_config(object(), {"SENTRAI_PANEL_PORT": "8443"})
    cfg = serve.panel_config(object(), {"SENTRAI_PANEL_PORT": "8443", "SENTRAI_PANEL_CERT": str(cert[0]),
                                        "SENTRAI_PANEL_KEY": str(cert[1])})
    assert cfg.port == 8443 and cfg.host == "0.0.0.0" and cfg.ssl_certfile == str(cert[0]) and cfg.lifespan == "off"
