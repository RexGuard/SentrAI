"""Webhook source (POST /webhook/<name>) and the responder webhook."""

import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from app import webhook
from app.config import Settings
from app.main import create_app
from app.responders import BlocklistResponder, WebhookResponder

from .conftest import AUTH, brute_force, ev


WAZUH = {"timestamp": "2026-10-19T10:00:00+0000", "agent": {"name": "db-02"},
         "data": {"srcip": "198.51.100.9", "dstuser": "postgres"},
         "full_log": "sshd[42]: Failed password for postgres from 198.51.100.9 port 4242 ssh2"}


def test_generic_guess_and_source_map():
    e = webhook.to_event({"client_ip": "203.0.113.5", "message": "GET /x 200", "hostname": "edge"}, "nginx")
    assert e["src_ip"] == "203.0.113.5" and e["raw"] == "GET /x 200" and e["host"] == "edge"
    assert e["source"] == "webhook_nginx" and e["layer"] == "web" and e["event_id"].startswith("wh-nginx-")
    maps = webhook.load_maps(json.dumps({"wazuh": {"layer": "=os", "raw": "full_log", "user": "data.dstuser"}}))
    w = webhook.to_events(WAZUH, "wazuh", maps)[0]
    assert (w["src_ip"], w["user"], w["host"], w["layer"]) == ("198.51.100.9", "postgres", "db-02", "os")
    assert w["raw"].startswith("sshd[42]: Failed password")


def test_lists_ids_and_limits():
    assert len(webhook.to_events({"alerts": [{"msg": "a"}, {"msg": "b"}]}, "x")) == 2
    a, b = webhook.to_events([{"msg": "same"}, {"msg": "same"}], "x")
    assert a["event_id"] == b["event_id"]  # a re-delivery is a duplicate, not a second event
    big = webhook.to_event({"message": "A" * 20000}, "x")
    assert len(big["raw"]) == webhook.MAX_RAW
    no_text = webhook.to_event({"severity": 5, "rule": {"id": 1}}, "x")
    assert json.loads(no_text["raw"]) == {"rule": {"id": 1}, "severity": 5}
    for bad in ("../etc", "", "a" * 41):
        try:
            webhook.to_events({}, bad)
            raise AssertionError("accepted a bad name")
        except webhook.WebhookError:
            pass
    assert webhook.load_maps("not json") == {}


def test_webhook_endpoint_ingests_and_cannot_pose_as_heartbeat(client):
    out = client.post("/webhook/waf", json={"src_ip": "198.51.100.23", "source": "heartbeat",
                                            "message": "GET /search?q=' OR 1=1 -- 200"})
    assert out.status_code == 200 and out.json()["accepted"] == 1
    inc = client.get("/incidents").json()[0]
    assert inc["category"] == "sql_injection" and inc["src_ip"] == "198.51.100.23"
    assert client.post("/webhook/bad name", json={}).status_code in (400, 404)
    assert client.post("/webhook/waf", json="just a string").status_code == 400


def test_webhook_needs_the_token(tmp_path):
    app = create_app(Settings(db_path=tmp_path / "c.db", background=False))
    with TestClient(app) as c:
        assert c.post("/webhook/waf", json={"message": "x"}).status_code == 401


def test_blocklist_refuses_unusable_targets():
    r = BlocklistResponder()
    assert r.apply({"type": "block_ip", "target": "203.0.113.1"}) is True
    assert r.apply({"type": "block_ip", "target": "not-an-ip"}) is False
    assert r.apply({"type": "lock_user", "target": ""}) is False
    r.revert({"type": "block_ip", "target": "not-an-ip"})  # never applied: nothing to undo
    assert r.blocklist() == {"ips": ["203.0.113.1"], "users": []}


class Receiver:
    def __init__(self, status=200):
        self.status, self.calls = status, []

    def __call__(self, url, body, headers):
        self.calls.append((url, json.loads(body), headers, body))
        return self.status


def test_responder_webhook_signs_and_reports_failure():
    rx = Receiver()
    hook = WebhookResponder("https://soar.example/hook", ("waf_rule",), secret="s3", poster=rx)
    action = {"action_id": "act-1", "type": "waf_rule", "target": "sqli", "_expires_ts": 1.0}
    assert hook.apply(action) is True
    _, payload, headers, body = rx.calls[0]
    assert payload["op"] == "apply" and "_expires_ts" not in payload
    assert headers["X-SentrAI-Signature"] == "sha256=" + hmac.new(b"s3", body, hashlib.sha256).hexdigest()
    hook.revert(action)
    assert rx.calls[1][1]["op"] == "revert"
    assert WebhookResponder("https://x", ("waf_rule",), poster=Receiver(500)).apply(dict(action)) is False

    def down(*a):
        raise OSError("connection refused")
    assert WebhookResponder("https://x", ("waf_rule",), poster=down).apply(dict(action)) is False


def test_core_sends_containment_to_the_webhook(tmp_path):
    s = Settings(db_path=tmp_path / "c.db", background=False, responder_webhook_url="https://soar.example/hook")
    app = create_app(s)
    with TestClient(app, headers=AUTH) as c:
        rx = Receiver()
        hook = app.state.core.responders.for_type("waf_rule")
        assert isinstance(hook, WebhookResponder)
        hook.poster = rx
        brute_force(c)
        c.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", source="flask_access"))
        sent = {(p["type"], p["target"]) for _, p, _, _ in rx.calls if p["op"] == "apply"}
        assert ("waf_rule", "sqli-signature") in sent and ("block_ip", "203.0.113.45") in sent
        assert "203.0.113.45" in c.get("/blocklist").json()["ips"]  # the built-in blocklist still applies
