"""Tuning: the noisiest sources this week and a plain-words suggestion for each."""
from app import ui_tuning as ut

from .conftest import brute_force


def test_false_alarm_and_suggestions():
    assert ut.false_alarm({"status": "rejected"})
    assert ut.false_alarm({"status": "resolved", "resolution": "Our own uptime monitor"})
    assert not ut.false_alarm({"status": "resolved", "resolution": "Blocked, reset password"})
    assert ut.suggest("network", "", 4, 3, 1, False, "198.51.100.0/24")["do"] == "trust"
    assert ut.suggest("machine", "port_scan", 40, 0, 30, False, "web-01")["do"] == "busy"
    assert ut.suggest("machine", "port_scan", 40, 0, 30, True, "web-01")["do"] == "keep"
    assert ut.suggest("machine", "sql_injection", 5, 0, 1, False, "web-01")["do"] == "keep"


def test_endpoint(client):
    brute_force(client)
    brute_force(client, ip="203.0.113.46", start=10)
    brute_force(client, ip="203.0.113.47", start=20)
    page = client.get("/ui/tuning").json()
    assert page["incidents"] >= 1 and page["learning"]["on"] is True and page["learning"]["day"] == 1
    assert page["rows"] and {"machine", "network"} >= {r["kind"] for r in page["rows"]}
    assert all(r["suggestion"]["text"] for r in page["rows"])
