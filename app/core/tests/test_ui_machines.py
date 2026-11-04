"""The web dashboard's Machines endpoints."""
from datetime import datetime, timezone

from app import ui_machines as um

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)


def test_local_machine_when_not_a_panel(client):
    page = client.get("/ui/machines").json()
    assert page["panel"] is False and len(page["machines"]) == 1
    assert page["machines"][0]["place"] == "Local" and page["stats"]["machines"] == 1


def test_join_code_needs_an_address_and_gives_commands(client):
    assert client.post("/ui/machines/join-code", json={}).status_code == 400
    r = client.post("/ui/machines/join-code", json={"panel_url": "https://panel.example.test:8443", "name": "web-01"}).json()
    assert r["https"] and r["code"] in r["commands"]["linux"] and "--name web-01" in r["commands"]["linux"]
    assert "-Panel https://panel.example.test:8443" in r["commands"]["windows"]


def test_panel_rows_worst_first_with_waiting_agent():
    risk = {"threshold": 80}
    found = [{"host": "a", "risk_index": 10, "open_incidents": 0}, {"host": "b", "risk_index": 70, "open_incidents": 2}]
    agents = [{"host": "c", "agent_id": "ag-1"}]
    rows = um.build(found, agents, risk, True, "x", NOW)
    assert [r["name"] for r in rows] == ["b", "a", "c"]
    assert next(r for r in rows if r["name"] == "c")["waiting"] is True
    assert next(r for r in rows if r["name"] == "b")["band"] == "red"


def test_seen_ago_words():
    assert um.seen_ago(None, NOW) == "never"
    assert um.seen_ago("2026-10-31T11:59:55+00:00", NOW) == "just now"
    assert um.seen_ago("2026-10-31T11:53:00+00:00", NOW) == "7 min ago"
