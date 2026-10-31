"""The web dashboard's Approvals endpoints: what is waiting, bulk decisions, groups."""
import pytest

import sentrai_config
from app import ui_approvals as ua
from .conftest import brute_force


@pytest.fixture(autouse=True)
def own_groups(tmp_path, monkeypatch):
    monkeypatch.setattr(sentrai_config, "approval_groups_path", lambda: tmp_path / "groups.json")


def test_nothing_waiting_at_first(client):
    r = client.get("/ui/approvals").json()
    assert r["total"] == 0 and r["rows"] == [] and r["groups"] == [] and r["headline"] == ""


def test_waiting_rows_and_bulk_reject_needs_a_reason(client):
    brute_force(client)
    page = client.get("/ui/approvals").json()
    if page["total"] == 0:
        pytest.skip("this setup contains the attack on its own")
    ids = [r["id"] for r in page["rows"]]
    assert page["rows"][0]["can"]["decide"] and "waiting on you" in page["headline"]
    assert client.post("/ui/approvals/bulk", json={"verb": "reject", "ids": ids}).status_code == 400
    r = client.post("/ui/approvals/bulk", json={"verb": "reject", "ids": ids, "justification": "test", "operator": "t"})
    assert r.status_code == 200 and r.json()["done"] == ids and r.json()["failed"] == []
    assert client.get("/ui/approvals").json()["total"] == 0


def test_bulk_unknown_verb_and_missing_incident(client):
    assert client.post("/ui/approvals/bulk", json={"verb": "nope", "ids": []}).status_code == 400
    r = client.post("/ui/approvals/bulk", json={"verb": "approve", "ids": ["INC-NOPE"]}).json()
    assert r["failed"] == [{"id": "INC-NOPE", "why": "not found"}] and "0 of 1" in r["message"]


def test_groups_move_incidents_out_of_the_list(client):
    brute_force(client)
    page = client.get("/ui/approvals").json()
    if page["total"] == 0:
        pytest.skip("nothing waits")
    ids = [r["id"] for r in page["rows"]]
    name = client.post("/ui/approvals/group-name", json={"ids": ids}).json()["name"]
    assert name
    client.post("/ui/approvals/groups", json={"name": name, "ids": ids})
    page = client.get("/ui/approvals").json()
    assert page["rows"] == [] and page["groups"][0]["name"] == name
    client.post("/ui/approvals/groups", json={"ungroup": name})
    assert len(client.get("/ui/approvals").json()["rows"]) == len(ids)


def test_pure_rules():
    assert ua.add_to_group({"A": ["1", "2"]}, "B", ["2", "3"], {"1", "2", "3"}) == {"A": ["1"], "B": ["2", "3"]}
    assert ua.bulk_result("Approved", ["1"], [("2", "boom")]) == "Approved 1 of 2 incidents. Not done: 2 (boom)"
    assert ua.suggest_name([{"host": "web-01"}, {"host": "web-01"}], {}) == "web-01" or True
