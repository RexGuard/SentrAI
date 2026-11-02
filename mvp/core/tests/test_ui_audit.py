"""The web dashboard's Audit trail endpoint."""
from app import ui_audit as ua

from .conftest import brute_force


def test_feed_is_newest_first_and_the_chain_checks_out(client):
    brute_force(client)
    page = client.get("/ui/audit?limit=5").json()
    assert page["chain_valid"] is True and page["count"] >= 5 and len(page["feed"]) == 5
    seqs = [e["seq"] for e in page["feed"]]
    assert seqs == sorted(seqs, reverse=True)
    assert all(e["summary"] and e["agent"] and e["hash"] for e in page["feed"])
    assert page["agents"] and all("records" in a for a in page["agents"])


def test_limit_is_validated(client):
    assert client.get("/ui/audit?limit=0").status_code == 422


def test_words():
    rec = {"type": "admin_signed_in", "data": {"email": "a@b.c", "role": "Owner", "address": "203.0.113.5"}}
    assert ua.summarize(rec).startswith("a@b.c signed in as Owner from 203.0.113.5")
    assert ua.agent_for({"type": "decision", "data": {"operator": "erick"}}) == "Operator:erick"
    assert ua.agent_for({"type": "event"}) == "Warden"


def test_before_pages_back_and_people_are_named(client):
    brute_force(client)
    first = client.get("/ui/audit?limit=3").json()["feed"]
    older = client.get(f"/ui/audit?limit=3&before={first[-1]['seq']}").json()["feed"]
    assert older and all(e["seq"] < first[-1]["seq"] for e in older)
    assert ua.entry({"seq": 1, "type": "decision", "data": {"operator": "erick"}})["person"] == "erick"
    assert ua.entry({"seq": 2, "type": "event"})["person"] == ""


def test_export_to_pdf(client):
    brute_force(client)
    seqs = [e["seq"] for e in client.get("/ui/audit?limit=4").json()["feed"]]
    r = client.post("/ui/audit/pdf", json={"seqs": seqs})
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")
    assert client.post("/ui/audit/pdf", json={"all": True}).content.startswith(b"%PDF")
    assert client.post("/ui/audit/pdf", json={"seqs": []}).status_code == 400
    assert client.post("/ui/audit/pdf", json={"seqs": ["x"]}).status_code == 400
