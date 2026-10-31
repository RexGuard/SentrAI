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
