"""Lessons backed by incidents (app/lessons.py): suggested from staff closures, confirmed by a person, withdrawn
by a counterexample, and never for the kinds of alert that must stay loud."""
from io import StringIO

import pytest

import sentrai_config
from app import lessons as ls
from .conftest import ev


@pytest.fixture(autouse=True)
def own_groups(tmp_path, monkeypatch):
    monkeypatch.setattr(sentrai_config, "approval_groups_path", lambda: tmp_path / "groups.json")


def inc(i, **kw):
    return {"id": f"RSK-{i}", "category": "brute_force", "src_ip": f"203.0.113.{i}", "status": "rejected",
            "closed_at": 1_000_000.0, "decisions": [], "actions": [], **kw}


def store(tmp_path, now=1_000_100.0):
    return ls.Lessons(tmp_path / "lessons.json", clock=lambda: now)


def test_two_closures_from_one_network_suggest_a_lesson(tmp_path):
    s = store(tmp_path)
    assert s.build([inc(1)]) == []  # one is not a pattern
    [lesson] = s.build([inc(1), inc(2)])
    assert lesson["key"] == "brute_force|203.0.113.0/24" and lesson["state"] == "suggested"
    assert lesson["evidence"] == ["RSK-1", "RSK-2"] and "RSK-1, RSK-2" in lesson["words"]


def test_never_learned_kinds_decoys_and_no_address(tmp_path):
    s = store(tmp_path)
    assert s.build([inc(1, category="malware"), inc(2, category="malware")]) == []
    assert s.build([inc(1, classification_reason="Tripwire: x"), inc(2, classification_reason="Tripwire: x")]) == []
    assert s.build([inc(1, src_ip=None), inc(2, src_ip=None)]) == []


def test_old_evidence_stops_counting(tmp_path):
    s = store(tmp_path, now=1_000_000.0 + (ls.KEEP_DAYS + 1) * 86400)
    assert s.build([inc(1), inc(2)]) == []


def test_confirm_then_a_real_attack_withdraws_it(tmp_path):
    s = store(tmp_path)
    two = [inc(1), inc(2)]
    out = s.decide("brute_force|203.0.113.0/24", True, "owner@x", two)
    assert out["state"] == "confirmed" and out["by"] == "owner@x"
    new = {"id": "RSK-9", "category": "brute_force", "src_ip": "203.0.113.50", "status": "open"}
    assert s.match(new, two)["evidence"] == ["RSK-1", "RSK-2"]
    real = inc(3, status="contained", decisions=[{"decision": "approve"}])
    [lesson] = s.build([*two, real])
    assert lesson["state"] == "withdrawn" and lesson["against"] == ["RSK-3"] and "real attack" in lesson["words"]
    assert s.match(new, [*two, real]) is None
    with pytest.raises(ValueError):
        s.decide(lesson["key"], True, "owner@x", [*two, real])  # the evidence no longer backs a yes
    with pytest.raises(KeyError):
        s.decide("port_scan|198.51.100.0/24", True, "owner@x", two)


def test_no_is_kept_and_forget_works_it_out_again(tmp_path):
    s = store(tmp_path)
    two = [inc(1), inc(2)]
    assert s.decide("brute_force|203.0.113.0/24", False, "owner@x", two)["state"] == "dismissed"
    assert s.build(two)[0]["state"] == "dismissed" and s.confirmed(two) == {}
    assert s.forget("brute_force|203.0.113.0/24") and s.build(two)[0]["state"] == "suggested"
    assert not s.forget("nope")


def xss(client, n, ip):
    return client.post("/events", json=ev(n, "GET /search?q=<script>alert(1)</script> 200", ip=ip, user=None,
                                          source="flask_access")).json()


def test_end_to_end_through_the_panel(client):
    for n, ip in ((1, "198.51.100.7"), (2, "198.51.100.8")):
        xss(client, n, ip)
    ids = [i["id"] for i in client.get("/incidents").json() if i["category"] == "xss" and i["status"] == "open"]
    if len(ids) < 2:
        pytest.skip("these lines joined one incident here")
    client.post("/ui/approvals/bulk", json={"verb": "reject", "ids": ids, "justification": "our own scanner"})
    page = client.get("/ui/lessons").json()
    assert page["suggested"] == 1
    key = page["lessons"][0]["key"]
    assert key == "xss|198.51.100.0/24"
    r = client.post("/ui/lessons/decide", json={"key": key, "yes": True})
    assert r.status_code == 200 and r.json()["lesson"]["state"] == "confirmed"
    assert any(x["type"] == "lesson_confirmed" and x["data"]["evidence"] == sorted(ids) for x in client.core.audit.records())
    xss(client, 3, "198.51.100.9")
    new = next(i for i in client.get("/incidents").json() if i["category"] == "xss" and i["status"] == "open")
    rows = client.get("/ui/risks?severity=all").json()["rows"]
    assert "not a threat 2 times" in next(b for b in rows if b["incident"] == new["id"])["seen_before"]
    risk = next(r for r in client.get("/ui/approvals").json()["rows"] if r["id"] == new["id"])["risk"]
    assert any("as not a threat 2 times before" in why for why in risk["reasons"])
    # a person treats this one as real: the lesson is withdrawn, naming it
    client.post("/ui/approvals/bulk", json={"verb": "approve", "ids": [new["id"]]})
    lesson = client.get("/ui/lessons").json()["lessons"][0]
    assert lesson["state"] == "withdrawn" and new["id"] in lesson["against"]
    assert client.post("/ui/lessons/decide", json={"key": key, "yes": True}).status_code == 409
    assert client.post("/ui/lessons/decide", json={"key": "nope", "yes": True}).status_code == 404


def test_cli_lessons(client):
    import sentrai_cli as cli
    from .test_cli import through
    out = StringIO()
    cli.main(["lessons", "list"], call=through(client), out=out)
    assert "No lessons yet" in out.getvalue()
