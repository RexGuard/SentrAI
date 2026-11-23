"""The owner picks how long a fix lasts on approve; SentrAI suggests what they picked before (app/fix_length.py)."""
import pytest

import sentrai_config
from app import fix_length as fl
from .conftest import ev


@pytest.fixture(autouse=True)
def own_groups(tmp_path, monkeypatch):
    monkeypatch.setattr(sentrai_config, "approval_groups_path", lambda: tmp_path / "groups.json")


def test_check_refuses_unreasonable_lengths_in_plain_words():
    assert fl.check(4, 24) is None and fl.check("2.5", 24) is None
    assert "15 minutes" in fl.check(0.1, 24) and "number of hours" in fl.check("soon", 24)
    long = fl.check(48, 24)
    assert "24 hours" in long and "Keep the block" in long
    assert fl.check(48, 0) is None  # no limit set
    assert fl.check(float("nan"), 24)


def test_choices_stay_within_the_limit_and_include_the_usual():
    assert fl.choices(8, 3) == [1.0, 2.0, 3, 4.0, 8.0]
    assert fl.words(0.5) == "30 minutes" and fl.words(1) == "1 hour" and fl.words(4) == "4 hours"


def appr(i, hours, at):
    return {"id": f"RSK-{i}", "category": "brute_force",
            "decisions": [{"decision": "approve", "hours": hours, "at": at}]}


def test_suggest_needs_the_last_two_to_agree():
    new = {"id": "RSK-9", "category": "brute_force"}
    assert fl.suggest(new, [appr(1, 4, "2026-11-01")], 2, 24) is None
    s = fl.suggest(new, [appr(1, 4, "2026-11-01"), appr(2, 4, "2026-11-02")], 2, 24)
    assert s["hours"] == 4 and s["evidence"] == ["RSK-1", "RSK-2"] and "4 hours the last 2 times" in s["because"]
    assert fl.suggest(new, [appr(1, 4, "2026-11-01"), appr(2, 8, "2026-11-02")], 2, 24) is None
    assert fl.suggest(new, [appr(1, 2, "2026-11-01"), appr(2, 2, "2026-11-02")], 2, 24) is None  # that is the usual
    assert fl.suggest(new, [appr(1, 4, "2026-11-01"), appr(2, 4, "2026-11-02")], 2, 3) is None  # over the limit now
    assert fl.suggest({"id": "x", "category": "xss"}, [appr(1, 4, "a"), appr(2, 4, "b")], 2, 24) is None


def xss(client, n, ip):
    client.post("/events", json=ev(n, "GET /search?q=<script>alert(1)</script> 200", ip=ip, user=None,
                                   source="flask_access"))
    return next(i for i in client.get("/incidents").json() if i["src_ip"] == ip)


def test_approve_with_a_length_and_the_next_one_suggests_it(client):
    first = xss(client, 1, "198.51.100.7")
    if first["status"] != "open":
        pytest.skip("this setup acts on its own")
    row = next(r for r in client.get("/ui/approvals").json()["rows"] if r["id"] == first["id"])
    assert row["length"]["usual"] > 0 and row["length"]["suggested"] is None
    bad = client.post("/ui/approvals/bulk", json={"verb": "approve", "ids": [first["id"]], "hours": 500})
    assert bad.status_code == 400 and "Keep the block" in bad.json()["detail"]
    assert client.post("/ui/approvals/bulk", json={"verb": "reject", "ids": [first["id"]], "hours": 4,
                                                   "justification": "x"}).status_code == 400
    r = client.post("/ui/approvals/bulk", json={"verb": "approve", "ids": [first["id"]], "hours": 3})
    assert r.status_code == 200 and r.json()["done"] == [first["id"]]
    done = client.get(f"/incidents/{first['id']}").json()
    assert done["decisions"][-1]["hours"] == 3
    assert done["actions"] and all(a["ttl_hours"] == 3 for a in done["actions"])
    second = xss(client, 2, "198.51.100.8")
    client.post(f"/incidents/{second['id']}/decision", json={"operator": "t", "decision": "approve", "hours": 3})
    third = xss(client, 3, "198.51.100.9")
    row = next(r for r in client.get("/ui/approvals").json()["rows"] if r["id"] == third["id"])
    assert row["length"]["suggested"]["hours"] == 3 and first["id"] in row["length"]["suggested"]["evidence"]


def test_cli_hours_only_with_approve(client):
    from io import StringIO
    import sentrai_cli as cli
    from .test_cli import through
    out = StringIO()
    assert cli.main(["incidents", "reject", "RSK-1", "--why", "x", "--hours", "2"], call=through(client), out=out) != 0
