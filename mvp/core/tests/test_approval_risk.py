"""The plain risk tag on each approval: fixed rules, the same answer every time, a reason for every point."""
import pytest

import sentrai_config
from app import approval_risk as ar
from app import ui_approvals as ua
from .conftest import brute_force


@pytest.fixture(autouse=True)
def own_groups(tmp_path, monkeypatch):
    monkeypatch.setattr(sentrai_config, "approval_groups_path", lambda: tmp_path / "groups.json")


def inc(**kw):
    return {"id": "INC-1", "status": "open", "host": "web-01", "src_ip": "203.0.113.9", "category": "brute_force",
            "classified_by": "rules", "ai_confidence": 0.95, "needs_review": False, "asset_criticality": 1.0, **kw}


def block(target="203.0.113.9", **kw):
    return [{"type": "block_ip", "target": target, "allowed": True, **kw}]


def test_rule_confirmed_outside_block_is_low():
    tag = ar.score(inc(), block())
    assert tag["level"] == "low" and tag["word"] == "Low risk to approve"
    assert any("blocks one internet address" in r for r in tag["reasons"])
    assert any("fixed rule" in r for r in tag["reasons"])
    assert ar.score(inc(), block()) == tag  # the same incident always gets the same tag


def test_locking_the_admin_account_is_high():
    tag = ar.score(inc(classified_by="ai", ai_confidence=0.6),
                   [{"type": "lock_user", "target": "admin", "allowed": True}])
    assert tag["level"] == "high" and tag["score"] >= 60
    assert any("administrator account" in r for r in tag["reasons"]) and any("60% sure" in r for r in tag["reasons"])


def test_private_address_and_admin_address_raise_it():
    private = ar.score(inc(), block("192.168.1.20"))
    assert private["level"] in ("medium", "high") and any("inside your own network" in r for r in private["reasons"])
    admin = ar.score(inc(), block(admin_address=True))
    assert admin["level"] == "medium" and any("administrators has signed in" in r for r in admin["reasons"])


def test_unsure_check_spread_and_important_machine_add_up():
    base = ar.score(inc(), block())["score"]
    tag = ar.score(inc(needs_review=True, asset_criticality=2.0), block(), seen_on={"web-01", "db-01", "mail-01"})
    assert tag["score"] > base + 40
    assert any("unsure" in r for r in tag["reasons"]) and any("2 other computers" in r for r in tag["reasons"])
    assert any("important computer" in r for r in tag["reasons"])


def test_a_decoy_touch_lowers_it_and_held_back_fixes_do_not_count():
    plain = ar.score(inc(classified_by="ai", ai_confidence=0.9), block())["score"]
    decoy = ar.score(inc(classified_by="ai", ai_confidence=0.9, classification_reason="Tripwire: opened a decoy page"),
                     block())
    assert decoy["score"] < plain and any("decoy" in r for r in decoy["reasons"])
    held = ar.score(inc(), block(allowed=False))
    assert any("could not tell" in r for r in held["reasons"])


def test_contained_uses_the_blocks_in_force():
    tag = ar.score(inc(status="contained", actions=[{"type": "block_ip", "target": "203.0.113.9", "status": "active"}]))
    assert any("already in force" in r for r in tag["reasons"]) and any("blocks one" in r for r in tag["reasons"])


def test_scores_stay_between_0_and_100():
    many = [{"type": "lock_user", "target": "root", "allowed": True}] * 5
    assert ar.score(inc(needs_review=True), many)["score"] == 100
    assert ar.score(inc(classification_reason="Tripwire: x"), [{"type": "waf_rule", "target": "/x", "allowed": True}])["score"] == 0


def test_low_risk_ids_skip_root_alerts_and_unsure_ones():
    waiting = [inc(id="A"), inc(id="B", needs_review=True), inc(id="C", category=ua.ADMIN_CATEGORY), inc(id="D")]
    tags = {"A": {"level": "low"}, "B": {"level": "low"}, "C": {"level": "low"}, "D": {"level": "medium"}}
    assert ua.low_risk_ids(waiting, tags) == ["A"]


def test_approvals_page_carries_the_tag_and_approves_low(client):
    brute_force(client)
    page = client.get("/ui/approvals").json()
    if page["total"] == 0:
        pytest.skip("this setup contains the attack on its own")
    r = page["rows"][0]
    assert r["risk"]["level"] in ("low", "medium", "high") and r["risk"]["reasons"]
    assert any("203.0.113.45" in why for why in r["risk"]["reasons"])  # names what a yes would block
    assert client.get("/ui/approvals?sort=risk").json()["total"] == page["total"]
    assert client.get("/ui/approvals?brief=1").json()["low_risk"] == page["low_risk"]
    out = client.post("/ui/approvals/approve-low", json={}).json()
    assert out["done"] == page["low_risk"]
    if not page["low_risk"]:
        assert out["message"] == "Nothing low risk is waiting."


def test_cli_waiting_shows_the_risk(client):
    from io import StringIO
    import sentrai_cli as cli

    def call(method, path, body=None):
        r = client.request(method, path, json=body)
        return r.json()

    brute_force(client)
    out = StringIO()
    cli.main(["incidents", "waiting", "--why-risk"], call=call, out=out)
    text = out.getvalue()
    assert "Nothing is waiting on you." in text or ("Risk" in text and "low risk to approve" in text)
