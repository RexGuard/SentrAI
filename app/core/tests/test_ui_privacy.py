"""The web dashboard's Privacy page: the data inventory, the retention policy and the staff notice."""
from app import ui_privacy as up

from .conftest import brute_force


def test_policy_defaults_save_and_checks(tmp_path):
    pol = up.PrivacyPolicy(tmp_path / "privacy.json")
    assert pol.load()["months"]["events"] == 6 and pol.load()["months"]["accounts"] is None
    saved = pol.save({"organisation": "Acme School", "months": {"events": 3, "backups": None}}, "erick@example.com")
    assert saved["months"]["events"] == 3 and saved["updated_by"] == "erick@example.com"
    assert pol.load()["organisation"] == "Acme School"
    for bad in ({"months": {"nope": 1}}, {"months": {"events": 999}}, {"months": {"events": True}}, {"months": {"events": "6"}}):
        try:
            pol.save(bad, "x")
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted {bad}")


def test_endpoints_and_notice(client):
    brute_force(client)
    page = client.get("/ui/privacy").json()
    keys = [k["key"] for k in page["kinds"]]
    assert {"events", "staff_activity", "audit", "ai"} <= set(keys)
    audit = next(k for k in page["kinds"] if k["key"] == "audit")
    assert audit["oldest_days"] == 0 and audit["over"] is False
    r = client.post("/ui/privacy", json={"organisation": "Acme", "contact": "dpo@acme.test", "months": {"events": 1}})
    assert r.status_code == 200 and r.json()["policy"]["months"]["events"] == 1
    assert client.post("/ui/privacy", json={"months": {"events": -1}}).status_code == 400
    assert any(rec["type"] == "privacy_policy_changed" for rec in client.get("/audit").json()["records"])
    md = client.get("/ui/privacy/notice.md")
    assert md.status_code == 200 and "How Acme uses SentrAI" in md.text and "dpo@acme.test" in md.text
    assert "1 month" in md.text and "Warden" not in md.text and "Cyanide" not in md.text
