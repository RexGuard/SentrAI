"""After an attack: the recovery checklist per incident, ticks on the audit record, the backup to restore from."""
from app import ui_recovery as ur

from .conftest import brute_force


def test_steps_per_kind_and_common():
    phases = ur.steps_for("brute_force")
    assert [p["key"] for p in phases] == ["contain", "secure", "restore", "tell", "learn"]
    secure = [s["text"] for s in phases[1]["steps"]]
    assert secure[0].startswith("Reset the password") and any("API keys" in t for t in secure)
    assert any("PDPA" in s["text"] for s in phases[3]["steps"])
    assert len({s["id"] for p in phases for s in p["steps"]}) == sum(len(p["steps"]) for p in phases)
    assert ur.steps_for("something_new")[0]["steps"]  # an unknown kind still gets the common plan


class FakeBackups:
    def status(self):
        return {"backups": [
            {"id": "B-new", "created": "2030-01-01T00:00:00+00:00", "verified": {"ok": True}},
            {"id": "B-old", "created": "2020-01-01T00:00:00+00:00", "verified": {"ok": None}},
            {"id": "B-good", "created": "2021-01-01T00:00:00+00:00", "verified": {"ok": True}},
        ]}


def test_backup_before_prefers_checked():
    b = ur.backup_before(FakeBackups(), 1700000000.0)
    assert b["id"] == "B-good" and b["checked"] is True
    assert ur.backup_before(None, 1.0) is None and ur.backup_before(FakeBackups(), 1.0) is None


def test_endpoints(client):
    brute_force(client)
    inc = client.get("/incidents").json()
    iid = (inc["incidents"] if isinstance(inc, dict) else inc)[0]["id"]
    plan = client.get("/ui/recovery", params={"incident": iid}).json()
    assert plan["done"] == 0 and plan["total"] > 8 and plan["what"] == "Password guessing"
    r = client.post("/ui/recovery/check", json={"incident": iid, "step": "secure-1", "done": True})
    assert r.status_code == 200 and r.json()["done"] == 1
    assert r.json()["phases"][1]["steps"][0]["done"]["by"]
    assert client.post("/ui/recovery/check", json={"incident": iid, "step": "nope-9"}).status_code == 400
    assert client.post("/ui/recovery/check", json={"incident": "INC-none", "step": "secure-1"}).status_code == 404
    assert client.get("/ui/recovery", params={"incident": "INC-none"}).status_code == 404
    recs = [x for x in client.get("/audit").json()["records"] if x["type"] == "recovery_step"]
    assert recs and recs[-1]["data"]["step"] == "secure-1"
    assert client.post("/ui/recovery/check", json={"incident": iid, "step": "secure-1", "done": False}).json()["done"] == 0
