"""The Command center's risk bubbles: approvals and incidents that need a person, one list per severity."""
from app import ui_risks as ui

from .conftest import brute_force, ev


def test_counts_per_severity_and_rows_of_one(client):
    brute_force(client)
    page = client.get("/ui/risks").json()
    assert [lv["severity"] for lv in page["levels"]] == ["critical", "high", "medium", "low"]
    assert "rows" not in page and sum(lv["count"] for lv in page["levels"]) >= 1
    sev = next(lv["severity"] for lv in page["levels"] if lv["count"])
    rows = client.get(f"/ui/risks?severity={sev}").json()["rows"]
    b = rows[0]
    assert b["title"] == "Brute force" and b["owner"] and b["open_for"] and b["ids"] == [b["incident"]]
    assert b["what_happened"] and b["meaning"] and b["fix"] and b["steps"]
    assert {a["verb"] for a in b["actions"]} >= {"approve", "reject"}
    assert all(a["label"] and a["hint"] for a in b["actions"])
    assert client.get("/ui/risks?severity=nope").status_code == 400


def test_a_decided_incident_leaves_the_bubbles(client):
    brute_force(client)
    sev = next(lv["severity"] for lv in client.get("/ui/risks").json()["levels"] if lv["count"])
    iid = client.get(f"/ui/risks?severity={sev}").json()["rows"][0]["incident"]
    client.post("/ui/approvals/bulk", json={"verb": "reject", "ids": [iid], "justification": "test traffic"})
    rows = client.get(f"/ui/risks?severity={sev}").json()["rows"]
    assert iid not in {i for r in rows for i in r["ids"]}


def test_waves_become_one_bubble_and_rules():
    members = [{"id": f"RSK-2026-00{n}", "status": "open", "severity": "high", "category": "port_scan",
                "src_ip": f"198.51.100.{n}", "wave": "W-1", "host": "web-01"} for n in range(1, 4)]
    single = {"id": "RSK-2026-009", "status": "open", "severity": "critical", "category": "log_tampering"}
    rows = ui.bubbles([*members, single])
    assert [r["severity"] for r in rows] == ["critical", "high"]
    wave = rows[1]
    assert wave["id"] == "W-1" and len(wave["ids"]) == 3 and wave["title"] == "Port or web scan from 3 addresses"
    assert rows[0]["owner"] == "Nobody yet" and "erase" in rows[0]["meaning"]
    assert not ui.needs_person({"status": "resolved"})
    assert ui.headline(ui.summary(rows, [])) == "4 things need a person. Start with Critical."


def test_my_fix_without_a_model_offers_the_matching_button(client):
    brute_force(client)
    iid = client.get("/incidents").json()[0]["id"]
    reply = client.post("/chat", json={"operator": "erick", "message": f"My fix for {iid}: block that address",
                                       "incident": iid}).json()
    assert reply["source"] == "fallback" and "That works" in reply["text"]
    assert reply["suggestions"][0]["decision"] == "approve" and reply["suggestions"][0]["incident"] == iid
    reply = client.post("/chat", json={"operator": "erick", "message": f"My fix for {iid}: it is a false alarm",
                                       "incident": iid}).json()
    assert reply["suggestions"][0]["decision"] == "reject"
    reply = client.post("/chat", json={"operator": "erick", "message": f"My fix for {iid}: phone the vendor",
                                       "incident": iid}).json()
    assert "by hand" not in reply["text"] and "without an AI model" in reply["text"]
    assert reply["suggestions"] and reply["suggestions"][0]["decision"] == "approve"
    assert client.get(f"/incidents/{iid}").json()["status"] == "open"  # chat never acts on its own
