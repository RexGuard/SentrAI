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


def test_all_severities_for_the_bell(client):
    brute_force(client)
    page = client.get("/ui/risks?severity=all").json()
    assert len(page["rows"]) == sum(lv["bubbles"] for lv in page["levels"]) >= 1
    hours = [r["hours"] for r in page["rows"]]
    assert hours == sorted(hours)  # newest first


def test_cards_use_plain_words():
    from app.ui_risks import plain_fix, plain_happened
    inc = {"category": "data_exfiltration", "src_ip": "198.51.100.7", "host": "shop", "needs_review": True,
           "recommended_action": "Block 198.51.100.7 for 2 h"}
    assert plain_happened(inc).startswith("198.51.100.7 asked shop for a large amount of customer data")
    fix = plain_fix(inc)
    assert fix.startswith("Block the IP address mentioned above for 2 hours so that") and "198.51" not in fix
    tamper = {"category": "log_tampering", "host": "shop", "recommended_action": "Investigate manually; no allowlisted playbook applies.",
              "classification_reason": "log-integrity replaced: /var/log/nginx/error.log was swapped after 357560 bytes"}
    assert "/var/log" not in plain_happened(tamper) and "357560" not in plain_happened(tamper)
    assert "SentrAI team" in plain_fix(tamper) and "manually" not in plain_fix(tamper)
