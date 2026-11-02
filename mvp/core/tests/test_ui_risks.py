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
    assert b["title"] == "Brute Force" and b["owner"] and b["open_for"] and b["ids"] == [b["incident"]]
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
    assert wave["id"] == "W-1" and len(wave["ids"]) == 3 and wave["title"] == "Port or Web Scan from 3 Addresses"
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


def test_titles_are_in_title_case():
    from app.ui_risks import title_case
    assert title_case("Data exfiltration") == "Data Exfiltration"
    assert title_case("Port or web scan") == "Port or Web Scan"
    assert title_case("SQL injection") == "SQL Injection"
    assert title_case("Cross-site scripting from 3 addresses") == "Cross-Site Scripting from 3 Addresses"


def test_handled_by_sentrai_leaves_the_active_lists(client):
    brute_force(client)
    sev = next(lv["severity"] for lv in client.get("/ui/risks").json()["levels"] if lv["count"])
    iid = client.get(f"/ui/risks?severity={sev}").json()["rows"][0]["incident"]
    client.post("/ui/approvals/bulk", json={"verb": "approve", "ids": [iid], "justification": "block it"})
    assert client.get(f"/incidents/{iid}").json()["status"] == "contained"
    page = client.get(f"/ui/risks?severity={sev}").json()
    assert iid not in {i for r in page["rows"] for i in r["ids"]}
    assert page["handled_count"] >= 1 and iid in {i for r in page["handled"] for i in r["ids"]}
    held = next(r for r in page["handled"] if iid in r["ids"])
    assert "rollback" in {a["verb"] for a in held["actions"]}  # still undoable from "Already handled"
    assert iid not in {i for r in client.get("/ui/risks?severity=all").json()["rows"] for i in r["ids"]}  # the bell
    inc_page = client.get("/ui/incidents").json()
    assert iid not in {r["id"] for r in inc_page["all"]} and iid not in {r["id"] for r in inc_page["todo"]}
    row = next(r for r in client.get("/ui/incidents?closed=true").json()["all"] if r["id"] == iid)
    assert row["handled"] and "Handled by SentrAI" in row["needs"]
    assert iid not in {i["id"] for i in client.get("/ui/approvals").json().get("rows", [])}
    # Undo it: the incident is back with the ones that need a person.
    client.post("/ui/approvals/bulk", json={"verb": "rollback", "ids": [iid], "justification": "false alarm"})
    assert iid in {i for r in client.get(f"/ui/risks?severity={sev}").json()["rows"] for i in r["ids"]}


def test_what_still_needs_a_person_after_an_automatic_block():
    from app.ui_approvals import handled
    block = {"status": "active", "type": "block_ip", "target": "203.0.113.9"}
    base = {"status": "contained", "category": "brute_force", "actions": [block]}
    assert handled(base)
    assert not handled({**base, "needs_review": True})  # the AI was unsure
    assert not handled({**base, "category": "unauthorised_admin"})  # "was this you?"
    assert not handled({**base, "actions": [{**block, "status": "rolled_back"}]})  # nothing in force any more
    assert not handled({**base, "actions": [{**block, "check": {"worked": False}}]})  # did not work
    assert not handled({**base, "actions": [{**block, "check": {"worked": True, "disruption": True}}]})  # hurting users
    assert handled({**base, "actions": [{**block, "check": {"worked": True, "disruption": False}}]})
    assert not handled({**base, "status": "open"})
