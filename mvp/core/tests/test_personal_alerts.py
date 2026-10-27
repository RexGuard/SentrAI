"""Personal Telegram alerts: linking a contact's private chat, and who handled it in the evidence report."""

import json

from .conftest import brute_force
from .test_routing import ROUTING, pending, routed_client


def link(c, contact="amir", chat="5551001", username="amir"):
    code = c.post("/telegram/link-codes", json={"operator": "erick", "contact": contact}).json()["code"]
    return c.post("/telegram/link", json={"code": code, "chat_id": chat, "username": username})


def test_a_link_code_puts_the_persons_chat_on_their_alerts(tmp_path):
    c = routed_client(tmp_path)
    made = c.post("/telegram/link-codes", json={"operator": "erick", "contact": "Amir"}).json()
    assert made["name"] == "Amir" and len(made["code"]) == 8 and made["send"] == f"/link {made['code']}"
    r = c.post("/telegram/link", json={"code": made["code"].lower(), "chat_id": 5551001, "username": "@amir"})
    assert r.status_code == 200 and r.json()["name"] == "Amir" and r.json()["username"] == "amir"
    # A code works once.
    again = c.post("/telegram/link", json={"code": made["code"], "chat_id": "5551002"})
    assert again.status_code == 400 and "Ask for a new one" in again.json()["detail"]
    brute_force(c)
    n = pending(c, "incident_opened")[0]
    by_name = {d["name"]: d for d in n["deliver_to"]}
    assert by_name["Amir"]["telegram_chat"] == "5551001" and by_name["Lee"]["telegram_chat"] == ""
    contacts = {x["id"]: x for x in c.get("/routing").json()["contacts"]}
    assert contacts["amir"]["telegram_linked"] and not contacts["lee"]["telegram_linked"]
    assert [x["chat_id"] for x in c.get("/telegram/links").json()] == ["5551001"]
    types = [r["type"] for r in c.get("/audit").json()["records"]]
    assert "telegram_link_code" in types and "telegram_linked" in types


def test_links_survive_a_restart_and_unlink_removes_them(tmp_path):
    c = routed_client(tmp_path)
    assert link(c).status_code == 200
    saved = json.loads((tmp_path / "people" / "telegram_links.json").read_text(encoding="utf-8"))
    assert saved["links"][0]["contact_id"] == "amir"
    c2 = routed_client(tmp_path)
    assert [x["name"] for x in c2.get("/telegram/links").json()] == ["Amir"]
    assert c2.post("/telegram/unlink", json={"operator": "amir", "chat_id": "5551001"}).json()["unlinked"]
    assert c2.get("/telegram/links").json() == []
    assert c2.post("/telegram/unlink", json={"operator": "amir", "contact": "amir"}).status_code == 404


def test_one_chat_belongs_to_one_person(tmp_path):
    c = routed_client(tmp_path)
    link(c, "amir", "777")
    link(c, "lee", "777")  # the same phone linked again for Lee: it moves, it is not shared
    assert [(x["contact_id"], x["chat_id"]) for x in c.get("/telegram/links").json()] == [("lee", "777")]


def test_unknown_contact_and_bad_codes(tmp_path):
    c = routed_client(tmp_path)
    assert c.post("/telegram/link-codes", json={"operator": "erick", "contact": "nobody"}).status_code == 404
    assert c.post("/telegram/link", json={"code": "ABCDEFGH", "chat_id": "1"}).status_code == 400
    code = c.post("/telegram/link-codes", json={"operator": "erick", "contact": "lee"}).json()["code"]
    assert c.post("/telegram/link", json={"code": code, "chat_id": "not-a-chat"}).status_code == 400


def test_a_chat_id_in_the_routing_file_counts_as_linked(tmp_path):
    routing = json.loads(json.dumps(ROUTING))
    routing["contacts"]["lee"]["telegram"] = "4242"
    c = routed_client(tmp_path, routing)
    assert [(x["name"], x["linked_by"]) for x in c.get("/telegram/links").json()] == [("Lee", "routing file")]
    brute_force(c)
    lee = next(d for d in pending(c, "incident_opened")[0]["deliver_to"] if d["name"] == "Lee")
    assert lee["telegram_chat"] == "4242"


def test_direct_delivery_receipts_name_the_person(tmp_path):
    c = routed_client(tmp_path)
    link(c)
    brute_force(c)
    n = pending(c, "incident_opened")[0]
    c.post(f"/notifications/{n['id']}/delivered", json={"channel": "telegram-direct", "message_id": 11, "to": "Amir"})
    c.post(f"/notifications/{n['id']}/delivered", json={"channel": "telegram", "message_id": 12})
    full = next(x for x in c.get("/notifications").json() if x["id"] == n["id"])
    assert [(d["channel"], d["to"]) for d in full["deliveries"]] == [("telegram-direct", "Amir"), ("telegram", None)]
    report = c.get("/reports/RSK-2026-081").json()
    line = next(d for d in report["non_repudiation"]["deliveries"] if d["notification"] == n["id"])
    assert line["reached"][0].startswith("Amir directly in Telegram at ")
    assert line["reached"][1].startswith("in the team Telegram group at ")
    assert report["handling"]["reached_directly"] == ["Amir"]
    assert "Alerts reached Amir in their own Telegram chat." in report["in_plain_words"]


def test_report_shows_owner_escalation_and_resolution(tmp_path):
    c = routed_client(tmp_path)
    brute_force(c)
    for hours in (2.5, 1, 1):  # two unanswered reminders to Amir, then Lee (the backup) takes over
        c.core.advance(hours)
    c.post("/incidents/RSK-2026-081/assign", json={"operator": "Lee", "assignee": "Dana", "note": "Knows the box"})
    c.post("/incidents/RSK-2026-081/resolve", json={"operator": "Dana", "note": "Password reset, IP blocked."})
    r = c.get("/reports/RSK-2026-081").json()
    h = r["handling"]
    assert h["owner"] == "Dana" and h["route"] == "High" and h["escalation_level"] == 1
    assert h["escalations"][0]["from"] == "Amir" and h["escalations"][0]["to"] == "Lee"
    assert h["resolution"]["by"] == "Dana" and h["resolution"]["note"] == "Password reset, IP blocked."
    steps = [e["event"] for e in h["history"]]
    assert steps[0] == 'Given to Amir by the routing rule "High" (backup: Lee); also told: Lee'
    assert any(s.startswith("Escalated from Amir to the backup Lee (level 1)") for s in steps)
    assert "Handed from Lee to Dana by Lee: Knows the box" in steps
    assert steps[-1] == "Resolved by Dana: Password reset, IP blocked."
    assert all(isinstance(e["seq"], int) for e in h["history"])  # each step points at its audit record
    assert r["responsible_entity"] == "Dana"
    story = r["in_plain_words"]
    assert 'It was given to Amir under the rule "High".' in story
    assert "Amir did not answer, so it moved to the backup, Lee." in story
    assert story.endswith("Dana closed it: Password reset, IP blocked.")
    md = c.get("/reports/RSK-2026-081.md").text
    assert "## Who handled it" in md and "| Owner now | Dana (backup: Lee) |" in md
    assert "| Closed | Dana at " in md
    pdf = c.get("/reports/RSK-2026-081.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")


def test_report_of_an_open_incident_says_not_closed(client):
    brute_force(client)
    h = client.get("/reports/RSK-2026-081").json()["handling"]
    assert h["resolution"] is None and h["history"][0]["kind"] == "incident_opened"
    assert "| Closed | Not yet |" in client.get("/reports/RSK-2026-081.md").text
