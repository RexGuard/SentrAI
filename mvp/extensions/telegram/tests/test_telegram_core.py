"""Telegram extension, core side: linking a contact's private chat with a one-time code, and what changes
when the extension is removed (its routes answer 404, alerts carry no chat ids, the links are kept)."""

import json

from conftest import brute_force

ROUTING = {
    "contacts": {
        "amir": {"name": "Amir", "role": "on_duty", "email": "amir@example.test", "telegram": "@amir", "backup": "lee"},
        "lee": {"name": "Lee", "role": "team_lead", "email": "lee@example.test", "backup": "it"},
        "it": {"name": "Ika", "role": "it_manager", "backup": "boss"},
        "boss": {"name": "Boss", "role": "cxo", "email": "boss@example.test"},
    },
    "rules": [{"name": "High", "match": {"severity": ["high"]}, "owner": "amir", "notify": ["lee"]}],
    "follow_up": {"escalate_after_reminders": 2, "max_escalations": 2, "resolve_within_hours": 4},
}
BOT = {"TELEGRAM_BOT_TOKEN": "123456:test-token", "TELEGRAM_CHAT_ID": "-1001"}
IID = "RSK-2026-081"


def routed(make_core, routing=ROUTING, **env):
    return make_core(routing=routing, **{**BOT, **env})


def link(c, contact="amir", chat="5551001", username="amir"):
    code = c.post("/telegram/link-codes", json={"operator": "erick", "contact": contact}).json()["code"]
    return c.post("/telegram/link", json={"code": code, "chat_id": chat, "username": username})


def pending(c, kind=None):
    return [n for n in c.get("/notifications/pending").json()
            if n["incident"] == IID and (kind is None or n["kind"] == kind)]


def test_a_link_code_puts_the_persons_chat_on_their_alerts(make_core):
    c = routed(make_core)
    made = c.post("/telegram/link-codes", json={"operator": "erick", "contact": "Amir"}).json()
    assert made["name"] == "Amir" and len(made["code"]) == 8 and made["send"] == f"/link {made['code']}"
    r = c.post("/telegram/link", json={"code": made["code"].lower(), "chat_id": 5551001, "username": "@amir"})
    assert r.status_code == 200 and r.json()["name"] == "Amir" and r.json()["username"] == "amir"
    # A code works once.
    again = c.post("/telegram/link", json={"code": made["code"], "chat_id": "5551002"})
    assert again.status_code == 400 and "Ask for a new one" in again.json()["detail"]
    brute_force(c, ip="203.0.113.45")
    n = pending(c, "incident_opened")[0]
    by_name = {d["name"]: d for d in n["deliver_to"]}
    assert by_name["Amir"]["telegram_chat"] == "5551001" and by_name["Lee"]["telegram_chat"] == ""
    contacts = {x["id"]: x for x in c.get("/routing").json()["contacts"]}
    assert contacts["amir"]["telegram_linked"] and not contacts["lee"]["telegram_linked"]
    assert [x["chat_id"] for x in c.get("/telegram/links").json()] == ["5551001"]
    types = [r["type"] for r in c.get("/audit").json()["records"]]
    assert "telegram_link_code" in types and "telegram_linked" in types


def test_links_survive_a_restart_and_unlink_removes_them(make_core, tmp_path):
    c = routed(make_core)
    assert link(c).status_code == 200
    saved = json.loads((tmp_path / "telegram_links.json").read_text(encoding="utf-8"))
    assert saved["links"][0]["contact_id"] == "amir"
    c2 = routed(make_core)
    assert [x["name"] for x in c2.get("/telegram/links").json()] == ["Amir"]
    assert c2.post("/telegram/unlink", json={"operator": "amir", "chat_id": "5551001"}).json()["unlinked"]
    assert c2.get("/telegram/links").json() == []
    assert c2.post("/telegram/unlink", json={"operator": "amir", "contact": "amir"}).status_code == 404


def test_one_chat_belongs_to_one_person(make_core):
    c = routed(make_core)
    link(c, "amir", "777")
    link(c, "lee", "777")  # the same phone linked again for Lee: it moves, it is not shared
    assert [(x["contact_id"], x["chat_id"]) for x in c.get("/telegram/links").json()] == [("lee", "777")]


def test_unknown_contact_and_bad_codes(make_core):
    c = routed(make_core)
    assert c.post("/telegram/link-codes", json={"operator": "erick", "contact": "nobody"}).status_code == 404
    assert c.post("/telegram/link", json={"code": "ABCDEFGH", "chat_id": "1"}).status_code == 400
    code = c.post("/telegram/link-codes", json={"operator": "erick", "contact": "lee"}).json()["code"]
    assert c.post("/telegram/link", json={"code": code, "chat_id": "not-a-chat"}).status_code == 400


def test_a_chat_id_in_the_routing_file_counts_as_linked(make_core):
    routing = json.loads(json.dumps(ROUTING))
    routing["contacts"]["lee"]["telegram"] = "4242"
    c = routed(make_core, routing)
    assert [(x["name"], x["linked_by"]) for x in c.get("/telegram/links").json()] == [("Lee", "routing file")]
    brute_force(c, ip="203.0.113.45")
    lee = next(d for d in pending(c, "incident_opened")[0]["deliver_to"] if d["name"] == "Lee")
    assert lee["telegram_chat"] == "4242"


def test_direct_delivery_receipts_name_the_person(make_core):
    c = routed(make_core)
    link(c)
    brute_force(c, ip="203.0.113.45")
    n = pending(c, "incident_opened")[0]
    c.post(f"/notifications/{n['id']}/delivered", json={"channel": "telegram-direct", "message_id": 11, "to": "Amir"})
    c.post(f"/notifications/{n['id']}/delivered", json={"channel": "telegram", "message_id": 12})
    full = next(x for x in c.get("/notifications").json() if x["id"] == n["id"])
    assert [(d["channel"], d["to"]) for d in full["deliveries"]] == [("telegram-direct", "Amir"), ("telegram", None)]
    report = c.get(f"/reports/{IID}").json()
    line = next(d for d in report["non_repudiation"]["deliveries"] if d["notification"] == n["id"])
    assert line["reached"][0].startswith("Amir directly in Telegram at ")
    assert line["reached"][1].startswith("in the team Telegram group at ")
    assert report["handling"]["reached_directly"] == ["Amir"]
    assert "Alerts reached Amir in their own Telegram chat." in report["in_plain_words"]


def test_status_says_what_is_missing(make_core):
    c = make_core(routing=ROUTING, SENTRAI_EXTENSIONS="telegram")
    row = next(r for r in c.get("/extensions").json() if r["name"] == "telegram")
    assert row["added"] and row["configured"] is False and "@BotFather" in row["detail"]
    c2 = make_core(routing=ROUTING, TELEGRAM_BOT_TOKEN="123456:test-token")
    row = next(r for r in c2.get("/extensions").json() if r["name"] == "telegram")
    assert row["configured"] is False and "chat id" in row["detail"]
    c3 = routed(make_core)
    row = next(r for r in c3.get("/extensions").json() if r["name"] == "telegram")
    assert row["configured"] and "0 personal chats linked" in row["detail"] and "test-token" not in str(row)


def test_removed_telegram_answers_404_and_keeps_the_links(make_core, tmp_path):
    c = routed(make_core)
    link(c)
    assert c.post("/extensions/telegram/remove", json={"operator": "erick"}).status_code == 200
    gone = c.post("/telegram/link-codes", json={"operator": "erick", "contact": "amir"})
    assert gone.status_code == 404 and "Extensions page" in gone.json()["detail"]
    assert c.get("/telegram/links").status_code == 404
    assert all("telegram_linked" not in x for x in c.get("/routing").json()["contacts"])
    brute_force(c, ip="203.0.113.45")
    assert all("telegram_chat" not in d for d in pending(c, "incident_opened")[0]["deliver_to"])
    assert (tmp_path / "telegram_links.json").exists()
    c.post("/extensions/telegram/add", json={"operator": "erick"})
    assert [x["name"] for x in c.get("/telegram/links").json()] == ["Amir"]  # added again: the links are back
