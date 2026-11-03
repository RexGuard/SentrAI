"""Feature ideas: requests Sentry can't meet yet are noted for SentrAI's team, grouped and counted."""

from app import feature_ideas

from .conftest import brute_force
from .test_chat import FakeProvider, call
from .test_cli import run


def test_ideas_are_grouped_counted_and_cleaned(tmp_path):
    box = feature_ideas.Ideas(tmp_path / "ideas.json")
    one = box.note("", "Clean up the overdue risks for RexGuard Machine", "ana@shop.test")
    assert one["new"] and one["count"] == 1
    two = box.note("", "please clean up overdue risks on the RexGuard machine", "ben@shop.test")
    assert not two["new"] and two["id"] == one["id"] and two["count"] == 2
    other = box.note("", "Email me a report every Monday", "ana@shop.test")
    assert other["new"] and other["id"] != one["id"]
    rows = box.listing()
    assert rows[0]["id"] == one["id"] and rows[0]["asked_by"] == 2  # most asked first
    secret = box.note("", "send alerts to bob@corp.test from 10.0.0.5 with password: hunter2 key sk_live_9f8a7b6c5d4e3f2a1b0c "
                          "and read C:\\Users\\bob\\notes.txt", "ana@shop.test")
    text = " ".join([secret["title"]] + secret["examples"])
    for leak in ("bob@corp.test", "10.0.0.5", "hunter2", "sk_live_9f8a7b6c5d4e3f2a1b0c", "notes.txt"):
        assert leak not in text


def test_done_ideas_are_hidden_and_dismissed_ones_come_back_when_asked_again(tmp_path):
    box = feature_ideas.Ideas(tmp_path / "ideas.json")
    a = box.note("", "Export incidents to Excel", "ana")
    assert box.set_status([a["id"]], "dismissed", "cli:erick") == 1
    assert box.listing() == []
    again = box.note("", "export the incidents to excel please", "ben")
    assert again["id"] == a["id"] and box.listing()[0]["status"] == "new"


def test_chat_without_a_key_notes_a_request_it_cannot_do(client):
    brute_force(client)
    r = client.post("/chat", json={"operator": "erick", "message": "Clean up the overdue risks for RexGuard Machine"})
    reply = r.json()
    assert reply["text"] != "(no answer)" and "can't do that yet" in reply["text"]
    assert reply["feature_idea"]["count"] == 1
    assert reply["suggestions"]  # still offers what it can: buttons for what is waiting
    ideas = client.get("/ui/feature-ideas").json()["ideas"]
    assert len(ideas) == 1 and ideas[0]["examples"] == ["Clean up the overdue risks for RexGuard Machine"]
    client.post("/chat", json={"operator": "ana", "message": "can you clean up the overdue risks for RexGuard?"})
    assert client.get("/ui/feature-ideas").json()["ideas"][0]["count"] == 2
    assert any(x["type"] == "feature_idea_noted" for x in client.get("/audit").json()["records"])


def test_questions_sentry_can_answer_are_not_noted(client):
    brute_force(client)
    for q in ("Are we safe right now?", "Do I need to do anything?", "Summarise this week for me",
              "why is RSK-2026-081 open?", "remember that rexguard is our game server", "Are our backups OK?"):
        assert "feature_idea" not in client.post("/chat", json={"operator": "erick", "message": q}).json()
    assert client.get("/ui/feature-ideas").json()["ideas"] == []


def test_the_model_can_suggest_a_feature_and_an_empty_answer_falls_back(client):
    chat = client.app.state.chat
    chat.provider = FakeProvider([
        sentrai_turn([call("suggest_feature", title="Weekly report by email", need="They want a Monday summary.")]),
        sentrai_turn([], texts=["SentrAI can't email reports yet; I passed the idea on."], stop="end"),
    ])
    reply = client.post("/chat", json={"operator": "erick", "message": "Email me a report every Monday"}).json()
    assert reply["feature_idea"]["title"] == "Weekly report by email" and reply["source"] == "ai"
    assert "FI-" in chat.provider.convos[0].results[0][0][1]
    chat.provider = FakeProvider([sentrai_turn([], texts=[], stop="end")])
    reply = client.post("/chat", json={"operator": "erick", "message": "Are we safe?"}).json()
    assert reply["text"] != "(no answer)" and reply["source"] == "fallback"


def sentrai_turn(calls, texts=None, stop="tool_use"):
    import sentrai_llm
    return sentrai_llm.Turn(texts=texts or [], tool_calls=calls, stop=stop)


def test_cli_lists_and_marks_ideas(client):
    client.post("/chat", json={"operator": "erick", "message": "Please export the incidents to Excel"})
    code, out = run(client, "ideas", "list")
    assert code == 0 and "asked 1x" in out and "export the incidents to Excel" in out
    iid = client.get("/ui/feature-ideas").json()["ideas"][0]["id"]
    code, out = run(client, "ideas", "planned", iid, "--note", "next sprint")
    assert code == 0 and "1 idea marked planned" in out
    assert "[planned]" in run(client, "ideas", "list")[1]
    run(client, "ideas", "done", iid)
    assert "No feature ideas waiting." in run(client, "ideas", "list")[1]
