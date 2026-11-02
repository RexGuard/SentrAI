"""The panel's Contact Us form and the SentrAI team's inbox for it."""
from app import ui_feedback


def test_feedback_is_kept_until_marked_done(client):
    bad = client.post("/ui/feedback", json={"name": "Ana", "contact": "", "message": "hi"})
    assert bad.status_code == 400 and "email or company" in bad.json()["detail"]
    ok = client.post("/ui/feedback", json={"name": "Ana", "contact": "ana@shop.test", "message": "The PDF export is blank."})
    assert ok.status_code == 200
    fid = ok.json()["id"]
    rows = client.get("/ui/feedback").json()["feedback"]
    assert any(r["id"] == fid and r["message"] == "The PDF export is blank." for r in rows)
    assert client.post("/ui/feedback/done", json={"ids": [fid]}).json()["changed"] == 1
    assert all(r["id"] != fid for r in client.get("/ui/feedback").json()["feedback"])
    assert any(r["id"] == fid and r["done"] for r in client.get("/ui/feedback?all=true").json()["feedback"])


def test_long_messages_and_floods_are_refused(client, tmp_path):
    long = client.post("/ui/feedback", json={"name": "A", "contact": "b", "message": "x" * 6000})
    assert long.status_code == 400
    box = ui_feedback.Inbox(tmp_path / "fb.json")
    for _ in range(ui_feedback.PER_HOUR):
        box.add("A", "b", "c", "someone")
    try:
        box.add("A", "b", "c", "someone")
        raise AssertionError("the 21st message in an hour should be refused")
    except OverflowError:
        pass
