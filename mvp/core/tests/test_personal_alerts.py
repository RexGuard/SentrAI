"""Who handled an incident, in the evidence report. (Linking a person's own Telegram chat is tested with the
Telegram extension: mvp/extensions/telegram/tests.)"""

from .conftest import brute_force
from .test_routing import routed_client


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
