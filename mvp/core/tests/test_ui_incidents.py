"""The web dashboard's Incidents endpoint."""
from app import ui_incidents as ui

from .conftest import brute_force


def test_page_counts_and_rows(client):
    brute_force(client)
    page = client.get("/ui/incidents").json()
    assert page["counts"]["open"] >= 1 and page["counts"]["unassigned"] >= 0
    assert page["all"] and page["all"][0]["id"] and page["todo"]
    assert client.get("/ui/incidents?mine=true").json()["all"] == []
    assert isinstance(page["contacts"], list) and isinstance(page["waves"], list)


def test_attention_words():
    inc = {"status": "open", "owner": "", "category": "brute_force"}
    assert ui.attention(inc)[0] == "No owner"
    assert ui.attention({"status": "resolved"}) == []
    assert ui.wave_line([{"category": "port_scan", "host": "web-01", "src_ip": "a"}]) == \
        "1 address scanning web-01 need a person"


def test_brief_sends_counts_and_a_few_rows(client):
    """The Command center asks for ?brief=N: the counts and the first N that need a person, nothing else."""
    for _ in range(3):
        brute_force(client)
    full = client.get("/ui/incidents").json()
    brief = client.get("/ui/incidents?brief=1").json()
    assert set(brief) == {"counts", "todo", "todo_total"}
    assert brief["counts"] == full["counts"] and brief["todo_total"] == len(full["todo"]) == full["todo_total"]
    assert brief["todo"] == full["todo"][:1]


def test_incident_list_with_only_some_fields(client):
    brute_force(client)
    whole = client.get("/incidents").json()
    slim = client.get("/incidents?fields=status, category").json()
    assert [i["id"] for i in slim] == [i["id"] for i in whole]
    assert all(set(i) <= {"id", "status", "category"} and "timeline" not in i for i in slim)
    assert slim[0]["status"] == whole[0]["status"]
