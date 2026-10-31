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
