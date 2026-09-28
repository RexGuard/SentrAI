"""Cactus spine hits (lab portal decoys) become high-confidence incidents."""

import pytest

from tests.conftest import ev

SPINE_CASES = [
    ("honeypot_page", "web", None, "port_scan"),
    ("honeypot_login", "web", None, "brute_force"),
    ("honeytoken_credential", "web", "svc_backup", "brute_force"),
    ("honeytoken_row", "db", None, "data_exfiltration"),
]


@pytest.mark.parametrize("kind,layer,user,category", SPINE_CASES)
def test_one_spine_touch_opens_a_certain_incident(client, kind, layer, user, category):
    raw = f"cactus-spine {kind}: decoy touched"
    client.post("/events", json=ev(1, raw, ip="203.0.113.99", user=user, layer=layer, source="cactus_spine"))
    [inc] = client.get("/incidents").json()
    assert inc["category"] == category
    assert inc["ai_confidence"] == 1.0 and inc["classified_by"] == "rules"
    assert inc["needs_review"] is False
    assert inc["classification_reason"].startswith("Cactus spine:")
    assert "decoy" in inc["explanation"]


def test_quiet_export_is_caught_only_by_the_bait_rows(client):
    # 42 rows is under the bulk-export threshold (benign on its own) ...
    client.post("/events", json=ev(1, "SELECT rows=42 q='SELECT * FROM members'", ip="203.0.113.99",
                                   user=None, layer="db", source="db_query"))
    assert client.get("/incidents").json() == []
    # ... but the bait rows inside that export are not.
    client.post("/events", json=ev(2, "cactus-spine honeytoken_row: bait member rows STF-0007 returned by /export",
                                   ip="203.0.113.99", user=None, layer="db", source="cactus_spine"))
    [inc] = client.get("/incidents").json()
    assert inc["category"] == "data_exfiltration" and inc["points"] == 105.0  # 70 x 1.0 x 1.5


def test_spine_text_from_other_sources_is_not_trusted(client):
    # Only the portal's own deception log may claim to be a spine.
    client.post("/events", json=ev(1, "cactus-spine honeytoken_credential: x", source="scout:app.log", user=None))
    reasons = [i["classification_reason"] for i in client.get("/incidents").json()]
    assert not any(r.startswith("Cactus spine") for r in reasons)


def test_spine_touch_joining_an_open_incident_leads_its_explanation(client):
    client.post("/events", json=ev(1, "GET /export 200", ip="203.0.113.99", user=None, source="flask_access"))
    client.post("/events", json=ev(2, "cactus-spine honeytoken_row: bait member rows STF-0007 returned by /export",
                                   ip="203.0.113.99", user=None, layer="db", source="cactus_spine"))
    [inc] = client.get("/incidents").json()
    assert inc["category"] == "data_exfiltration" and len(inc["event_ids"]) == 2
    assert inc["classification_reason"].startswith("Cactus spine:")
    assert "decoy" in inc["explanation"]
