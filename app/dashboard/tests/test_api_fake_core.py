import pytest
import requests

from sentrai_ui import shaping as sh
from sentrai_ui.api import CoreClient, CoreError


def test_core_down_raises_coreerror():
    c = CoreClient("http://127.0.0.1:9", timeout=0.5)
    assert c.health() is False
    try:
        c.risk()
    except CoreError as exc:
        assert "unreachable" in str(exc)
    else:
        raise AssertionError("expected CoreError")


def test_full_operator_flow(fake_core):
    c = CoreClient(fake_core)
    assert c.health()
    inc = requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3).json()
    iid = inc["id"]
    assert iid in c.risk()["open_incidents"]
    try:
        c.decision(iid, "erick", "reject", "")
    except CoreError as exc:
        assert exc.status == 422
    c.ack(iid, "erick")
    c.decision(iid, "erick", "approve", "")
    assert c.get_json(f"/incidents/{iid}")["status"] == "contained"
    assert "203.0.113.45" not in c.blocklist()["ips"]  # trigger default IP is 198.51.100.7
    assert "198.51.100.7" in c.blocklist()["ips"]
    c.permanent(iid, "erick", "confirmed attacker")
    audit = c.audit()
    assert audit["chain_valid"] is True
    assert any(r["type"] == "permanent" for r in audit["records"])
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    assert c.incidents() == []


def test_protection_switch(fake_core):
    c = CoreClient(fake_core)
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    assert c.protection()["protection"] == "on" and c.risk()["monitor_only"] is False
    try:
        c.set_protection(False, "erick", "")
    except CoreError as exc:
        assert exc.status == 400
    else:
        raise AssertionError("turning protection off without a reason must fail")
    p = c.set_protection(False, "erick", "testing on the live server")
    assert p["monitor_only"] is True and p["changed_by"] == "erick"
    assert c.risk()["monitor_only"] is True
    iid = requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3).json()["id"]
    try:
        c.decision(iid, "erick", "approve", "")
    except CoreError as exc:
        assert exc.status == 409
    else:
        raise AssertionError("approve must be refused while protection is off")
    assert c.blocklist()["ips"] == []
    c.set_protection(True, "erick")
    assert c.protection()["protection"] == "on"
    assert any(r["type"] == "protection_changed" for r in c.audit()["records"])
    requests.post(f"{fake_core}/dev/reset", timeout=3)


def test_machine_names_for_the_report_form(fake_core):
    assert {"web-01", "office-pc"} <= set(CoreClient(fake_core).machine_names())
    assert CoreClient("http://127.0.0.1:9", timeout=0.3).machine_names() == []  # no list: the form shows no picker


def test_assign_and_resolve(fake_core):
    c = CoreClient(fake_core)
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    iid = requests.post(f"{fake_core}/dev/trigger/brute_force", timeout=3).json()["id"]
    assert c.get_json(f"/incidents/{iid}")["owner"]
    assert c.assign(iid, "Lee", "erick")["owner"] == "Lee"
    try:
        c.resolve(iid, "erick", "")
    except CoreError as exc:
        assert exc.status == 400
    else:
        raise AssertionError("resolving without a note must fail")
    assert c.resolve(iid, "erick", "password reset")["status"] == "resolved"
    assert [x["id"] for x in c.routing()["contacts"]][0] == "on_duty"
    doc = {"contacts": {"on_duty": {"name": "Amir"}, "lee": {"name": "Lee", "backup": "on_duty"}},
           "rules": [{"name": "Web", "match": {"category": ["xss"]}, "owner": "lee", "notify": ["on_duty"]}]}
    saved = c.save_routing(doc, "erick")
    assert [x["name"] for x in saved["contacts"]] == ["Amir", "Lee"]
    assert [r["name"] for r in saved["rules"]] == ["Web", "Everything else"]


def _routing_records(c: CoreClient) -> list[dict]:
    return [r for r in c.audit()["records"] if r["type"] == "routing_changed"]


def test_routing_saves_with_its_map_and_what_changed(fake_core):
    c = CoreClient(fake_core)
    layout = {"incident": [0, 120], "rules": [[210, 0], [210, 90]], "contacts": {"on_duty": [620, 40], "lee": [620, 140]}}
    doc = {"contacts": {"on_duty": {"name": "Amir", "role": "on_duty"}, "lee": {"name": "Lee", "backup": "on_duty"}},
           "rules": [{"name": "Web", "match": {"category": ["xss"]}, "owner": "lee", "notify": ["on_duty"]},
                     {"name": "Everything else", "match": {}, "owner": "on_duty", "notify": []}],
           "follow_up": {"escalate_after_reminders": 3, "max_escalations": 2, "resolve_within_hours": 12},
           "layout": layout}
    saved = c.save_routing(doc, "erick", "Web attacks go to Lee")
    got = c.routing()
    assert got == saved and got["layout"] == layout  # the map comes back where it was left
    assert [r["name"] for r in got["rules"]] == ["Web", "Everything else"] and got["follow_up"] == doc["follow_up"]
    record = _routing_records(c)[-1]["data"]
    assert record["operator"] == "erick" and record["summary"] == "Web attacks go to Lee"

    # What the editor is given, saved without a change, is the same routing: same version, same map.
    again = c.save_routing(sh.routing_from_editor(sh.routing_editor_data(got)["routing"]), "erick", "No change")
    assert sh.routing_version(again) == sh.routing_version(got) and again["layout"] == layout

    # A save the core refuses changes nothing, and the dashboard can show the core's own words.
    logged = len(_routing_records(c))
    with pytest.raises(CoreError) as refused:
        c.save_routing({**doc, "rules": [{"name": "Web", "match": {}, "owner": "ghost", "notify": []}]}, "erick", "x")
    assert refused.value.status == 400
    assert str(refused.value).split(": ", 1)[-1] == "rule 'Web' needs an owner who is one of the people"
    assert c.routing() == again and len(_routing_records(c)) == logged
