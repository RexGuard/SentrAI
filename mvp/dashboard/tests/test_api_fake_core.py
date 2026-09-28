import requests

from cactai_ui.api import CoreClient, CoreError


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
    c.reset_demo()
    assert c.incidents() == []


def test_protection_switch(fake_core):
    c = CoreClient(fake_core)
    c.reset_demo()
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
    c.reset_demo()
