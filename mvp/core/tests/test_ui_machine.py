"""The web dashboard's single-machine details (Signed in, Services, Packages tabs)."""
from app import ui_machine as um


def test_details_for_an_unknown_host_are_empty_but_well_formed(client):
    d = client.get("/ui/machines/nowhere/details").json()
    assert d["host"] == "nowhere" and d["services"] == [] and d["packages"]["latest"] is None
    assert set(d["admins"]) == {"on", "sessions", "suspect", "activity", "entries"}
    assert d["admin_kinds"]["key"] == "SSH key fingerprint"


def test_added_admin_address_shows_with_forget(client):
    r = client.post("/admins", json={"operator": "t", "action": "add", "kind": "address", "value": "203.0.113.5",
                                     "label": "home"})
    assert r.status_code == 200
    entries = client.get("/ui/machines/web-01/details").json()["admins"]["entries"]
    e = next(e for e in entries if e["value"] == "203.0.113.5")
    assert e["kind"] == "address" and e["forget"] and e["headline"] == "203.0.113.5 · home"


def test_session_and_service_rows():
    rows = um.session_rows([{"user": "erick", "via": "ssh", "key": "SHA256:" + "a" * 40, "address": "203.0.113.5",
                             "trust": "trusted", "actions": 3}])
    assert rows[0]["how"].startswith("SSH key SHA256:") and rows[0]["trust_words"] == "Known administrator"
    svc = um.service_rows([{"name": "sshd", "port": 22, "proto": "tcp"},
                           {"name": "nginx", "port": 443, "open_incidents": 2}])
    assert [s["name"] for s in svc] == ["nginx", "sshd"] and svc[1]["proto"] == "TCP"


def test_packages_latest_scan_and_undoable_updates():
    mine = [  # newest first
        {"kind": "dep_rollback", "status": "done", "params": {"update": "u1"}},
        {"kind": "dep_update", "status": "done", "result": {"id": "u2", "name": "b"}},
        {"kind": "dep_update", "status": "done", "result": {"id": "u1", "name": "a"}},
        {"kind": "dep_scan", "status": "done", "result": {"findings": [
            {"name": "jinja2", "version": "2.0", "fixed": "3.1.4", "vulns": [{"id": "GHSA-x", "aliases": ["CVE-1"]}]}]}},
    ]
    p = um.packages(mine)
    assert [u["id"] for u in p["updates"]] == ["u2"] and p["busy"] is None
    assert p["latest"]["findings"][0]["line"] == "jinja2 2.0 → 3.1.4 · CVE-1"
