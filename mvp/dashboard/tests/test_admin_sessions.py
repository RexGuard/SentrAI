"""The administrators' own root work (core admins.py): "This was me" / "Not me: block it", the Admins tab,
and the dashboard sign-in that vouches for an Owner's or Admin's address. Example data only."""
from pathlib import Path

import pytest
import requests

from sentrai_ui import shaping as sh
from sentrai_ui.api import CoreClient, CoreError

APP = str(Path(__file__).resolve().parents[1] / "app.py")
KEY = "SHA256:Q7w3cZk2u5Yd9bJm1LxkfA0Hn6Rr8PtEoSvNqGiCz4U"


@pytest.fixture
def fresh(fake_core):
    requests.post(f"{fake_core}/dev/reset", timeout=3)
    yield fake_core
    requests.post(f"{fake_core}/dev/reset", timeout=3)


def _root_alert(url: str) -> dict:
    return requests.post(f"{url}/dev/trigger/unauthorised_admin", params={"src_ip": "203.0.113.9", "user": "erick"},
                         timeout=3).json()


def _app(url, tmp_path, monkeypatch, page="incidents", **params):
    import streamlit as st
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    st.cache_data.clear()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = url
    at.session_state["auto_refresh"] = False
    at.session_state["operator"] = "erick"
    at.session_state["page"] = page
    for k, v in params.items():
        at.query_params[k] = v
    return at


def _only_fragment_refresh(at) -> None:
    # AppTest cannot rerun just a fragment, so the refresh after an action raises here; in a browser it reruns the
    # page part. Anything else is a real error.
    assert all("fragment" in str(e.value) for e in at.exception), at.exception


def _text(at) -> str:
    return " ".join(m.value for m in at.markdown)


# ---------------------------------------------------------------- the client

def test_mine_teaches_the_sign_in_and_closes_the_alert(fresh):
    c = CoreClient(fresh)
    inc = _root_alert(fresh)
    assert inc["category"] == "unauthorised_admin" and inc["actor"]["address"] == "203.0.113.9"
    out = c.mine(inc["id"], "erick")
    assert out["status"] == "resolved" and out["resolved_by"] == "erick"
    assert "address 203.0.113.9" in out["learned"] and "account erick on web-01" in out["learned"]
    assert any(d["decision"] == "mine" for d in out["decisions"])
    with pytest.raises(CoreError) as exc:
        c.mine(inc["id"], "erick")  # already closed
    assert exc.value.status == 409
    known = c.admins()
    assert any(a["address"] == "203.0.113.9" and a["how"] == "taught" for a in known["addresses"])


def test_admins_for_one_machine_and_by_hand(fresh):
    c = CoreClient(fresh)
    data = c.admins("web-01")
    assert data["on"] is True and all(s["host"] == "web-01" for s in data["sessions"])
    assert any(k["fingerprint"] == KEY for k in data["keys"])
    assert c.admins("office-pc")["sessions"] == []
    after = c.admin_change("erick", "add", "address", "203.0.113.77", "office")
    assert any(a["address"] == "203.0.113.77" and a["label"] == "office" for a in after["addresses"])
    after = c.admin_change("erick", "forget", "address", "203.0.113.77")
    assert not any(a["address"] == "203.0.113.77" for a in after["addresses"])
    after = c.admin_change("erick", "add", "account", "deploy2", host="web-01")
    assert any(a["account"] == "deploy2" and a["host"] == "web-01" for a in after["accounts"])


def test_a_bad_value_is_refused_in_the_cores_own_words(fresh):
    c = CoreClient(fresh)
    with pytest.raises(CoreError) as exc:
        c.admin_change("erick", "add", "address", "not-an-address")
    assert str(exc.value) == "'not-an-address' is not an address or a network"  # no "POST /admins -> HTTP 400"
    assert exc.value.status == 400
    with pytest.raises(CoreError, match="ssh-keygen -lf"):
        c.admin_change("erick", "add", "key", "abc")


def test_sign_in_vouches_only_for_owners_and_admins(fresh):
    c = CoreClient(fresh)
    assert c.admin_signed_in("erick@example.com", "Owner", "203.0.113.8")["vouched"] is True
    assert c.admin_signed_in("hozen@example.com", "Auditor", "203.0.113.30")["vouched"] is False
    assert c.admin_signed_in("erick@example.com", "Owner", "local")["vouched"] is False


def test_an_auditors_client_changes_nothing(fresh):
    ro = CoreClient(fresh, read_only=True)
    assert ro.admins()["on"] is True  # reading works
    inc = _root_alert(fresh)
    for call in (lambda: ro.mine(inc["id"], "hozen"), lambda: ro.admin_change("hozen", "add", "address", "203.0.113.4")):
        with pytest.raises(CoreError, match="Auditors"):
            call()


# ---------------------------------------------------------------- the words

def test_category_label_and_actions():
    assert sh.category_label("unauthorised_admin") == "Root access from an unrecognised sign-in"
    assert ["unauthorised_admin", "Root access from an unrecognised sign-in"] in sh.routing_editor_data({})["categories"]
    inc = {"id": "RSK-1", "status": "open", "category": "unauthorised_admin", "actions": []}
    can = sh.available_actions(inc)
    assert can["mine"] and can["decide"] and sh.decision_verb(inc) == "Was this you?"
    assert "Was this you?" in sh.attention(inc)
    assert not sh.available_actions({**inc, "status": "resolved"})["mine"]
    assert not sh.available_actions({**inc, "category": "brute_force"})["mine"]
    assert sh.suggestion_state(inc, "mine")[0] is True


def test_actor_and_learned_in_plain_words():
    actor = {"host": "web-01", "user": "erick", "via": "ssh", "address": "203.0.113.9", "key": KEY,
             "trust": "unknown", "why": "neither the address nor the key is known", "since": "2026-10-28T10:21:00+08:00"}
    facts = dict(sh.actor_facts(actor))
    assert facts["Who"] == "erick on web-01" and facts["From"] == "203.0.113.9" and facts["How"].startswith("SSH key")
    assert sh.actor_sentence(actor).startswith("SentrAI did not know this sign-in as an administrator's: neither")
    assert sh.actor_facts(None) == [] and sh.actor_sentence({}) == ""
    text = sh.learned_text("RSK-1", {"learned": ["address 203.0.113.9", "account erick on web-01"],
                                     "also_closed": ["RSK-2"]})
    assert "RSK-1 closed" in text and "address 203.0.113.9, account erick on web-01" in text and "RSK-2" in text


def test_admins_tab_rows():
    sessions = sh.session_rows([{"user": "erick", "via": "ssh", "address": "203.0.113.5", "key": KEY,
                                 "trust": "trusted", "why": "known SSH key", "since": "2026-10-28T10:21:00+08:00",
                                 "actions": 2}])
    row = sessions.iloc[0]
    assert row["User"] == "erick" and row["Trust"] == "Known administrator" and row["Root commands"] == 2
    work = sh.admin_activity_rows([{"at": "2026-10-28T10:30:00+08:00", "user": "erick", "via": "ssh",
                                    "address": "203.0.113.5", "what": "sudo: /usr/bin/systemctl stop sentrai-core",
                                    "flagged_as": "log_tampering", "reason": "Log tampering"},
                                   {"at": "2026-10-28T10:00:00+08:00", "user": "erick", "via": "ssh",
                                    "what": "sudo: /usr/bin/apt update", "flagged_as": None}])
    assert list(work["Would have been"]) == ["Log tampering", "-"]
    entries = sh.admin_entries({
        "accounts": [{"account": "deploy", "host": "*", "how": "setting", "by": "ADMIN_ACCOUNTS"},
                     {"account": "erick", "host": "web-01", "how": "learned", "by": "a trusted sign-in"},
                     {"account": "bob", "host": "office-pc", "how": "taught", "by": "erick"}],
        "addresses": [{"address": "192.0.2.0/24", "how": "setting", "by": "ADMIN_IPS"},
                      {"address": "203.0.113.5", "how": "taught", "by": "erick", "label": "home"}],
        "keys": [{"fingerprint": KEY, "type": "ED25519", "users": ["erick"], "how": "taught", "by": "erick"}]},
        "web-01")
    by = {e["value"]: e for e in entries}
    assert "bob" not in by  # another machine's account
    assert by["deploy"]["forget"] is False and by["deploy"]["headline"] == "deploy on every machine"
    assert by["192.0.2.0/24"]["forget"] is False and by["192.0.2.0/24"]["detail"] == "from the settings (ADMIN_IPS)"
    assert by["203.0.113.5"]["forget"] and by["203.0.113.5"]["headline"] == "203.0.113.5 · home"
    assert by["erick"]["forget"] and by[KEY]["forget"] and "used by erick" in by[KEY]["detail"]


def test_machine_card_counts_who_is_signed_in(fresh):
    rows = sh.panel_machines(CoreClient(fresh).machines(), [], None)
    web = next(r for r in rows if r["host"] == "web-01")
    assert web["sessions"] == 1


# ---------------------------------------------------------------- the pages

def test_the_alert_asks_was_this_you_and_this_was_me_closes_it(fresh, tmp_path, monkeypatch):
    inc = _root_alert(fresh)
    at = _app(fresh, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    labels = [b.label for b in at.button]
    assert "This was me" in labels and "Not me: block it" in labels and "Approve" not in labels
    mine = next(b for b in at.button if b.label == "This was me")
    assert not mine.disabled and "known administrator's" in (mine.help or "")
    mine.click().run()
    _only_fragment_refresh(at)
    assert requests.get(f"{fresh}/incidents/{inc['id']}", timeout=3).json()["status"] == "resolved"
    import streamlit as st
    st.cache_data.clear()  # the page reads the core at most once a second
    at.run()
    assert not at.exception, at.exception
    assert "This was me" not in [b.label for b in at.button]  # the alert left the list
    text = _text(at)
    assert f"{inc['id']} closed: this was you" in text and "address 203.0.113.9" in text


def test_not_me_blocks_the_address(fresh, tmp_path, monkeypatch):
    inc = _root_alert(fresh)
    at = _app(fresh, tmp_path, monkeypatch)
    at.run()
    next(b for b in at.button if b.label == "Not me: block it").click().run()
    _only_fragment_refresh(at)
    assert requests.get(f"{fresh}/incidents/{inc['id']}", timeout=3).json()["status"] == "contained"
    assert "203.0.113.9" in CoreClient(fresh).blocklist()["ips"]


def test_an_auditor_sees_the_buttons_greyed_out(fresh, tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_DASHBOARD_ROLE", "auditor")
    _root_alert(fresh)
    at = _app(fresh, tmp_path, monkeypatch)
    at.run()
    assert not at.exception, at.exception
    for label in ("This was me", "Not me: block it"):
        assert all(b.disabled for b in at.button if b.label == label), label
    at = _app(fresh, tmp_path, monkeypatch, page="machines", machine="web-01", tab="admins")
    at.run()
    assert not at.exception, at.exception
    assert all(b.disabled for b in at.button if b.label == "Forget")


def test_the_admins_tab(fresh, tmp_path, monkeypatch):
    at = _app(fresh, tmp_path, monkeypatch, page="machines", machine="web-01", tab="admins")
    at.run()
    assert not at.exception, at.exception
    assert at.session_state["machine_tab"] == "Admins"
    text = _text(at)
    for words in ("Signed in now", "Recent admin work", "Known administrators", "from the settings (ADMIN_IPS)",
                  "from the settings (ADMIN_ACCOUNTS)", "Add a known administrator"):
        assert words in text, words
    frames = [d.value for d in at.dataframe]
    assert any("Known administrator" in list(f.get("Trust", [])) for f in frames)
    assert any("Log tampering" in list(f.get("Would have been", [])) for f in frames)
    forgets = [b for b in at.button if b.label == "Forget"]
    assert forgets and not any(b.disabled for b in forgets)
    assert len(forgets) == 5  # erick's account, two addresses, the dashboard sign-in, the key: not the 2 settings
    # Add by hand: a bad value shows the core's words; a good one is added.
    next(t for t in at.text_input if t.label == "Value").input("not-an-address")
    next(b for b in at.button if b.label == "Add").click().run()
    assert any("Not added: 'not-an-address' is not an address or a network" == e.value for e in at.error)
    next(t for t in at.text_input if t.label == "Value").input("203.0.113.77")
    next(t for t in at.text_input if t.label == "Label (optional)").input("office")
    next(b for b in at.button if b.label == "Add").click().run()
    _only_fragment_refresh(at)
    assert any(a["address"] == "203.0.113.77" for a in CoreClient(fresh).admins()["addresses"])
    # Forget it again: its own Forget button.
    at.run()
    forgets = [b for b in at.button if b.label == "Forget"]
    assert len(forgets) == 6
    row = next(n for n, m in enumerate(at.markdown) if "<b>203.0.113.77 · office</b>" in m.value)
    assert row is not None
    next(b for b in at.button if b.key == "forget_address__203.0.113.77_0").click().run()
    _only_fragment_refresh(at)
    assert not any(a["address"] == "203.0.113.77" for a in CoreClient(fresh).admins()["addresses"])


def test_dashboard_sign_in_tells_the_core_once(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    from test_sign_in import GOOD, acc, button, cfg, owner_with_authenticator, password_step, signed_in

    requests.post(f"{fake_core}/dev/reset", timeout=3)
    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("SENTRAI_ACCOUNTS", raising=False)
    monkeypatch.delenv("SENTRAI_DASHBOARD_LOGIN")
    for name in (cfg.EMAIL_ENV, cfg.HASH_ENV, cfg.PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SENTRAI_CORE_URL", fake_core)
    secret = owner_with_authenticator()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = fake_core
    at.session_state["auto_refresh"] = False
    at.run()
    password_step(at, "erick@example.com", GOOD)
    assert requests.get(f"{fake_core}/dev/admin-sign-ins", timeout=3).json() == []  # not after the password alone
    at.text_input[0].input(acc.totp_code(secret))
    button(at, "Verify").click().run()
    assert not at.exception, at.exception
    assert signed_in(at)
    at.run()
    reports = requests.get(f"{fake_core}/dev/admin-sign-ins", timeout=3).json()
    assert len(reports) == 1
    assert reports[0]["email"] == "erick@example.com" and reports[0]["role"] == "Owner"
    assert reports[0]["address"] == "local"  # no browser in a test: the lockout's own name for it


def test_sign_in_goes_on_when_the_core_is_down(fake_core, tmp_path, monkeypatch):
    from streamlit.testing.v1 import AppTest

    from test_sign_in import GOOD, acc, button, cfg, owner_with_authenticator, password_step, signed_in

    monkeypatch.setenv("SENTRAI_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("SENTRAI_ACCOUNTS", raising=False)
    monkeypatch.delenv("SENTRAI_DASHBOARD_LOGIN")
    for name in (cfg.EMAIL_ENV, cfg.HASH_ENV, cfg.PASSWORD_ENV):
        monkeypatch.delenv(name, raising=False)
    secret = owner_with_authenticator()
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["core_url"] = "http://127.0.0.1:9"  # nothing listens there
    at.session_state["auto_refresh"] = False
    at.run()
    password_step(at, "erick@example.com", GOOD)
    at.text_input[0].input(acc.totp_code(secret))
    button(at, "Verify").click().run()
    assert not at.exception, at.exception
    assert signed_in(at)
