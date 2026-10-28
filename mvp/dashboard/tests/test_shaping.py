import copy
import importlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from sentrai_ui import shaping as sh


def test_band_boundaries():
    assert sh.band_for(0) == "green"
    assert sh.band_for(29) == "green"
    assert sh.band_for(30) == "amber"
    assert sh.band_for(59) == "amber"
    assert sh.band_for(60) == "red"
    assert sh.band_for(79) == "red"
    assert sh.band_for(80) == "critical"
    assert sh.band_for(100) == "critical"
    assert sh.band_for(140) == "critical"
    assert sh.band_for(None) == "unknown"


def test_band_colors():
    assert sh.band_color("green") == sh.BAND_COLORS["green"]
    assert sh.band_color(85) == sh.BAND_COLORS["critical"]
    assert sh.band_color(45) == sh.BAND_COLORS["amber"]
    assert sh.band_color("nonsense") == sh.UNKNOWN_COLOR
    assert len(set(sh.BAND_COLORS.values())) == 4


def test_resolve_band_prefers_core_value():
    assert sh.resolve_band({"risk_index": 10, "band": "critical"}) == "critical"
    assert sh.resolve_band({"risk_index": 65, "band": None}) == "red"


INCIDENTS = [
    {"id": "RSK-1", "category": "brute_force", "severity": "high", "ai_confidence": 0.94, "points": 28.2,
     "classified_by": "jev", "status": "contained", "inaction_penalty": 15, "sla_breached": True,
     "opened_at": "2026-09-29T14:00:00+08:00", "src_ip": "203.0.113.45",
     "actions": [{"action_id": "act-1", "type": "block_ip", "target": "203.0.113.45", "status": "active",
                  "mode": "autonomous", "approved_by": "Needle", "expires_at": "2026-09-29T16:00:00+08:00"},
                 {"action_id": "act-2", "type": "rate_limit", "target": "/login", "status": "active"}]},
    {"id": "RSK-2", "category": "sql_injection", "severity": "high", "ai_confidence": 1.0, "points": 60,
     "classified_by": "rules", "status": "open", "inaction_penalty": 0, "sla_breached": False,
     "opened_at": "2026-09-29T14:30:00+08:00"},
]


def test_incident_table_shape_and_order():
    df = sh.build_incident_table(INCIDENTS)
    assert list(df.columns) == sh.INCIDENT_COLUMNS
    assert df.iloc[0]["ID"] == "RSK-2"  # open incidents first
    row = df[df["ID"] == "RSK-1"].iloc[0]
    assert row["Category"] == "Brute force"
    assert row["Classified by"] == "Jev (AI)"
    assert row["Inaction penalty"] == 15
    assert bool(row["SLA breached"]) is True
    assert abs(row["Confidence"] - 0.94) < 1e-9


def test_incident_table_empty_and_sparse():
    assert sh.build_incident_table([]).empty
    df = sh.build_incident_table([{"id": "X"}])
    assert df.iloc[0]["Category"] == "Unknown"


def test_default_incident_and_actions():
    assert sh.pick_default_incident(INCIDENTS) == "RSK-2"
    assert sh.available_actions(INCIDENTS[1])["decide"] is True
    assert sh.available_actions(INCIDENTS[0])["contain_controls"] is True
    assert sh.available_actions(INCIDENTS[0])["decide"] is False
    assert len(sh.action_rows(INCIDENTS[0])) == 2


def test_check_and_undo_text():
    assert sh.check_text({"status": "active"}) == "pending"
    assert sh.check_text({"check": {"worked": True, "disruption": False}}) == "worked, no harm seen"
    assert sh.check_text({"check": {"worked": False, "disruption": True}}) == "did not work, possible disruption"
    assert sh.check_text({"check": {"worked": None, "disruption": None}}) == "can't see"
    assert sh.undo_text({}) == "-"
    assert sh.undo_text({"undo": {"ok": True}}) == "done"
    assert sh.undo_text({"undo": {"ok": False, "attempts": 3}}) == "FAILED (3 tries)"


def test_containment_rows():
    df = sh.build_containment_rows({"ips": ["203.0.113.45"], "users": ["admin"]}, INCIDENTS)
    kinds = list(df["Kind"])
    assert kinds.count("IP") == 1 and kinds.count("User") == 1 and kinds.count("Rule") == 1
    ip = df[df["Kind"] == "IP"].iloc[0]
    assert ip["Incident"] == "RSK-1" and ip["Approved by"] == "Countersign"  # older records show the new name
    assert sh.build_containment_rows(None, []).empty


def test_audit_normalize_and_feed():
    recs = [
        {"seq": 1, "ts": "2026-09-29T14:00:00+08:00", "type": "incident_opened", "data": {"incident": "RSK-1"},
         "prev_hash": "0", "hash": "aaa"},
        {"seq": 2, "ts": "2026-09-29T14:00:01+08:00", "type": "action_approved", "data": {"agent": "Needle"},
         "prev_hash": "aaa", "hash": "bbb"},
        {"seq": 3, "ts": "2026-09-29T14:00:02+08:00", "type": "decision",
         "data": {"operator": "erick", "decision": "approve"}, "prev_hash": "bbb", "hash": "ccc"},
    ]
    assert sh.normalize_audit({"records": recs, "chain_valid": True}) == (recs, True)
    assert sh.normalize_audit(recs) == (recs, None)
    assert sh.normalize_audit("garbage") == ([], None)
    assert sh.verify_chain_links(recs)
    assert not sh.verify_chain_links([recs[0], {**recs[1], "prev_hash": "zzz"}])
    feed = sh.build_activity_feed(recs)
    assert [e["seq"] for e in feed] == [3, 2, 1]
    assert feed[0]["agent"] == "Operator · erick"
    assert feed[1]["agent"] == "Countersign"  # saved as "Needle"
    assert feed[2]["agent"] == "Warden"  # inferred from type


def test_history_and_figures():
    df = sh.history_frame([{"t": "2026-09-29T14:00:05+08:00", "risk_index": 44},
                           {"t": "2026-09-29T14:00:00+08:00", "risk_index": 8},
                           {"t": None, "risk_index": 3}, "junk"])
    assert list(df["risk_index"]) == [8, 44]
    fig = sh.history_figure(df, 80)
    assert fig.data[0].line.color == sh.BAND_COLORS["amber"]


def test_parse_peers():
    assert sh.parse_peers("Office PC=http://10.0.0.5:8000, https://web:8000 ,bad, =ftp://x,") == [
        ("Office PC", "http://10.0.0.5:8000"), ("https://web:8000", "https://web:8000")]
    assert sh.parse_peers(None) == []


def test_machine_rows():
    here = sh.machine("This computer", "Local", {"risk_index": 31, "band": "amber", "threshold": 80})
    off = sh.machine("Office <PC>", "Remote", None, "Core unreachable")
    quiet = sh.machine("Web", "Remote", {"risk_index": 5, "threshold": 70, "monitor_only": True})
    assert here["online"] and here["band"] == "amber" and not off["online"] and quiet["band"] == "green"
    rows = sh.machine_rows_html([here, off, quiet])
    assert rows.count('<li class="machine">') == 3
    assert ">31<" in rows and "Elevated" in rows and "width:31%" in rows and "threshold 80" in rows
    assert "Office &lt;PC&gt;" in rows and ">Offline<" in rows  # names are escaped
    assert "remove_moderator" in rows and "Protection off" in rows and "threshold 70" in rows
    assert "m-more" not in rows  # no arrow unless the rows open a machine's page
    assert 'class="machine clickable"' in sh.machine_rows_html([here], link=True)
    assert ">chevron_right<" in sh.machine_rows_html([here], link=True)


def test_demote_headings():
    out = sh.demote_headings("# Title\n## Sub\nnot # a heading\n")
    assert out.splitlines() == ["### Title", "#### Sub", "not # a heading"]


def test_board_says_who_owns_what_and_what_needs_a_person():
    incs = [
        {"id": "A", "status": "open", "severity": "high", "owner": "Amir", "sla_breached": True, "acked": False,
         "escalation_level": 1, "category": "brute_force", "opened_at": "2026-10-26T10:00:00+08:00"},
        {"id": "B", "status": "acknowledged", "severity": "medium", "owner": "Lee", "acked": True, "category": "xss"},
        {"id": "C", "status": "open", "severity": "critical", "owner": None, "acked": False, "category": "malware"},
        {"id": "D", "status": "resolved", "severity": "high", "owner": "Lee", "resolved_by": "Lee"},
    ]
    assert sh.attention(incs[1]) == []  # acknowledged and owned: in hand
    assert sh.attention(incs[0])[:2] == ["Overdue, nobody answered", "Escalated to Amir"]
    assert sh.attention(incs[2])[0] == "No owner"
    assert [i["id"] for i in sh.needs_attention(incs)] == ["C", "A"]
    c = sh.board_counts(incs, me="lee")
    assert (c["open"], c["attention"], c["overdue"], c["escalated"], c["unassigned"], c["mine"]) == (3, 2, 1, 1, 1, 1)
    df = sh.board_rows(incs)
    assert list(df["Incident"]) == ["C", "A", "B"] and list(df["Owner"]) == ["Nobody", "Amir", "Lee"]
    assert list(df[df["Incident"] == "B"]["Needs"]) == ["In hand"]
    assert "D" in list(sh.board_rows(incs, include_closed=True)["Incident"])


def test_routing_tables_use_names():
    routing = {"contacts": [{"id": "a", "name": "Amir", "role": "on_duty", "backup": "b"}, {"id": "b", "name": "Lee"}],
               "rules": [{"name": "High", "match": {"severity": ["high"]}, "owner": "a", "notify": ["b"]},
                         {"name": "Everything else", "match": {}, "owner": "a", "notify": []}]}
    rules = sh.routing_rows(routing)
    assert list(rules["When"]) == ["severity is high", "anything else"] and list(rules["Also told"]) == ["Lee", "-"]
    assert list(sh.contact_rows(routing)["Backup"]) == ["Lee", "-"]
    assert "Alerts in Telegram" not in sh.contact_rows(routing)  # Telegram not added: the core sends no link state
    routing["contacts"][0]["telegram_linked"] = True
    assert list(sh.contact_rows(routing)["Alerts in Telegram"]) == ["Own chat", "Team group"]


# ---------------------------------------------- "Who gets what" editor (sentrai_ui/routing_editor.mjs)

# GET /routing as the core sends it: people as a list, Telegram links, where each box sits on the map.
ROUTING_MAP = {"source": "routing.json",
               "contacts": [{"id": "a", "name": "Amir", "role": "on_duty", "backup": "b"},
                            {"id": "b", "name": "Lee", "role": "team_lead", "backup": "c"},
                            {"id": "c", "name": "Ika", "telegram_linked": True}],
               "rules": [{"name": "Inside", "match": {"category": ["malware"], "host": ["db-*"]}, "owner": "a",
                          "notify": ["b", "c"]},
                         {"name": "Everything else", "match": {}, "owner": "b", "notify": []}],
               "follow_up": {"escalate_after_reminders": 2},
               "layout": {"incident": [0, 120], "rules": [[210, 0], [210, 90]], "contacts": {"a": [620, 40]}}}
BLANK_PERSON = {"name": "", "role": "", "email": "", "telegram": "", "backup": ""}

# What the editor's Save sends back: people as a list in the editor's order, untrimmed text, boxes it has not
# placed as null, and keys of its own that are not part of the file.
EDITOR_SAVE = {
    "contacts": [{"id": "lee", "name": " Lee ", "role": "team_lead", "email": " lee@example.com ", "telegram": "@lee ",
                  "backup": "amir", "telegram_linked": True},
                 {"id": "amir", "name": "Amir", "role": "", "email": "", "telegram": "", "backup": ""}],
    "rules": [{"key": "r0", "name": " Web ", "match": {"category": ["xss", " "], "severity": [], "host": " web-* "},
               "owner": "lee", "notify": ["amir"]},
              {"key": "r1", "name": "Everything else", "match": {}, "owner": "amir", "notify": []}],
    "follow_up": {"escalate_after_reminders": 3, "max_escalations": 2, "resolve_within_hours": 12},
    "layout": {"incident": [0, 120], "rules": [[210, 0], None], "contacts": {"lee": [620, 40], "amir": None}},
    "version": "0123456789abcdef", "linked": {"lee": True}, "source": "routing.json",
}


def test_routing_doc_is_the_file_shape_and_a_copy():
    doc = sh.routing_doc(ROUTING_MAP)
    assert list(doc) == ["contacts", "rules", "follow_up"]  # what POST /routing takes: no source, map or links
    assert list(doc["contacts"]) == ["a", "b", "c"]  # keyed by id, in file order
    assert doc["contacts"]["a"] == {"name": "Amir", "role": "on_duty", "email": "", "telegram": "", "backup": "b"}
    assert doc["contacts"]["c"] == {**BLANK_PERSON, "name": "Ika"}
    assert doc["rules"][0] == {"name": "Inside", "match": {"category": ["malware"], "host": ["db-*"]}, "owner": "a",
                               "notify": ["b", "c"]}
    assert doc["follow_up"] == {"escalate_after_reminders": 2}
    doc["rules"][0]["notify"].append("z")
    doc["rules"][0]["match"]["host"].append("web-*")
    doc["follow_up"]["max_escalations"] = 9
    assert ROUTING_MAP["rules"][0]["notify"] == ["b", "c"]  # a copy, not the fetched data
    assert ROUTING_MAP["rules"][0]["match"]["host"] == ["db-*"]
    assert ROUTING_MAP["follow_up"] == {"escalate_after_reminders": 2}
    assert sh.routing_doc(None) == {"contacts": {}, "rules": [], "follow_up": {}}
    ids = sh.routing_doc({"contacts": [{"name": "No id"}, {"id": "", "name": "Blank"}, {"id": 7, "name": None}]})
    assert ids["contacts"] == {"7": BLANK_PERSON}  # a rule can only name someone who has an id


def test_routing_version_tells_one_saved_routing_from_another():
    version = sh.routing_version(ROUTING_MAP)
    assert re.fullmatch(r"[0-9a-f]{16}", version)
    assert sh.routing_version(copy.deepcopy(ROUTING_MAP)) == version  # same routing, same version

    def changed(edit) -> str:
        routing = copy.deepcopy(ROUTING_MAP)
        edit(routing)
        return sh.routing_version(routing)

    # Everything the editor can change makes a new version: a moved box, a rule, a person, the follow-up.
    assert changed(lambda r: r["layout"]["contacts"].update(a=[620, 41])) != version
    assert changed(lambda r: r["layout"].pop("rules")) != version
    assert changed(lambda r: r["rules"][0].update(name="Inside job")) != version
    assert changed(lambda r: r["rules"][0]["match"].update(severity=["critical"])) != version
    assert changed(lambda r: r["rules"][0].update(notify=["b"])) != version
    assert changed(lambda r: r["rules"].reverse()) != version  # the first rule that matches wins: order counts
    assert changed(lambda r: r["contacts"][2].update(email="ika@example.com")) != version
    assert changed(lambda r: r["contacts"].pop()) != version
    assert changed(lambda r: r["follow_up"].update(escalate_after_reminders=3)) != version
    # What it cannot change keeps the version, so the editor does not take it for someone else's save.
    assert changed(lambda r: r["contacts"][2].update(telegram_linked=False)) == version
    assert changed(lambda r: r.update(source="defaults")) == version
    # People are keyed by id, so the order of the list is not a change: the map orders them by the rules.
    assert changed(lambda r: r["contacts"].reverse()) == version
    assert changed(lambda r: r.update(layout=None)) == changed(lambda r: r.update(layout={}))
    assert sh.routing_version(None) == sh.routing_version({})


def test_routing_editor_data_is_what_the_map_draws():
    result = {"id": "save-2", "ok": False, "message": "rule 'Inside' needs an owner who is one of the people"}
    sent = copy.deepcopy(result)
    data = sh.routing_editor_data(ROUTING_MAP, read_only=True, lock_reason="Auditors look only.", result=result)
    assert set(data) == {"routing", "version", "linked", "categories", "severities", "roles", "read_only",
                         "lock_reason", "result", "focus", "numbers"}
    routing = data["routing"]
    assert list(routing) == ["contacts", "rules", "follow_up", "layout"]
    assert routing["contacts"] == [  # a list, in file order, each person with their id
        {"id": "a", "name": "Amir", "role": "on_duty", "email": "", "telegram": "", "backup": "b"},
        {"id": "b", "name": "Lee", "role": "team_lead", "email": "", "telegram": "", "backup": "c"},
        {"id": "c", **BLANK_PERSON, "name": "Ika"}]
    assert routing["rules"] == sh.routing_doc(ROUTING_MAP)["rules"]
    assert routing["follow_up"] == {"escalate_after_reminders": 2}
    assert routing["layout"] == ROUTING_MAP["layout"]
    assert data["version"] == sh.routing_version(ROUTING_MAP)
    assert data["linked"] == {"c": True}  # only whether someone has their own Telegram chat
    assert data["categories"] == [[k, v] for k, v in sh.CATEGORY_LABELS.items()]  # [value, label] pairs
    assert ["malware", "Malware found"] in data["categories"]
    assert data["severities"] == ["low", "medium", "high", "critical"]
    assert data["roles"] == [["", "none"], ["on_duty", "on duty"], ["team_lead", "team lead"],
                             ["it_manager", "IT manager"], ["cxo", "CXO"]]
    assert data["read_only"] is True and data["lock_reason"] == "Auditors look only."
    assert data["result"] == sent and result == sent  # as it was: the editor matches it to its save by id
    assert json.loads(json.dumps(data)) == data  # it reaches the browser as JSON, unchanged

    mine = sh.routing_editor_data(ROUTING_MAP)
    assert mine["read_only"] is False and mine["lock_reason"] == "" and mine["result"] is None
    assert sh.routing_editor_data(ROUTING_MAP, read_only=1)["read_only"] is True
    empty = sh.routing_editor_data(None)
    assert empty["routing"] == {"contacts": [], "rules": [], "follow_up": {}, "layout": {}}
    assert empty["version"] == sh.routing_version(None) and empty["linked"] == {}


def test_routing_editor_data_gives_the_browser_nothing_else():
    """Only what the map draws reaches the page: not a Telegram chat id, a token or whatever else the core adds."""
    routing = copy.deepcopy(ROUTING_MAP)
    routing["token"] = "core-token-123"
    routing["contacts"][0].update(chat_id="99887766", password="hunter2")
    routing["rules"][0]["api_key"] = "key-abc"
    data = sh.routing_editor_data(routing)
    assert data == sh.routing_editor_data(ROUTING_MAP)  # the extras change nothing
    text = json.dumps(data)
    assert not any(secret in text for secret in ("core-token-123", "99887766", "hunter2", "key-abc"))


def test_every_role_the_panel_offers_has_plain_words():
    assert list(sh.ROLE_LABELS) == sh.ROLE_CHOICES  # one label per choice, in the panel's order
    assert sh.ROLE_LABELS[""] == "none" and sh.ROLE_LABELS["it_manager"] == "IT manager"
    assert all(label and "_" not in label for label in sh.ROLE_LABELS.values())


def test_routing_from_editor_is_the_file_the_core_takes():
    out = sh.routing_from_editor(EDITOR_SAVE)
    assert list(out) == ["contacts", "rules", "follow_up", "layout"]  # none of the editor's own keys
    assert list(out["contacts"]) == ["lee", "amir"]  # keyed by id, in the editor's order
    assert out["contacts"]["lee"] == {"name": "Lee", "role": "team_lead", "email": "lee@example.com",
                                      "telegram": "@lee", "backup": "amir"}  # trimmed, no Telegram link
    assert out["rules"] == [{"name": "Web", "match": {"category": ["xss"], "host": ["web-*"]}, "owner": "lee",
                             "notify": ["amir"]},
                            {"name": "Everything else", "match": {}, "owner": "amir", "notify": []}]
    assert out["follow_up"] == EDITOR_SAVE["follow_up"]
    assert out["layout"] == EDITOR_SAVE["layout"]  # as sent: the core drops the boxes it cannot place
    assert "layout" not in sh.routing_from_editor({**EDITOR_SAVE, "layout": "junk"})
    # What the editor was given comes back as the same file (and the same map) when nothing was changed.
    given = sh.routing_editor_data(ROUTING_MAP)["routing"]
    assert sh.routing_from_editor(given) == {**sh.routing_doc(ROUTING_MAP), "layout": ROUTING_MAP["layout"]}


GARBAGE = [None, "", "routing", 42, [], [{"id": "a", "name": "A"}],
           {"contacts": None, "rules": None, "follow_up": None, "layout": None},
           {"contacts": "abc", "rules": "abc", "layout": [1, 2]},
           {"contacts": {"a": {"name": "A"}}, "rules": {"a": 1}},  # objects where the editor sends lists
           {"contacts": [None, 3, "x", [], {"id": ""}, {"name": "no id"}], "rules": [None, 3, "x", {"match": "x"}]},
           {"rules": [{"name": None, "owner": None, "notify": None, "match": {"severity": [None, "", " "]}}]}]
# Wrong-typed parts become empty ones, for the core to refuse with its own words.
WRONG_TYPES = [{"contacts": 5}, {"rules": 5}, {"rules": [{"name": "Web", "owner": "a", "notify": 5}]},
                {"follow_up": "soon"}, {"follow_up": [1, 2]}, {"follow_up": 5}]


@pytest.mark.parametrize("sent", GARBAGE + WRONG_TYPES)
def test_routing_from_editor_copes_with_garbage(sent):
    out = sh.routing_from_editor(sent)
    assert isinstance(out["contacts"], dict) and isinstance(out["rules"], list) and isinstance(out["follow_up"], dict)
    assert all(isinstance(c, dict) for c in out["contacts"].values())
    assert all(isinstance(r["match"], dict) and isinstance(r["notify"], list) for r in out["rules"])
    json.dumps(out)  # still something to post


CORE_APP = Path(__file__).resolve().parents[2] / "core" / "app"


@pytest.fixture(scope="module")
def core_routing():
    """The core's own checks for a routing file (mvp/core/app/routing.py, standard library only): they decide
    whether a save from the map is written. Loaded under a name of its own, since "app" here is the dashboard."""
    if not (CORE_APP / "routing.py").is_file():
        pytest.skip("the core is not in this checkout")
    name = "sentrai_core_app"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, CORE_APP / "__init__.py",
                                                      submodule_search_locations=[str(CORE_APP)])
        package = importlib.util.module_from_spec(spec)
        sys.modules[name] = package
        spec.loader.exec_module(package)
    return importlib.import_module(f"{name}.routing")


def test_the_core_takes_what_the_editor_sends(core_routing):
    clean = core_routing.validate(sh.routing_from_editor(EDITOR_SAVE))
    assert list(clean["contacts"]) == ["lee", "amir"] and clean["contacts"]["lee"]["email"] == "lee@example.com"
    assert [r["name"] for r in clean["rules"]] == ["Web", "Everything else"]
    assert clean["rules"][0]["match"] == {"category": ["xss"], "host": ["web-*"]}
    assert clean["follow_up"] == {"escalate_after_reminders": 3, "max_escalations": 2, "resolve_within_hours": 12}
    assert clean["layout"] == {"incident": [0, 120], "rules": [[210, 0], None], "contacts": {"lee": [620, 40]}}


OFFERED = sh.routing_editor_data(None)
CHOICES = [("category", v) for v, _ in OFFERED["categories"]] + [("severity", v) for v in OFFERED["severities"]]
@pytest.mark.parametrize("key,value", [pytest.param(k, v, id=f"{k}-{v}") for k, v in CHOICES])
def test_every_choice_the_editor_offers_is_one_the_core_accepts(core_routing, key, value):
    doc = {"contacts": {"amir": {"name": "Amir"}}, "rules": [{"name": "Rule", "match": {key: [value]}, "owner": "amir"}]}
    assert core_routing.validate(doc)["rules"][0]["match"] == {key: [value]}


def test_panel_machines_merge_scores_and_joined_agents():
    from datetime import datetime, timezone

    now = datetime(2026, 10, 26, 6, 0, 30, tzinfo=timezone.utc)
    found = [{"host": "web-01", "risk_index": 83, "band": "critical", "open_incidents": 1, "contained_incidents": 2,
              "blocked": 1, "last_seen": "2026-10-26T06:00:20+00:00", "silent": False},
             {"host": "nginx-seen", "risk_index": 0, "band": "green", "last_seen": None, "silent": False}]
    agents = [{"agent_id": "a1", "host": "web-01", "last_seen": "2026-10-26T06:00:25+00:00"},
              {"agent_id": "a2", "host": "laptop", "last_seen": None},
              {"agent_id": "a3", "host": "old", "revoked_at": "2026-10-25T00:00:00+00:00"},
              {"agent_id": "a4", "host": "stale", "last_seen": "2026-10-26T05:50:00+00:00"}]
    found.append({"host": "stale", "risk_index": 10, "band": "green", "silent": False})
    rows = sh.panel_machines(found, agents, {"threshold": 80}, now=now)
    by = {r["name"]: r for r in rows}
    assert rows[0]["name"] == "web-01" and by["web-01"]["online"] and by["web-01"]["place"] == "Agent"
    assert by["web-01"]["blocked"] == 1 and by["web-01"]["agent_id"] == "a1"
    assert by["laptop"]["waiting"] and not by["laptop"]["online"]
    assert "old" not in by  # revoked machines leave the list
    assert not by["stale"]["online"]  # agent quiet for 10 minutes
    assert by["nginx-seen"]["place"] == "Seen in logs" and by["nginx-seen"]["online"]
    html_rows = sh.machine_rows_html(rows)
    assert "Waiting" in html_rows and "waiting for its first data" in html_rows


def test_agent_rows_and_join_commands():
    df = sh.agent_rows([{"agent_id": "b", "host": "z", "revoked_at": "x", "revoked_by": "erick"},
                        {"agent_id": "a", "host": "web-01", "joined_at": "2026-10-26T06:00:00+00:00"}])
    assert list(df["Machine"]) == ["web-01", "z"] and list(df["Status"]) == ["Active", "Revoked by erick"]
    cmds = sh.join_commands("https://panel.example.com:8000/", "K7QM-2XPA-9RTD", "web-01")
    assert cmds["linux"] == ("sudo ./mvp/deploy/install-agent.sh --panel https://panel.example.com:8000 "
                             "--code K7QM-2XPA-9RTD --name web-01")
    assert cmds["windows"] == ("powershell -ExecutionPolicy Bypass -File .\\mvp\\deploy\\install-agent.ps1 "
                               "-Panel https://panel.example.com:8000 -Code K7QM-2XPA-9RTD -Name web-01")
    assert "-Name" not in sh.join_commands("https://p.example.com", "K7QM-2XPA-9RTD")["windows"]
    pin = "sha256:" + "ab" * 32
    pinned = sh.join_commands("https://panel.example.com:8443", "K7QM-2XPA-9RTD", None, pin)
    assert pinned["linux"].endswith(f"--code K7QM-2XPA-9RTD --pin {pin}") and pinned["windows"].endswith(f"-Pin {pin}")
    off = sh.agent_rows([{"agent_id": "a", "host": "web-01", "offline": {"from": "2026-10-26T10:00:00+00:00",
                                                                         "to": "2026-10-26T10:40:00+00:00",
                                                                         "local_blocks": 2}}])
    assert off["Last time offline"][0].startswith("2 local blocks")


def test_newly_joined_closes_the_join_form():
    agents = [{"agent_id": "a", "host": "web-01"}, {"agent_id": "b", "host": "homelab-01"},
              {"agent_id": "c", "host": "old", "revoked_at": "x"}]
    assert sh.newly_joined(agents, {"a"}) == ["homelab-01"]
    assert sh.newly_joined(agents, {"a", "b"}) == []
    assert sh.newly_joined(agents, None) == []  # no join code made in this session


def test_services_on_a_machine():
    svcs = [{"name": "sshd", "port": 22, "proto": "tcp", "process": "sshd", "open_incidents": 0},
            {"name": "nginx", "port": 443, "proto": "tcp", "process": "nginx", "open_incidents": 2},
            {"name": "a", "port": 1}, {"name": "b", "port": 2}, {"name": "c", "port": 3}]
    assert sh.services_text(svcs) == "nginx :443 (2 open), a :1, b :2, c :3, +1 more"
    df = sh.service_rows(svcs)
    assert list(df["Service"])[:2] == ["nginx", "a"] and df.iloc[0]["Protocol"] == "TCP"
    row = sh.panel_machines([{"host": "web-01", "risk_index": 10, "services": svcs}], [], {})[0]
    assert "nginx :443 (2 open)" in sh.machine_rows_html([row])


def test_job_rows_and_latest_findings():
    jobs = [{"kind": "threat_scan", "status": "done", "requested_by": "erick", "created_at": "2026-10-26T10:00:00+00:00",
             "finished_at": "2026-10-26T10:00:20+00:00", "summary": "3 files checked, 1 findings",
             "result": {"findings": [{"severity": "critical", "label": "PHP web shell", "kind": "web_shell",
                                      "path": "/var/www/x.php", "line": 2}]}},
            {"kind": "backup", "status": "queued", "requested_by": "erick", "created_at": "2026-10-26T10:01:00+00:00"}]
    rows = sh.job_rows(jobs)
    assert list(rows["Job"]) == ["Threat scan", "Backup"] and list(rows["Status"]) == ["Done", "Waiting"]
    found = sh.job_findings(jobs)
    assert list(found["File"]) == ["/var/www/x.php"] and found["Severity"][0] == "critical"
    assert sh.job_findings([]).empty and sh.job_rows(None).empty


def test_incident_target_names_the_live_block_then_the_source():
    inc = {"src_ip": "1.2.3.4", "host": "web", "actions": [
        {"target": "5.6.7.8", "status": "rolled_back"}, {"target": "9.9.9.9", "status": "active"}]}
    assert sh.incident_target(inc) == "9.9.9.9 on web"
    assert sh.incident_target({"src_ip": "1.2.3.4"}) == "1.2.3.4"
    assert sh.incident_target({}) == "-"


def test_times_from_the_core_show_in_local_time():
    # Works on any machine's zone (Windows has no time.tzset): both spellings of one moment
    # must print the same local clock time.
    from datetime import datetime, timezone
    local = datetime(2026, 10, 26, 18, 52, 58, tzinfo=timezone.utc).astimezone().strftime("%H:%M:%S")
    assert sh.short_time("2026-10-26T18:52:58+00:00") == local  # UTC from the fleet / jobs code
    assert sh.short_time("2026-10-27T02:52:58+08:00") == local  # same moment, another offset
    assert sh.short_time("2026-10-26T18:52:58Z") == local
    assert sh.short_time("2026-10-26T18:52:58") == "18:52:58"  # no offset: taken as local already


def test_expiry_says_how_long_is_left():
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 10, 26, 18, 0, 0, tzinfo=timezone.utc)
    soon = (now + timedelta(minutes=125, seconds=30)).isoformat()
    assert sh.expires_label(soon, now=now).endswith("(in 2 h 5 min)")
    assert sh.expires_label((now + timedelta(minutes=4)).isoformat(), now=now).endswith("(in 4 min)")
    assert sh.expires_label((now + timedelta(seconds=20)).isoformat(), now=now).endswith("(in under 1 min)")
    assert sh.expires_label((now - timedelta(minutes=1)).isoformat(), now=now).endswith("(expired)")
    assert sh.expires_label(None) == "-"


def test_approvals_headline_answers_first():
    from datetime import datetime, timedelta, timezone
    now = datetime(2026, 10, 26, 18, 0, tzinfo=timezone.utc)
    soon = (now + timedelta(minutes=90)).isoformat()
    later = (now + timedelta(minutes=110)).isoformat()
    contained = [{"id": "a", "status": "contained", "actions": [{"status": "active", "expires_at": later}]},
                 {"id": "b", "status": "contained", "actions": [{"status": "active", "expires_at": soon}]}]
    text = sh.approvals_headline(contained, now=now)
    assert text.startswith("2 waiting on you: 2 blocks to keep or roll back.")
    assert "(in 1 h 30 min)" in text  # the earliest block, not the first row
    opened = [{"id": "c", "status": "open", "actions": []}]
    assert sh.approvals_headline(opened, now=now) == "1 waiting on you: 1 to approve or reject."
    assert sh.approvals_headline([], now=now) == ""


def test_incident_age_reads_like_speech():
    assert sh.span_label(20) == "under 1 min"
    assert sh.span_label(7 * 60) == "7 min"
    assert sh.span_label(125 * 60) == "2 h 5 min"
    assert sh.span_label((3 * 24 + 4) * 3600) == "3 d 4 h"
    from datetime import datetime, timedelta
    opened = (datetime.now().astimezone() - timedelta(minutes=7, seconds=5)).isoformat()
    df = sh.board_rows([{"id": "A", "status": "open", "opened_at": opened}])
    assert df.iloc[0]["Open for"] == "7 min"


def test_actions_read_in_plain_words():
    inc = {"id": "R1", "actions": [{"action_id": "a1", "type": "block_ip", "target": "1.2.3.4", "mode": "autonomous",
                                   "status": "rolled_back"},
                                  {"action_id": "a2", "type": "new_thing", "target": "x", "mode": "operator"}]}
    df = sh.action_rows(inc)
    assert list(df["Type"]) == ["Block IP", "New thing"]
    assert list(df["Mode"]) == ["Automatic", "By a person"]
    assert list(df["Status"]) == ["Rolled back", "-"]
    rows = sh.build_containment_rows({"ips": ["1.2.3.4"], "users": ["bob"]}, [])
    assert list(rows["Action"]) == ["Block IP", "Lock account"] and list(rows["Mode"]) == ["-", "-"]


# ------------------------------------------------- each person's own part of "Who gets what"

def test_find_person_matches_the_sign_in_email_first_then_the_name():
    routing = {"contacts": [{"id": "a", "name": "Amir", "email": "Amir@Example.com"}, {"id": "b", "name": "Lee"}]}
    assert sh.find_person(routing, "amir@example.com", "Lee")["id"] == "a"
    assert sh.find_person(routing, "nobody@example.com", "@lee")["id"] == "b"
    assert sh.find_person(routing, "", "") is None
    assert sh.find_person(None, "amir@example.com") is None


def test_my_part_lists_rules_backups_and_the_incidents_that_reach_a_person():
    incidents = [{"id": "1", "owner": "Lee"}, {"id": "2", "owner": "Amir", "backup": "Lee"},
                 {"id": "3", "owner": "Amir", "notify": ["Lee", "Ika"]}, {"id": "4", "owner": "Ika"}]
    part = sh.my_part(ROUTING_MAP, "b", incidents)
    assert [r["name"] for _, r in part["owns"]] == ["Everything else"]
    assert [(i, r["name"]) for i, r in part["told"]] == [(0, "Inside")]
    assert part["backup"]["name"] == "Ika" and [c["name"] for c in part["covers"]] == ["Amir"]
    assert [[i["id"] for i in part[k]] for k in ("mine", "backing", "heard")] == [["1"], ["2"], ["3"]]


def test_my_routing_cuts_the_map_down_to_one_person_and_keeps_rule_numbers_and_places():
    cut = sh.my_routing(ROUTING_MAP, "c")  # Ika: told about rule 1, backs up Lee
    assert [r["name"] for r in cut["rules"]] == ["Inside"] and cut["numbers"] == [1]
    assert {c["id"] for c in cut["contacts"]} == {"a", "b", "c"}
    amir = sh.my_routing(ROUTING_MAP, "a")  # owns Inside, which also tells Lee and Ika: only Lee (his backup) stays
    assert {c["id"] for c in amir["contacts"]} == {"a", "b"} and amir["rules"][0]["notify"] == ["b"]
    assert cut["layout"]["rules"] == [[210, 0]] and cut["layout"]["contacts"] == {"a": [620, 40]}
    lone = sh.my_routing({**ROUTING_MAP, "contacts": ROUTING_MAP["contacts"] + [
        {"id": "d", "name": "Dee", "backup": "a"}]}, "d")  # in no rule; their backup stays, Amir's does not
    assert lone["rules"] == [] and {c["id"]: c["backup"] for c in lone["contacts"]} == {"a": "", "d": "a"}
    data = sh.routing_editor_data(cut, read_only=True, focus="c")
    assert data["focus"] == "c" and data["numbers"] == [1] and data["read_only"]


# ------------------------------------------------- "How an attack is handled" map

def _flow(**kw):
    args = dict(risk={"risk_index": 12, "band": "green", "threshold": 80}, incidents=[], agents=[], blocklist={},
                extensions=[], records=[], settings={"AUTO_ACTIONS": "block_ip", "HOTPATCH_TTL_HOURS": "2"}, chain_ok=True)
    data = sh.flow_map_data(**(args | kw))
    return {n["id"]: n for n in data["nodes"]}, data["edges"]


def test_a_quiet_system_shows_every_step_fine_and_nothing_moving():
    nodes, edges = _flow()
    assert nodes["score"]["value"] == "12" and nodes["score"]["state"] == "ok"
    assert nodes["auto"]["badge"] == "On" and nodes["auto"]["value"] == "1" and "block an address" in nodes["auto"]["what"]
    assert nodes["record"]["note"] == "records · chain intact"
    assert not any(e["live"] for e in edges)


def test_an_attack_in_progress_lights_its_path():
    waiting = {"id": "1", "status": "open", "category": "brute_force", "recommended_action": "block_ip",
               "requires_approval": True, "owner": ""}
    nodes, edges = _flow(risk={"risk_index": 85, "band": "critical", "threshold": 80}, incidents=[waiting],
                         blocklist={"ips": ["203.0.113.4"], "users": []})
    assert nodes["score"]["state"] == "alert" and nodes["block"]["state"] == "busy"
    assert nodes["owner"]["state"] == "alert" and "1 with no owner" in nodes["owner"]["note"]
    assert {(e["from"], e["to"]) for e in edges if e["live"]} >= {("score", "owner")}


def test_watch_only_and_broken_extensions_say_so():
    nodes, _ = _flow(risk={"risk_index": 5, "monitor_only": True},
                     extensions=[{"name": "telegram", "title": "Telegram", "added": True, "configured": True,
                                  "last_error": "401"}], chain_ok=False)
    assert nodes["auto"]["badge"] == "Off" and nodes["auto"]["state"] == "off"
    assert nodes["alerts"]["state"] == "alert" and "Telegram failing" in nodes["alerts"]["note"]
    assert nodes["edge"]["badge"] == "Off" and nodes["record"]["state"] == "alert"
    assert _flow(settings={"AUTO_ACTIONS": ""})[0]["auto"]["note"] == "everything waits for a person"


# ------------------------------------------------- "What it may do on its own" map

LIMITS = {"AUTO_ACTIONS": "rate_limit,block_ip", "NEEDLE_MIN_CONFIDENCE": "0.6", "RISK_THRESHOLD": "80",
          "MAX_AUTO_ACTIONS_PER_HOUR": "10", "HOTPATCH_TTL_HOURS": "2", "MAX_TTL_HOURS": "24",
          "PROTECTED_IPS": " 10.0.0.0/8 ,, 127.0.0.1", "PROTECTED_USERS": ""}


def test_limits_map_data_carries_only_the_limits_and_every_action():
    data = sh.limits_map_data(LIMITS | {"SMTP_PASSWORD": "secret"}, read_only=True, lock_reason="Look only.")
    assert set(data["settings"]) == set(sh.LIMIT_FIELDS) and "SMTP_PASSWORD" not in json.dumps(data)
    assert [a for a, _ in data["actions"]] == list(sh.ACTION_WORDS) and data["read_only"]
    assert data["version"] != sh.limits_map_data(LIMITS | {"RISK_THRESHOLD": "70"})["version"]


def test_check_limits_tidies_a_save_and_refuses_what_the_core_could_not_use():
    out = sh.check_limits(LIMITS | {"SMTP_HOST": "evil.example"})
    assert out["AUTO_ACTIONS"] == "block_ip,rate_limit" and out["PROTECTED_IPS"] == "10.0.0.0/8,127.0.0.1"
    assert "SMTP_HOST" not in out
    for bad in ({"AUTO_ACTIONS": "rm_rf"}, {"NEEDLE_MIN_CONFIDENCE": "1.5"}, {"RISK_THRESHOLD": "eighty"},
                {"MAX_AUTO_ACTIONS_PER_HOUR": "-1"}, {"HOTPATCH_TTL_HOURS": "0"}, {"HOTPATCH_TTL_HOURS": "30"}):
        with pytest.raises(ValueError):
            sh.check_limits(LIMITS | bad)


def test_update_status(tmp_path):
    version, check = tmp_path / "VERSION", tmp_path / "update-check.json"
    old, new = "a" * 40, "b" * 40
    assert sh.update_status(version, check) == {"version": "", "available": False, "latest": "", "ref": "", "checked": ""}
    version.write_text(f"commit={old}\nref=main\nrepo=https://github.com/RexGuard/SentrAI\n")
    assert sh.update_status(version, check)["version"] == "aaaaaaa"
    check.write_text(json.dumps({"installed": old, "latest": new, "available": True, "ref": "main"}))
    u = sh.update_status(version, check)
    assert u["available"] and u["latest"] == "bbbbbbb" and u["ref"] == "main"
    # Installed since the check ran: the notice goes at once, before the next check.
    version.write_text(f"commit={new}\n")
    assert not sh.update_status(version, check)["available"]
    check.write_text("not json")
    assert not sh.update_status(version, check)["available"]


# ---------------------------------------------------------------- hardware (core hardware.py)
HW = {"cpu": {"percent": 12.4, "cores": 4, "load": [0.5, 0.4, 0.3]},
      "memory": {"total": 8 * 2**30, "used": 5 * 2**30, "percent": 62.5},
      "disks": [{"mount": "/data", "total": 500 * 2**30, "used": 100 * 2**30, "percent": 20.0},
                {"mount": "/", "total": 80 * 2**30, "used": 75 * 2**30, "percent": 93.0}],
      "net": {"recv_rate": 15360.0, "sent_rate": 2048.0},
      "temps": [{"label": "nvme Composite", "current": 41.0, "high": 84.8},
                {"label": "coretemp Package id 0", "current": 58.2, "high": 100.0}],
      "uptime_s": 3 * 86400 + 4 * 3600, "os": "Linux 6.8.0", "at": "2026-10-27T02:45:20+00:00",
      "warnings": ["disk / is 93% full (limit 90%)"]}


def test_hardware_labels():
    assert sh.bytes_label(1536) == "1.5 KB" and sh.bytes_label(8 * 2**30) == "8.0 GB" and sh.bytes_label(None) == "-"
    assert sh.rate_label(2048.0) == "2.0 KB/s" and sh.pct_label(41.0) == "41%"
    assert sh.hardware_text(HW) == "4 cores · 8.0 GB memory · Linux 6.8.0 · up 3 d 4 h"
    assert sh.hardware_text(None) == ""


def test_hardware_cells_mark_what_is_over_its_limit():
    assert sh.hardware_hot(HW) == {"disk"}
    assert sh.hardware_cells(HW) == [("CPU", "12%", False), ("Memory", "62%", False), ("Disk", "93%", True)]
    stats = {label: (value, note, hot) for label, value, note, hot in sh.hardware_stats(HW)}
    assert stats["Fullest disk"] == ("93%", "/ · 80.0 GB", True)
    assert stats["Hottest"][0] == "58 °C" and stats["Network in"] == ("15.0 KB/s", "out 2.0 KB/s", False)
    assert sh.hardware_cells(None) == [] and sh.hardware_stats({}) == []


def test_machine_row_shows_hardware_when_online():
    m = {"name": "web-01", "place": "Agent", "host": "web-01", "online": True, "index": 10.0, "band": "green",
         "threshold": 80, "monitor_only": False, "open": 0, "contained": 0, "blocked": 0, "last_seen": None,
         "hardware": HW}
    row = sh.machine_rows_html([m])
    assert 'm-stat hw' in row and ">93%<" in row and "Incidents" in row
    assert "m-stat hw" not in sh.machine_rows_html([{**m, "online": False}])  # an offline machine's numbers are old


def test_hardware_tables_and_charts():
    disks = sh.disk_rows(HW)
    assert list(disks["Disk"]) == ["/", "/data"] and disks["Full"].iloc[0] == 93.0
    assert list(sh.temp_rows(HW)["Sensor"]) == ["nvme Composite", "coretemp Package id 0"]
    df = sh.hardware_frame([{"t": "2026-10-27T02:45:50+00:00", "cpu": 20.0, "memory": 60.0, "disk": 93.0,
                             "net_in": 100.0, "net_out": None},
                            {"t": "2026-10-27T02:45:20+00:00", "cpu": 10.0, "memory": "x"}, {"t": "bad"}])
    assert list(df["cpu"]) == [10.0, 20.0] and df["memory"].isna().iloc[0]
    fig = sh.usage_figure(df, {"alerts": True, "cpu": 90})
    assert [t.name for t in fig.data] == ["CPU", "Memory", "Fullest disk"]
    assert [t.name for t in sh.network_figure(df).data] == ["In"]
    assert sh.usage_figure(sh.hardware_frame([]), {}).data == ()


def test_waves_fold_into_one_board_row_and_one_attention_line():
    scan = {"category": "port_scan", "host": "game-01", "severity": "medium", "status": "open", "owner": "Amir"}
    members = [{**scan, "id": f"R{n}", "src_ip": f"198.51.100.{n}", "wave": "WAVE-001"} for n in range(30)]
    other = {"id": "S1", "category": "sql_injection", "host": "game-01", "severity": "high", "status": "open"}
    singles, waves = sh.split_waves([*members, other])
    assert [i["id"] for i in singles] == ["S1"] and len(waves["WAVE-001"]) == 30
    assert sh.wave_line(waves["WAVE-001"]) == "30 addresses scanning game-01 need a person"
    df = sh.board_rows([*members, other], group_waves=True)
    assert sorted(df["Incident"]) == ["S1", "WAVE-001 (30)"]
    row = df[df["Incident"] == "WAVE-001 (30)"].iloc[0]
    assert row["Status"] == "30 open" and row["Owner"] == "Amir"
    assert len(sh.board_rows([*members, other])) == 31  # not grouped: one row each
    w = sh.wave_rows([{"id": "WAVE-001", "category": "port_scan", "host": "game-01", "addresses": 30,
                       "networks": [{"network": "198.51.100.0/24", "addresses": 30}],
                       "started_at": "2026-10-28T14:02:11+08:00", "last_seen_at": "2026-10-28T14:31:40+08:00",
                       "active": True}])
    assert list(w.iloc[0][["Wave", "Addresses", "Top networks", "Started", "Now"]]) == [
        "WAVE-001", 30, "198.51.100.0/24 (30)", "14:02", "Going"]
    assert sh.wave_rows([]).empty
