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
    assert "m-more" not in rows  # no arrow unless the rows open details
    assert 'class="machine clickable"' in sh.machine_rows_html([here], opened=False)
    assert ">expand_more<" in sh.machine_rows_html([here], opened=False)
    assert ">expand_less<" in sh.machine_rows_html([here], opened=True)


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
    routing["contacts"][0]["telegram_linked"] = True
    assert list(sh.contact_rows(routing)["Alerts in Telegram"]) == ["Own chat", "Team group"]


ROUTING_MAP = {"contacts": [{"id": "a", "name": "Amir", "role": "on_duty", "backup": "b"},
                            {"id": "b", "name": "Lee", "role": "team_lead", "backup": "c"},
                            {"id": "c", "name": "Ika", "telegram_linked": True}],
               "rules": [{"name": "Inside", "match": {"category": ["malware"], "host": ["db-*"]}, "owner": "a",
                          "notify": ["b", "c"]},
                         {"name": "Everything else", "match": {}, "owner": "b", "notify": []}],
               "follow_up": {"escalate_after_reminders": 2}}


def test_routing_map_draws_rules_owners_told_and_backups():
    dot = sh.routing_dot(ROUTING_MAP)
    assert dot.startswith("digraph") and dot.rstrip().endswith("}")
    assert 'rule1 [label="1. Inside\\nMalware found; machine\\ndb-*"' in dot  # wrapped
    assert 'rule2 [label="2. Everything else"' in dot  # no "anything else" under it
    assert 'rule1 -> "p_a" [label="owns"' in dot and 'rule1 -> "p_c" [color' in dot
    assert '"p_a" -> "p_b" [label="backup"' in dot and '"p_c" ->' not in dot
    assert 'own Telegram chat' in dot
    odd = {"contacts": [{"id": "x", "name": 'Say "hi" \\ bye'}], "rules": []}
    assert '"p_x" [label="Say \\"hi\\" \\\\ bye\\nin no rule yet", style="rounded,dashed"]' in sh.routing_dot(odd)


def test_routing_doc_round_trips_to_the_file_shape():
    doc = sh.routing_doc(ROUTING_MAP)
    assert doc["contacts"]["a"] == {"name": "Amir", "role": "on_duty", "email": "", "telegram": "", "backup": "b"}
    assert doc["rules"][0]["notify"] == ["b", "c"] and doc["follow_up"] == {"escalate_after_reminders": 2}
    doc["rules"][0]["notify"].append("z")
    assert ROUTING_MAP["rules"][0]["notify"] == ["b", "c"]  # a copy, not the fetched data
    assert sh.new_contact_id(doc, "Amir Q.") == "amir-q"
    doc["contacts"]["amir-q"] = {}
    assert sh.new_contact_id(doc, "Amir Q.") == "amir-q-2" and sh.new_contact_id(doc, "!!") == "person"


def test_removing_someone_who_owns_a_rule_is_refused():
    doc = sh.routing_doc(ROUTING_MAP)
    try:
        sh.remove_contact(doc, "b")
    except ValueError as exc:
        assert "Lee owns Everything else" in str(exc)
    else:
        raise AssertionError("expected a refusal")
    assert "b" in doc["contacts"]


def test_removing_someone_passes_their_backup_on_and_drops_them_from_told():
    doc = sh.routing_doc(ROUTING_MAP)
    doc["rules"][1]["owner"] = "a"
    notes = sh.remove_contact(doc, "b")
    assert "b" not in doc["contacts"] and doc["contacts"]["a"]["backup"] == "c"
    assert doc["rules"][0]["notify"] == ["c"]
    assert notes == ["Amir's backup is now Ika", "Inside no longer tells Lee"]


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
