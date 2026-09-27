from cactai_ui import shaping as sh


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


def test_containment_rows():
    df = sh.build_containment_rows({"ips": ["203.0.113.45"], "users": ["admin"]}, INCIDENTS)
    kinds = list(df["Kind"])
    assert kinds.count("IP") == 1 and kinds.count("User") == 1 and kinds.count("Rule") == 1
    ip = df[df["Kind"] == "IP"].iloc[0]
    assert ip["Incident"] == "RSK-1" and ip["Approved by"] == "Needle"
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
    assert feed[1]["agent"] == "Needle"
    assert feed[2]["agent"] == "Saguaro"  # inferred from type


def test_history_and_figures():
    df = sh.history_frame([{"t": "2026-09-29T14:00:05+08:00", "risk_index": 44},
                           {"t": "2026-09-29T14:00:00+08:00", "risk_index": 8},
                           {"t": None, "risk_index": 3}, "junk"])
    assert list(df["risk_index"]) == [8, 44]
    fig = sh.history_figure(df, 80)
    assert fig.data[0].line.color == sh.BAND_COLORS["amber"]
    g = sh.gauge_figure(91, 80)
    assert g.data[0].value == 91
    assert g.data[0].gauge.bar.color == sh.BAND_COLORS["critical"]
    assert g.data[0].gauge.threshold.value == 80
    assert sh.gauge_figure(None).data[0].value == 0


def test_demote_headings():
    out = sh.demote_headings("# Title\n## Sub\nnot # a heading\n")
    assert out.splitlines() == ["### Title", "#### Sub", "not # a heading"]
