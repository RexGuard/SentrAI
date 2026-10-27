from sentrai_ui import shaping as sh

RECORDS = [
    {"seq": 1, "ts": "2026-10-26T10:00:00", "type": "action_applied", "data": {"agent": "Garrison-Linux"}},
    {"seq": 2, "ts": "2026-10-26T10:05:00", "type": "action_applied", "data": {"agent": "Garrison-Linux"}},
    {"seq": 3, "ts": "2026-10-26T10:01:00", "type": "needle_review", "data": {"agent": "Needle"}},
]


def test_agent_list_counts_records_busiest_first():
    agents = [{"name": "Saguaro", "role": "decides", "can_execute": False},
              {"name": "Garrison-Linux", "role": "enforces", "can_execute": True}]
    df = sh.agent_table(agents, RECORDS)
    assert list(df["Agent"]) == ["Garrison-Linux", "Warden"]  # old names shown under the new ones
    assert list(df["Records"]) == [2, 0] and list(df["Last"]) == ["10:05:00", "-"]
    assert list(df["Can act"]) == ["Yes", "No"]


def test_agents_seen_in_records_show_without_the_core_list():
    df = sh.agent_table([], RECORDS)
    assert dict(zip(df["Agent"], df["Records"])) == {"Garrison-Linux": 2, "Countersign": 1}
    assert list(df.columns) == ["Agent", "Records", "Last"]  # no empty Role / Can act columns
