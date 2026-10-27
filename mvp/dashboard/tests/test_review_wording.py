from sentrai_ui import shaping as sh


def test_unanswered_time_reads_in_words():
    df = sh.risk_breakdown([{"id": "A", "status": "open", "time_unaddressed_hours": 2.5},
                            {"id": "B", "status": "contained", "time_unaddressed_hours": 1}])
    got = dict(zip(df["Incident"], df["Unanswered for"]))
    assert got == {"A": "2 h 30 min", "B": "-"}
