"""Guards for the public-server replay set: the numbers in results/ must not quietly get worse."""

from pathlib import Path

import build_replay as build
import score_replay as ev

HERE = Path(__file__).resolve().parent


def _chain():
    res = ev.evaluate(ev.load_events(), ev.load_core(HERE.parents[1] / "core"))
    return res["runs"]["chain"]


def test_events_file_matches_the_builder():
    fresh = build.Builder().build()
    assert [e["raw"] for e in fresh] == [e["raw"] for e in ev.load_events()]


def test_no_documentation_range_leaks():
    import re
    for e in ev.load_events():
        for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", e["raw"]):
            assert ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.", "0.0.0.0")), ip


def test_attackers_caught_and_no_false_alarms():
    chain = _chain()
    attackers = [s for s in chain["sources"] if s["label"] != "benign"]
    normal = [s for s in chain["sources"] if s["label"] == "benign"]
    assert sum(1 for s in attackers if s["first_flag"]) >= 25
    assert not [s["session"] for s in normal if s["flagged"]]
    assert chain["per_category"]["data_exfiltration"]["predicted"] == 0
