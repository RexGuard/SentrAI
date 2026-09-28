"""Checks for the classifier evaluation (python -m pytest eval)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import evaluate  # noqa: E402
from app.jev_client import JevResult  # noqa: E402
from app.risk import CATEGORIES  # noqa: E402


class FakeJev:
    """Stands in for JevClient: always answers with the event's true label."""

    status = "fake"

    def classify(self, event):
        return JevResult(event["label"], 0.9, 0.0 if event["label"] == "benign" else 0.9, {})


def test_dataset_is_labelled_and_covers_every_category():
    events = evaluate.load_events()
    assert {ev["label"] for ev in events} == set(CATEGORIES)
    assert {ev["origin"] for ev in events} == {"lab", "replay", "handcrafted"}
    assert len({ev["event_id"] for ev in events}) == len(events)


def test_score_counts_precision_recall_and_no_answer():
    s = evaluate.score(["xss", "xss", "benign", "benign"], ["xss", evaluate.NONE, "xss", "benign"])
    xss = s["per_category"]["xss"]
    assert (xss["precision"], xss["recall"], xss["support"]) == (0.5, 0.5, 2)
    assert s["no_answer"] == 1
    assert s["detection_rate"] == 0.5 and s["false_alarm_rate"] == 0.5


def test_without_jev_the_jev_columns_say_not_run():
    res = evaluate.evaluate(evaluate.load_events())
    assert set(res["runs"]) == {"rules", "fallback", "chain"}
    md = evaluate.to_markdown(res)
    assert "not run" in md and "| xss |" in md


def test_jev_columns_use_the_jev_answers():
    res = evaluate.evaluate(evaluate.load_events(), jev=FakeJev())
    assert res["runs"]["jev"]["accuracy"] == 1.0
    # Rules still answer first in the chain, so the chain is not simply Jev.
    assert res["runs"]["chain+jev"]["accuracy"] >= res["runs"]["chain"]["accuracy"]
