"""Classifier accuracy on the labelled event set (eval/events.jsonl).

Scores each classifier step on its own and the chain as it runs in core:

- rules      RulesClassifier alone. Events it cannot settle count as "no answer" (a miss).
- fallback   FallbackClassifier (keyword heuristic) alone.
- chain      rules -> fallback, which is what core runs when no TypeSafe key is set.
- jev        Jev (TypeSafe System One) alone, and chain+jev (rules -> Jev -> fallback).
             Only when TYPESAFE_API_KEY is set and typesafe_sdk imports; otherwise the
             columns say "not run".

Events are fed in file order with their own timestamps, so the brute-force threshold
(5 failed logins from one source within 60 s) behaves as it does live.

    python eval/evaluate.py            # writes eval/results/classifier_eval.{md,json,csv}
    python eval/evaluate.py --no-write # print only
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

EVAL_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(EVAL_DIR.parent / "core"))

from app.classifier import (  # noqa: E402
    ClassifierChain,
    FallbackClassifier,
    JevClassifier,
    RulesClassifier,
)
from app.jev_client import JevClient  # noqa: E402
from app.risk import CATEGORIES  # noqa: E402
from app.rules import RulesEngine  # noqa: E402

EVENTS = EVAL_DIR / "events.jsonl"
RESULTS = EVAL_DIR / "results"
NONE = "(no answer)"
ATTACKS = [c for c in CATEGORIES if c != "benign"]


def load_events(path: Path = EVENTS) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _ts(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["timestamp"]).timestamp()


def predictors(jev: JevClient | None) -> dict[str, Callable[[], Callable[[dict], str]]]:
    """name -> factory giving a fresh predict(event) (fresh rules state per run)."""

    def rules_only():
        r = RulesClassifier(RulesEngine())
        return lambda ev: (c.category if (c := r.classify(ev, _ts(ev))) else NONE)

    def fallback_only():
        f = FallbackClassifier()
        return lambda ev: f.classify(ev).category

    def chain():
        ch = ClassifierChain(RulesClassifier(RulesEngine()), FallbackClassifier())
        return lambda ev: ch.classify(ev, _ts(ev)).category

    out = {"rules": rules_only, "fallback": fallback_only, "chain": chain}
    if jev is not None:
        def jev_only():
            j = JevClassifier(jev)
            return lambda ev: (c.category if (c := j.classify(ev, _ts(ev))) else NONE)

        def chain_jev():
            ch = ClassifierChain(RulesClassifier(RulesEngine()), JevClassifier(jev), FallbackClassifier())
            return lambda ev: ch.classify(ev, _ts(ev)).category

        out["jev"] = jev_only
        out["chain+jev"] = chain_jev
    return out


def score(labels: list[str], preds: list[str]) -> dict[str, Any]:
    per: dict[str, dict[str, float]] = {}
    for cat in CATEGORIES:
        tp = sum(1 for y, p in zip(labels, preds) if y == cat and p == cat)
        fp = sum(1 for y, p in zip(labels, preds) if y != cat and p == cat)
        fn = sum(1 for y, p in zip(labels, preds) if y == cat and p != cat)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[cat] = {"precision": prec, "recall": rec, "f1": f1, "support": tp + fn, "predicted": tp + fp}
    present = [c for c in CATEGORIES if per[c]["support"]]
    attacks = [i for i, y in enumerate(labels) if y != "benign"]
    benign = [i for i, y in enumerate(labels) if y == "benign"]
    flagged = lambda p: p not in ("benign", NONE)  # noqa: E731
    return {
        "per_category": per,
        "accuracy": sum(y == p for y, p in zip(labels, preds)) / len(labels),
        "macro_f1": sum(per[c]["f1"] for c in present) / len(present),
        # Any attack label on an attack event, right category or not.
        "detection_rate": sum(flagged(preds[i]) for i in attacks) / len(attacks) if attacks else 0.0,
        # Benign events given an attack label.
        "false_alarm_rate": sum(flagged(preds[i]) for i in benign) / len(benign) if benign else 0.0,
        "no_answer": sum(p == NONE for p in preds),
    }


def evaluate(events: list[dict[str, Any]], jev: JevClient | None = None) -> dict[str, Any]:
    labels = [ev["label"] for ev in events]
    runs: dict[str, Any] = {}
    for name, make in predictors(jev).items():
        predict = make()
        t = time.perf_counter()
        preds = [predict(ev) for ev in events]
        elapsed = time.perf_counter() - t
        runs[name] = {**score(labels, preds), "ms_per_event": 1000 * elapsed / len(events),
                      "mistakes": [{"event_id": ev["event_id"], "origin": ev["origin"], "raw": ev["raw"],
                                    "label": y, "predicted": p}
                                   for ev, y, p in zip(events, labels, preds) if y != p]}
    by_origin: dict[str, int] = {}
    for ev in events:
        by_origin[ev["origin"]] = by_origin.get(ev["origin"], 0) + 1
    return {"events": len(events), "by_origin": by_origin, "jev_status": jev.status if jev else "not run", "runs": runs}


def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def to_markdown(res: dict[str, Any]) -> str:
    runs = res["runs"]
    cols = ["rules", "fallback", "chain", "jev", "chain+jev"]
    heads = {"rules": "Rules", "fallback": "Keyword fallback", "chain": "Chain (as shipped)",
             "jev": "Jev", "chain+jev": "Chain with Jev"}
    lines = [
        "# CactAI classifier accuracy",
        "",
        f"{res['events']} labelled events ({', '.join(f'{v} {k}' for k, v in res['by_origin'].items())}). "
        "Built by `eval/build_dataset.py`, scored by `eval/evaluate.py`.",
        f"Jev: {res['jev_status']}.",
        "",
        "## Headline",
        "",
        "| | " + " | ".join(heads[c] for c in cols) + " |",
        "|---|" + "---|" * len(cols),
    ]
    for key, title in [("macro_f1", "Macro F1"), ("accuracy", "Accuracy"),
                       ("detection_rate", "Attacks flagged"), ("false_alarm_rate", "False alarms on benign")]:
        lines.append(f"| {title} | " + " | ".join(_pct(runs[c][key]) if c in runs else "not run" for c in cols) + " |")
    lines.append("| No answer | " + " | ".join(str(runs[c]["no_answer"]) if c in runs else "not run" for c in cols) + " |")
    lines += ["", "## F1 per category", "",
              "Precision / recall / F1. Support is the number of events with that label.", "",
              "| Category | Support | " + " | ".join(heads[c] for c in cols) + " |",
              "|---|---|" + "---|" * len(cols)]
    first = next(iter(runs.values()))
    for cat in CATEGORIES:
        sup = first["per_category"][cat]["support"]
        cells = []
        for c in cols:
            if c not in runs:
                cells.append("not run")
                continue
            m = runs[c]["per_category"][cat]
            cells.append(f"{_pct(m['precision'])} / {_pct(m['recall'])} / **{_pct(m['f1'])}**")
        lines.append(f"| {cat} | {sup} | " + " | ".join(cells) + " |")
    lines += ["", "## What the shipped chain gets wrong", ""]
    mistakes = runs["chain"]["mistakes"]
    if not mistakes:
        lines.append("Nothing.")
    else:
        lines += ["| Event | Label | Predicted | Line |", "|---|---|---|---|"]
        for m in mistakes:
            raw = m["raw"].replace("|", "\\|")
            lines.append(f"| {m['event_id']} ({m['origin']}) | {m['label']} | {m['predicted']} | `{raw[:90]}` |")
    lines += ["", "\"Attacks flagged\" counts any attack label on an attack event, even the wrong one. "
              "Rules \"no answer\" means the event was passed on to Jev or the fallback.", ""]
    return "\n".join(lines)


def to_csv(res: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["classifier", "category", "precision", "recall", "f1", "support"])
        for name, r in res["runs"].items():
            for cat, m in r["per_category"].items():
                w.writerow([name, cat, f"{m['precision']:.3f}", f"{m['recall']:.3f}", f"{m['f1']:.3f}", m["support"]])
            w.writerow([name, "MACRO", "", "", f"{r['macro_f1']:.3f}", res["events"]])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--events", type=Path, default=EVENTS)
    ap.add_argument("--no-write", action="store_true", help="print the table, do not write eval/results/")
    args = ap.parse_args()

    jev = JevClient(timeout_s=5.0)
    res = evaluate(load_events(args.events), jev if jev.enabled else None)
    if not jev.enabled:
        res["jev_status"] = jev.status
    md = to_markdown(res)
    print(md)
    if not args.no_write:
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "classifier_eval.md").write_text(md, encoding="utf-8")
        slim = {**res, "runs": {k: {kk: vv for kk, vv in v.items() if kk != "ms_per_event"} for k, v in res["runs"].items()}}
        (RESULTS / "classifier_eval.json").write_text(json.dumps(slim, indent=2) + "\n", encoding="utf-8")
        to_csv(res, RESULTS / "classifier_eval.csv")
        print(f"\nwrote {RESULTS.relative_to(EVAL_DIR.parent)}/classifier_eval.{{md,json,csv}}")


if __name__ == "__main__":
    main()
