"""Classifier accuracy on the public-server replay set (eval/realworld/events.jsonl).

Same measures as the lab table in PR #18 (per-category precision / recall / F1, attacks flagged,
false alarms), plus a per-source view: for each attacker, whether the chain flagged it at all
and after how many of its lines; for each normal source, whether any of its lines raised an alarm.

- rules      RulesClassifier alone ("no answer" = handed on to Jev / fallback, a miss).
- fallback   FallbackClassifier (keyword heuristic) alone.
- chain      rules -> fallback, what core runs without a TypeSafe key. Events carry only `raw`,
             so this shows the rules parsing lines themselves.
- chain+parsed  the same chain after the collector's parser (lab/collector/parsers.py, PR #23)
             has filled `parsed`, `src_ip` and `user`, as on a live server. Skipped if absent.

Events run in file order with their own timestamps, so the thresholds behave as they do live.

    python eval/realworld/score_replay.py                 # writes eval/realworld/results/
    python eval/realworld/score_replay.py --no-write
    python eval/realworld/score_replay.py --core <dir> --tag before   # score another copy of core/
    python eval/realworld/score_replay.py --parser <path to parsers.py>
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
EVENTS = HERE / "events.jsonl"
RESULTS = HERE / "results"
NONE = "(no answer)"


def load_core(core_dir: Path):
    sys.path.insert(0, str(core_dir))
    from app.classifier import ClassifierChain, FallbackClassifier, RulesClassifier  # noqa: E402
    from app.risk import CATEGORIES  # noqa: E402
    from app.rules import RulesEngine  # noqa: E402
    return ClassifierChain, FallbackClassifier, RulesClassifier, RulesEngine, CATEGORIES


def load_parser(path: Path):
    """The collector's parse_line(), or None."""
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location("cactai_collector_parsers", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.parse_line


def with_parsed(events: list[dict[str, Any]], parse_line) -> list[dict[str, Any]]:
    """What the collector would send: parsed fields plus src_ip / user; raw stays the line."""
    out = []
    for ev in events:
        fmt = "nginx_access" if ev["origin"] == "web" else "syslog"
        p = parse_line(ev["raw"], fmt) or parse_line(ev["raw"], "auto")
        e = dict(ev)
        if p is not None:
            e.update(parsed=p.fields, src_ip=p.src_ip, user=p.user)
        out.append(e)
    return out


def load_events(path: Path = EVENTS) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _ts(ev: dict[str, Any]) -> float:
    return datetime.fromisoformat(ev["timestamp"]).timestamp()


def predictors(core) -> dict[str, Callable[[], Callable[[dict], str]]]:
    ClassifierChain, FallbackClassifier, RulesClassifier, RulesEngine, _ = core

    def rules_only():
        r = RulesClassifier(RulesEngine())
        return lambda ev: (c.category if (c := r.classify(dict(ev), _ts(ev))) else NONE)

    def fallback_only():
        f = FallbackClassifier()
        return lambda ev: f.classify(dict(ev)).category

    def chain():
        ch = ClassifierChain(RulesClassifier(RulesEngine()), FallbackClassifier())
        return lambda ev: ch.classify(dict(ev), _ts(ev)).category

    return {"rules": rules_only, "fallback": fallback_only, "chain": chain}


def flagged(p: str) -> bool:
    return p not in ("benign", NONE)


def score(labels: list[str], preds: list[str], categories: list[str]) -> dict[str, Any]:
    per: dict[str, dict[str, float]] = {}
    for cat in categories:
        tp = sum(1 for y, p in zip(labels, preds) if y == cat and p == cat)
        fp = sum(1 for y, p in zip(labels, preds) if y != cat and p == cat)
        fn = sum(1 for y, p in zip(labels, preds) if y == cat and p != cat)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[cat] = {"precision": prec, "recall": rec, "f1": f1, "support": tp + fn, "predicted": tp + fp}
    present = [c for c in categories if per[c]["support"]]
    attacks = [i for i, y in enumerate(labels) if y != "benign"]
    benign = [i for i, y in enumerate(labels) if y == "benign"]
    return {
        "per_category": per,
        "accuracy": sum(y == p for y, p in zip(labels, preds)) / len(labels),
        "macro_f1": sum(per[c]["f1"] for c in present) / len(present),
        "detection_rate": sum(flagged(preds[i]) for i in attacks) / len(attacks) if attacks else 0.0,
        "false_alarm_rate": sum(flagged(preds[i]) for i in benign) / len(benign) if benign else 0.0,
        "no_answer": sum(p == NONE for p in preds),
    }


def per_source(events: list[dict[str, Any]], preds: list[str]) -> list[dict[str, Any]]:
    """One row per session: attackers (caught? after how many lines? right category?) and normal sources."""
    rows: dict[str, dict[str, Any]] = {}
    for ev, p in zip(events, preds):
        r = rows.setdefault(ev["session"], {"session": ev["session"], "label": ev["label"], "scenario": ev["scenario"],
                                            "origin": ev["origin"], "lines": 0, "first_flag": None, "flagged": 0,
                                            "categories": {}})
        r["lines"] += 1
        if flagged(p):
            r["flagged"] += 1
            r["categories"][p] = r["categories"].get(p, 0) + 1
            if r["first_flag"] is None:
                r["first_flag"] = r["lines"]
    return list(rows.values())


def evaluate(events: list[dict[str, Any]], core, parse_line=None) -> dict[str, Any]:
    categories = core[4]
    labels = [ev["label"] for ev in events]
    runs: dict[str, Any] = {}
    plan = [(name, make, events) for name, make in predictors(core).items()]
    if parse_line is not None:
        plan.append(("chain+parsed", predictors(core)["chain"], with_parsed(events, parse_line)))
    for name, make, evs in plan:
        predict = make()
        preds = [predict(ev) for ev in evs]
        runs[name] = {**score(labels, preds, categories),
                      "mistakes": [{"event_id": ev["event_id"], "session": ev["session"], "raw": ev["raw"], "label": y,
                                    "predicted": p} for ev, y, p in zip(events, labels, preds) if y != p]}
        if name.startswith("chain"):
            runs[name]["sources"] = per_source(events, preds)
    by_origin: dict[str, int] = {}
    for ev in events:
        by_origin[ev["origin"]] = by_origin.get(ev["origin"], 0) + 1
    return {"events": len(events), "by_origin": by_origin, "categories": categories, "runs": runs}


def _pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def to_markdown(res: dict[str, Any], before: dict[str, Any] | None = None) -> str:
    runs = res["runs"]
    cols = ["rules", "fallback", "chain"] + (["chain+parsed"] if "chain+parsed" in runs else [])
    heads = {"rules": "Rules", "fallback": "Keyword fallback", "chain": "Chain (as shipped)",
             "chain+parsed": "Chain, collector-parsed events"}
    if before:
        runs = {**runs, "before": before["runs"]["chain"]}
        cols.append("before")
        heads["before"] = "Chain before this change"
    lines = [
        "# SentrAI classifier accuracy: public-server replay",
        "",
        f"{res['events']} labelled synthetic events ({res['by_origin'].get('web', 0)} nginx access lines, "
        f"{res['by_origin'].get('ssh', 0)} sshd lines). Built by `eval/realworld/build_replay.py`, scored by "
        "`eval/realworld/score_replay.py`. Jev not run." + (
            "" if "chain+parsed" in res["runs"] else " Collector parser not found, so the collector-parsed column is not run."),
        "",
        "## Headline",
        "",
        "| | " + " | ".join(heads[c] for c in cols) + " |",
        "|---|" + "---|" * len(cols),
    ]
    for key, title in [("macro_f1", "Macro F1"), ("accuracy", "Accuracy"),
                       ("detection_rate", "Attack lines flagged"), ("false_alarm_rate", "False alarms on benign lines")]:
        lines.append(f"| {title} | " + " | ".join(_pct(runs[c][key]) for c in cols) + " |")
    lines.append("| No answer | " + " | ".join(str(runs[c]["no_answer"]) for c in cols) + " |")
    lines.append("| Lines called data exfiltration (none are) | " + " | ".join(
        str(runs[c]["per_category"]["data_exfiltration"]["predicted"]) for c in cols) + " |")
    lines += ["", "## F1 per category", "", "Precision / recall / F1. Support is the number of lines with that label.", "",
              "| Category | Support | " + " | ".join(heads[c] for c in cols) + " |", "|---|---|" + "---|" * len(cols)]
    for cat in res["categories"]:
        sup = runs["chain"]["per_category"][cat]["support"]
        if not sup and not any(runs[c]["per_category"].get(cat, {}).get("predicted") for c in cols):
            continue
        cells = []
        for c in cols:
            m = runs[c]["per_category"].get(cat, {"precision": 0, "recall": 0, "f1": 0})
            cells.append(f"{_pct(m['precision'])} / {_pct(m['recall'])} / **{_pct(m['f1'])}**")
        lines.append(f"| {cat} | {sup} | " + " | ".join(cells) + " |")

    sources = runs["chain"]["sources"]
    attackers = [s for s in sources if s["label"] != "benign"]
    normal = [s for s in sources if s["label"] == "benign"]
    caught = [s for s in attackers if s["first_flag"]]
    right = [s for s in caught if max(s["categories"], key=s["categories"].get) == s["label"]]
    noisy = [s for s in normal if s["flagged"]]
    lines += ["", "## Per source (chain as shipped)", "",
              f"Attackers flagged: **{len(caught)} of {len(attackers)}** ({len(right)} with the right category). "
              f"Normal sources that raised any alarm: **{len(noisy)} of {len(normal)}**.", "",
              "| Attacker | Kind | Label | Lines | Flagged from line | Flagged as |", "|---|---|---|---|---|---|"]
    for s in sorted(attackers, key=lambda s: (s["origin"], s["session"])):
        got = ", ".join(f"{k} ({v})" for k, v in s["categories"].items()) or "missed"
        lines.append(f"| {s['session']} | {s['scenario']} | {s['label']} | {s['lines']} | {s['first_flag'] or '-'} | {got} |")
    if noisy:
        lines += ["", "Normal sources with a false alarm:", ""]
        for s in noisy:
            lines.append(f"- {s['session']} ({s['scenario']}): {s['flagged']} of {s['lines']} lines, as {s['categories']}")
    if before:
        bsrc = before["runs"]["chain"]["sources"]
        b_att = [s for s in bsrc if s["label"] != "benign"]
        b_caught = [s for s in b_att if s["first_flag"]]
        b_right = [s for s in b_caught if max(s["categories"], key=s["categories"].get) == s["label"]]
        b_noisy = [s for s in bsrc if s["label"] == "benign" and s["flagged"]]
        lines += ["", f"Before this change: {len(b_caught)} of {len(b_att)} attackers flagged ({len(b_right)} with the right "
                  f"category); {len(b_noisy)} normal sources raised an alarm."]

    lines += ["", "## What the shipped chain gets wrong", ""]
    mistakes = runs["chain"]["mistakes"]
    if not mistakes:
        lines.append("Nothing.")
    else:
        groups: dict[tuple[str, str, str], list[dict]] = {}
        for m in mistakes:
            groups.setdefault((m["session"], m["label"], m["predicted"]), []).append(m)
        lines += ["| Source | Label | Predicted | Lines | Example |", "|---|---|---|---|---|"]
        for (sess, y, p), ms in groups.items():
            raw = ms[0]["raw"].replace("|", "\\|")
            lines.append(f"| {sess} | {y} | {p} | {len(ms)} | `{raw[:100]}` |")
    lines += ["", "Every line of an attack session carries the attack label, so the first lines before a threshold "
              "(5 SSH guesses in 10 minutes, 10 not-found replies in 2 minutes, 5 failed web logins in 60 s) count as "
              "misses. The per-source table is the better guide to whether an attacker gets caught.", ""]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--events", type=Path, default=EVENTS)
    ap.add_argument("--core", type=Path, default=HERE.parents[1] / "core", help="core/ directory to score")
    ap.add_argument("--parser", type=Path, default=HERE.parents[1] / "lab" / "collector" / "parsers.py",
                    help="collector parsers.py for the collector-parsed column")
    ap.add_argument("--tag", default="", help="write results/<tag>.json only (for a before/after comparison)")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()

    res = evaluate(load_events(args.events), load_core(args.core), None if args.tag else load_parser(args.parser))
    if args.tag:
        RESULTS.mkdir(exist_ok=True)
        slim = {**res, "runs": {k: {kk: vv for kk, vv in v.items() if kk != "mistakes"} for k, v in res["runs"].items()}}
        (RESULTS / f"{args.tag}.json").write_text(json.dumps(slim, indent=1) + "\n", encoding="utf-8")
        print(f"wrote {RESULTS.name}/{args.tag}.json")
        return
    before_path = RESULTS / "before.json"
    before = json.loads(before_path.read_text(encoding="utf-8")) if before_path.exists() else None
    md = to_markdown(res, before)
    print(md)
    if not args.no_write:
        RESULTS.mkdir(exist_ok=True)
        (RESULTS / "realworld_eval.md").write_text(md, encoding="utf-8")
        slim = {**res, "runs": {k: {kk: vv for kk, vv in v.items() if kk != "mistakes"} for k, v in res["runs"].items()}}
        (RESULTS / "realworld_eval.json").write_text(json.dumps(slim, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
