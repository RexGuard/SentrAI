# Classifier evaluation

How well CactAI's classifier (part 2 of 3) labels events, per category.

```
python eval/evaluate.py          # scores eval/events.jsonl, writes eval/results/
python -m pytest eval            # checks for the evaluation itself
python eval/build_dataset.py     # rebuilds events.jsonl (needs Flask from lab/requirements.txt)
```

Set `TYPESAFE_API_KEY` (and install `typesafe-sdk`) to add the Jev and "Chain with Jev" columns.
Without a key those columns say "not run".

## The event set

`events.jsonl` holds 178 labelled events in the contract Event shape:

- **lab (116)**: the real lab portal driven with the payloads from `lab/attacks/*.py`, extra SQLi
  and XSS payloads, and normal staff traffic (including searches such as `O'Brien` and
  `select course`). The log lines go through the real collector.
- **replay (17)**: `lab/replay/simulate.py` unchanged.
- **handcrafted (45)**: firewall, cloud, Windows and sshd lines the lab cannot produce, and benign
  look-alikes (a closed security-group rule, a nightly `pg_dump`, a small export).

A line gets an attack label only if the line itself shows the attack. Every failed login in a
brute-force burst is labelled `brute_force`, so the first four of each burst count as misses for
a threshold rule. Scores are per event, not per incident.

## Results

See [results/classifier_eval.md](results/classifier_eval.md) (also `.json` and `.csv`).
