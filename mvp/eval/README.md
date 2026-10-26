# Classifier evaluation

How well SentrAI's classifier (part 2 of 3) labels events, per category.

```
python eval/evaluate.py          # scores eval/events.jsonl, writes eval/results/
python -m pytest eval            # checks for the evaluation itself
```

Set `TYPESAFE_API_KEY` (and install `typesafe-sdk`) to add the Jev and "Chain with Jev" columns.
Without a key those columns say "not run".

## The event set

`events.jsonl` holds 196 labelled events in the contract Event shape. It is a fixed set: the demo
portal and attack scripts that built it were removed, so it can no longer be rebuilt, only scored.

- **lab (116)**: the old demo portal driven with its attack payloads, extra SQLi
  and XSS payloads, and normal staff traffic (including searches such as `O'Brien` and
  `select course`). The log lines go through the real collector.
- **replay (17)**: the old scripted demo incident, unchanged.
- **handcrafted (63)**: firewall, cloud, Windows and sshd lines the lab cannot produce, threat-scan findings, and benign
  look-alikes (a closed security-group rule, a nightly `pg_dump`, a small export).

A line gets an attack label only if the line itself shows the attack. Every failed login in a
brute-force burst is labelled `brute_force`, so the first four of each burst count as misses for
a threshold rule. Scores are per event; two extra rows show what an operator sees: "attack lines
in an incident" also counts the earlier lines a later hit attaches to its incident, and "attackers
caught" counts each attacker (label + source address) once.

## Results

See [results/classifier_eval.md](results/classifier_eval.md) (also `.json` and `.csv`).
