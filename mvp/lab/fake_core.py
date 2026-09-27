"""Tiny fake CactAI core for lab development and demos.

This is NOT the real core (the core agent builds that). It implements just
enough of the contract for the lab to run end-to-end on its own:
  GET  /health           -> {"ok": true}
  POST /events           -> counts events, returns a toy risk_index
  GET  /risk             -> current toy risk
  GET  /blocklist        -> {"ips": [...], "users": [...]}
  POST /blocklist        -> set the blocklist (lab-only helper for demos/tests)
  POST /demo/reset       -> clear state

The toy risk_index just grows with non-benign-looking events so you can see
the target app get blocked when you add an IP to the blocklist.

    python fake_core.py            (serves on 127.0.0.1:8000)
"""
from __future__ import annotations

import math
import os

from flask import Flask, jsonify, request

app = Flask(__name__)

STATE = {"raw": 0.0, "events": 0, "ips": [], "users": []}


def _risk_index() -> int:
    return round(100 * (1 - math.exp(-STATE["raw"] / 60)))


@app.get("/health")
def health():
    return jsonify(ok=True)


@app.post("/events")
def events():
    payload = request.get_json(force=True, silent=True)
    batch = payload if isinstance(payload, list) else [payload]
    for ev in batch:
        if not isinstance(ev, dict):
            continue
        STATE["events"] += 1
        raw = (ev.get("raw") or "").lower()
        # crude toy scoring, just for the lab
        if "fail" in raw:
            STATE["raw"] += 3 * float(ev.get("asset_criticality", 1.0))
        elif "union select" in raw or "drop table" in raw or "'1'='1" in raw:
            STATE["raw"] += 40 * float(ev.get("asset_criticality", 1.0))
        elif "spawned shell" in raw:
            STATE["raw"] += 60
    return jsonify(accepted=len(batch), risk_index=_risk_index())


@app.get("/risk")
def risk():
    idx = _risk_index()
    band = ("green" if idx < 30 else "amber" if idx < 60
            else "red" if idx < 80 else "critical")
    return jsonify(risk_index=idx, band=band, raw_score=round(STATE["raw"], 1),
                   threshold=80, open_incidents=[], history=[])


@app.get("/blocklist")
def get_blocklist():
    return jsonify(ips=STATE["ips"], users=STATE["users"])


@app.post("/blocklist")
def set_blocklist():
    """Lab-only helper: set the blocklist to demonstrate containment."""
    payload = request.get_json(force=True, silent=True) or {}
    STATE["ips"] = list(payload.get("ips", []))
    STATE["users"] = list(payload.get("users", []))
    return jsonify(ips=STATE["ips"], users=STATE["users"])


@app.post("/demo/reset")
def reset():
    STATE.update({"raw": 0.0, "events": 0, "ips": [], "users": []})
    return jsonify(ok=True)


if __name__ == "__main__":
    port = int(os.environ.get("CACTAI_FAKE_CORE_PORT", "8000"))
    print(f"[fake-core] lab stand-in on http://127.0.0.1:{port} "
          f"(NOT the real core)")
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
