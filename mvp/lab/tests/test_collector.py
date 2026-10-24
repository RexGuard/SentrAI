"""Collector: normalization to the contract Event schema, plus tailing."""
from __future__ import annotations

import json

from collector import collector
from target_app import paths

CONTRACT_LAYERS = {"web", "db", "os", "network", "cloud"}


def _assert_valid_event(ev: dict) -> None:
    for field in ("event_id", "timestamp", "host", "layer", "source",
                  "src_ip", "user", "raw", "asset_criticality"):
        assert field in ev, f"missing field {field}"
    assert ev["event_id"].startswith("evt-")
    assert ev["layer"] in CONTRACT_LAYERS
    assert ev["host"] == "web-01"
    assert ev["asset_criticality"] in (1.0, 1.5, 2.0)


def test_normalize_access_line():
    record = {
        "ts": "2026-09-29T14:00:03+08:00",
        "src_ip": "203.0.113.45", "user": "admin",
        "method": "POST", "path": "/login", "status": 401,
        "raw": "POST /login 401 user=admin",
    }
    ev = collector.normalize(paths.ACCESS_LOG, record)
    _assert_valid_event(ev)
    assert ev["layer"] == "web"
    assert ev["source"] == "flask_access"
    assert ev["src_ip"] == "203.0.113.45"
    assert ev["timestamp"] == "2026-09-29T14:00:03+08:00"
    assert ev["asset_criticality"] == 1.0


def test_normalize_db_line_is_pii_critical():
    record = {"ts": "2026-09-29T14:05:00+08:00", "src_ip": "198.51.100.23",
              "user": None, "query": "' OR '1'='1", "rows": 0, "pii": True,
              "raw": "SELECT rows=0 q=\"' OR '1'='1\""}
    ev = collector.normalize(paths.DB_LOG, record)
    _assert_valid_event(ev)
    assert ev["layer"] == "db"
    assert ev["source"] == "db_query"
    assert ev["asset_criticality"] == 1.5


def test_normalize_os_line():
    record = {"ts": "2026-09-29T14:06:00+08:00", "src_ip": "198.51.100.77",
              "raw": "web server spawned shell: whoami", "simulated": True}
    ev = collector.normalize(paths.OS_LOG, record)
    _assert_valid_event(ev)
    assert ev["layer"] == "os"
    assert ev["source"] == "os_process"


def test_heartbeat_event_is_valid_and_neutral():
    ev = collector.heartbeat_event()
    _assert_valid_event(ev)
    assert ev["source"] == "heartbeat"
    assert ev["raw"] == "collector heartbeat"


def test_pii_access_line_is_critical():
    record = {"ts": "2026-09-29T14:07:00+08:00", "src_ip": "203.0.113.77",
              "method": "GET", "path": "/export", "status": 200, "pii": True,
              "raw": "GET /export 200"}
    ev = collector.normalize(paths.ACCESS_LOG, record)
    assert ev["asset_criticality"] == 1.5


def test_tailer_reads_new_lines_and_handles_creation(tmp_path):
    log = tmp_path / "access.jsonl"
    tailer = collector.Tailer(log)
    # File does not exist yet.
    assert tailer.read_new_lines() == []
    log.write_text(json.dumps({"raw": "line1"}) + "\n", encoding="utf-8")
    assert tailer.read_new_lines() == [json.dumps({"raw": "line1"})]
    # Append more.
    with open(log, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"raw": "line2"}) + "\n")
    assert tailer.read_new_lines() == [json.dumps({"raw": "line2"})]
    # Truncation/rotation -> read from start again.
    log.write_text(json.dumps({"raw": "fresh"}) + "\n", encoding="utf-8")
    assert tailer.read_new_lines() == [json.dumps({"raw": "fresh"})]


def test_collector_buffers_when_core_down(monkeypatch, tmp_path):
    (tmp_path / "access.jsonl").write_text(
        json.dumps({"ts": "2026-09-29T14:00:03+08:00", "raw": "POST /login 401",
                    "src_ip": "203.0.113.45"}) + "\n", encoding="utf-8")
    col = collector.Collector("http://127.0.0.1:9", tmp_path)
    col.collect()
    assert len(col.pending) == 1

    def _boom(*a, **k):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(collector.requests.Session, "post", _boom)
    assert col.flush() is False
    # Event stays buffered for retry.
    assert len(col.pending) == 1


def test_collector_accepts_any_source(tmp_path):
    class Fake(collector.Source):
        def poll(self):
            return [collector.make_event("network", "fake_ids", "nmap -sS 10.0.0.0/24", src_ip="198.51.100.9")]

    col = collector.Collector("http://127.0.0.1:9", tmp_path, sources=[Fake()])
    col.collect()
    assert [e["source"] for e in col.pending] == ["fake_ids"]
    _assert_valid_event(col.pending[0])
