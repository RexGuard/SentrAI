"""verify_recent() and snapshot(): the quick versions of verify() and records() that the busy pages use."""
import sqlite3

from app.audit import AuditLog


def _log(tmp_path, n=3):
    log = AuditLog(tmp_path / "audit.db")
    for i in range(n):
        log.append("note", {"i": i}, f"2026-10-31T10:00:0{i}Z")
    return log


def _edit_behind_its_back(log, seq):
    """What an attacker with the file would do: drop the triggers and change one record."""
    conn = sqlite3.connect(str(log.path))
    conn.execute("DROP TRIGGER audit_no_update")
    conn.execute("UPDATE audit SET data = '{\"i\":99}' WHERE seq = ?", (seq,))
    conn.commit()
    conn.close()


def test_snapshot_grows_instead_of_rereading(tmp_path):
    log = _log(tmp_path)
    assert [r["seq"] for r in log.snapshot()] == [1, 2, 3]
    log.append("note", {"i": 3}, "2026-10-31T10:00:09Z")
    assert [r["seq"] for r in log.snapshot()] == [1, 2, 3, 4]
    assert log.snapshot() == log.records()


def test_new_records_are_checked_between_full_checks(tmp_path):
    log = _log(tmp_path)
    assert log.verify_recent(max_age=3600) == (True, None)
    log.append("note", {"i": 3}, "2026-10-31T10:00:09Z")
    assert log.verify_recent(max_age=3600) == (True, None)
    assert log._seen["seq"] == 4  # only the new record was hashed


def test_an_edit_to_an_old_record_shows_at_the_next_full_check(tmp_path):
    log = _log(tmp_path)
    assert log.verify_recent(max_age=3600) == (True, None)
    _edit_behind_its_back(log, 2)
    assert log.verify_recent(max_age=3600) == (True, None)  # within the minute: the last full check still stands
    assert log.verify_recent(max_age=0) == (False, 2)  # the next full check finds it
    assert log.verify_recent(max_age=3600) == (False, 2)  # and a broken chain is never reused as fine


def test_a_forged_new_record_is_caught_at_once(tmp_path):
    log = _log(tmp_path)
    assert log.verify_recent(max_age=3600) == (True, None)
    conn = sqlite3.connect(str(log.path))
    conn.execute("INSERT INTO audit (seq, ts, type, data, prev_hash, hash) VALUES (4,'t','note','{}','x','y')")
    conn.commit()
    conn.close()
    assert log.verify_recent(max_age=3600) == (False, 4)


def test_a_reset_forgets_what_was_cached(tmp_path):
    log = _log(tmp_path)
    log.snapshot()
    log.verify_recent()
    log.archive_and_reset()
    assert log.snapshot() == [] and log.verify_recent() == (True, None)


def test_the_audit_page_feed_asks_for_the_quick_check(client):
    client.post("/events", json={"host": "h", "layer": "web", "source": "nginx", "src_ip": "203.0.113.9",
                                 "raw": "GET /x?id=1' OR '1'='1 HTTP/1.1 200"})
    strict = client.get("/audit?limit=5").json()
    quick = client.get("/audit?limit=5&quick=1").json()
    assert quick["chain_valid"] is True and quick["records"] == strict["records"] and quick["count"] == strict["count"]
    assert quick["head_hash"] == strict["head_hash"]
