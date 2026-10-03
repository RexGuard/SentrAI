"""Signed record fingerprints sent off the box prove a rebuilt audit chain is fake."""

import json
import sqlite3

from app import anchor
from app.audit import AuditLog, canonical, compute_hash, GENESIS_HASH


def _chain(tmp_path, n=5):
    log = AuditLog(tmp_path / "audit.db")
    for i in range(n):
        log.append("event", {"i": i, "who": "Warden"}, f"2026-10-02T10:00:{i:02d}Z")
    return log


def _rebuild(log, change_seq, data):
    """What an attacker with the database file does: drop the guards, edit, recompute every hash."""
    db = sqlite3.connect(str(log.path))
    db.execute("DROP TRIGGER audit_no_update")
    rows = db.execute("SELECT seq, ts, type, data FROM audit ORDER BY seq").fetchall()
    prev = GENESIS_HASH
    for seq, ts, rtype, d in rows:
        d = json.loads(d)
        if seq == change_seq:
            d = data
        h = compute_hash(prev, seq, ts, rtype, d)
        db.execute("UPDATE audit SET data=?, prev_hash=?, hash=? WHERE seq=?", (canonical(d), prev, h, seq))
        prev = h
    db.commit()
    db.close()


def test_fingerprint_verifies_while_the_chain_is_untouched(tmp_path):
    log = _chain(tmp_path)
    key = anchor.load_key(log.path)
    fp = anchor.fingerprint(log, key)
    assert fp.seq == 5 and fp.line().startswith("SENTRAI-FP v1 seq=5 head=")
    log.append("event", {"i": 99}, "2026-10-02T10:01:00Z")  # later records do not matter
    ok, why = anchor.verify(log, f"From Telegram: {fp.line()} (forwarded)", key)
    assert ok and "records 1 to 5" in why and "signature matches" in why


def test_a_rebuilt_chain_is_caught_even_though_it_verifies_on_its_own(tmp_path):
    log = _chain(tmp_path)
    key = anchor.load_key(log.path)
    line = anchor.fingerprint(log, key).line()
    _rebuild(log, 2, {"i": 2, "who": "nobody saw anything"})
    assert log.verify() == (True, None)  # the chain alone cannot tell
    ok, why = anchor.verify(log, line, key)
    assert not ok and "record 5 has a different hash" in why


def test_short_fingerprint_from_an_alert_works_too(tmp_path):
    log = _chain(tmp_path)
    fp = anchor.fingerprint(log, None)
    short = f"SENTRAI-FP v1 seq={fp.seq} head={fp.head[:16]} at={fp.at}"
    assert anchor.verify(log, short)[0]
    _rebuild(log, 1, {"x": 1})
    assert not anchor.verify(log, short)[0]


def test_deleted_records_and_forged_lines(tmp_path):
    log = _chain(tmp_path)
    key = anchor.load_key(log.path)
    fp = anchor.fingerprint(log, key)
    forged = anchor.Fingerprint(fp.seq, fp.head, "2026-10-03T00:00:00Z", fp.sig).line()
    ok, why = anchor.verify(log, forged, key)
    assert not ok and "signature does not match" in why
    db = sqlite3.connect(str(log.path))
    db.execute("DROP TRIGGER audit_no_delete")
    db.execute("DELETE FROM audit WHERE seq >= 4")
    db.commit()
    db.close()
    ok, why = anchor.verify(log, fp.line(), key)
    assert not ok and "record 5 is missing" in why
    assert anchor.verify(log, "hello")[1].startswith("not a SentrAI fingerprint")


def test_key_is_made_once_and_private(tmp_path, monkeypatch):
    monkeypatch.delenv("CACTAI_ANCHOR_KEY", raising=False)
    db = tmp_path / "x" / "cactai.db"
    assert anchor.load_key(db, create=False) is None
    k1 = anchor.load_key(db)
    assert anchor.load_key(db) == k1 and len(k1) == 64
    import os
    if os.name == "posix":
        assert oct(anchor.key_path(db).stat().st_mode & 0o777) == "0o600"
    monkeypatch.setenv("CACTAI_ANCHOR_KEY", "kept-elsewhere")
    assert anchor.load_key(db) == b"kept-elsewhere"


def test_cli(tmp_path, capsys):
    log = _chain(tmp_path)
    assert anchor.main(["--db", str(log.path), "show"]) == 0
    line = capsys.readouterr().out.strip()
    assert anchor.main(["--db", str(log.path), "verify", line]) == 0
    assert capsys.readouterr().out.startswith("OK: ")
    log.close()
    _rebuild(AuditLog(log.path), 3, {"gone": True})
    assert anchor.main(["--db", str(log.path), "verify", line]) == 1
    assert capsys.readouterr().out.startswith("TAMPERED: ")


def test_core_sends_fingerprints_and_puts_one_in_alerts(client):
    core = client.core
    n = core._send_fingerprint(core.clock.now(), force=True)
    assert n["kind"] == "audit_anchor" and n["incident"] is None
    line = n["text"].splitlines()[-1]
    assert line.startswith("SENTRAI-FP v1") and " sig=" in line
    assert core._send_fingerprint(core.clock.now()) is None  # not due yet
    r = client.get("/audit/verify", params={"fingerprint": line}).json()
    assert r["ok"] is True
    assert client.get("/audit/fingerprint").json()["line"].startswith("SENTRAI-FP v1")
    # An incident alert carries the short fingerprint.
    for i in range(6):
        client.post("/events", json={"event_id": f"e{i}", "timestamp": "2026-10-02T10:00:00+08:00", "host": "web-01",
                                     "layer": "web", "source": "flask_auth", "src_ip": "203.0.113.45", "user": "admin",
                                     "raw": "POST /login 401 user=admin", "asset_criticality": 1.5})
    opened = [x for x in core.notifications if x["kind"] == "incident_opened"]
    assert opened and "Record fingerprint: #" in opened[0]["text"]
