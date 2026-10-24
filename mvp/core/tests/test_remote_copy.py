"""Off-box copy: the core sends every audit record and sealed log line to a witness that only adds."""

import json
import sqlite3
import sys
import threading
from pathlib import Path

import httpx
import pytest

from app import remote_copy
from app.audit import AuditLog, GENESIS_HASH, canonical, compute_hash
from app.config import Settings
from app.integrity import GENESIS, chain_hash
from app.saguaro import Saguaro

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "witness"))
import witness  # noqa: E402

APPEND, READ = "append-token-for-tests", "read-token-for-tests"


@pytest.fixture
def wit(tmp_path):
    srv = witness.make_server(tmp_path / "witness", APPEND, READ, "127.0.0.1", 0)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    srv.url = f"http://127.0.0.1:{srv.server_address[1]}"
    yield srv
    srv.shutdown()
    srv.server_close()


def _audit(tmp_path, n=5):
    log = AuditLog(tmp_path / "core" / "cactai.db")
    for i in range(n):
        log.append("event_classified", {"i": i, "raw": f"Failed password for root from 203.0.113.{i}"},
                   f"2026-10-02T10:00:{i:02d}Z")
    return log


def _rebuild(log, change_seq, data):
    """What root does with the database file: drop the guards, edit, recompute every hash."""
    db = sqlite3.connect(str(log.path))
    db.execute("DROP TRIGGER audit_no_update")
    prev = GENESIS_HASH
    for seq, ts, rtype, d in db.execute("SELECT seq, ts, type, data FROM audit ORDER BY seq").fetchall():
        d = data if seq == change_seq else json.loads(d)
        h = compute_hash(prev, seq, ts, rtype, d)
        db.execute("UPDATE audit SET data=?, prev_hash=?, hash=? WHERE seq=?", (canonical(d), prev, h, seq))
        prev = h
    db.commit()
    db.close()


def _lines(n, start=1, prev=GENESIS, stream="web-01-abcd1234"):
    out = []
    for seq in range(start, start + n):
        ev = {"event_id": f"evt-{stream}-{seq}", "timestamp": "2026-10-02T10:00:00+00:00", "host": "web-01",
              "layer": "os", "source": "scout:auth.log", "raw": f"Accepted publickey for deploy #{seq}"}
        h = chain_hash(prev, ev)
        ev["chain"] = {"stream": stream, "seq": seq, "prev": prev, "hash": h}
        prev = h
        out.append(ev)
    return out


def test_audit_records_reach_the_witness(tmp_path, wit):
    log = _audit(tmp_path)
    rc = remote_copy.RemoteCopy(log, wit.url, APPEND, host="web-01")
    assert rc.flush() and rc.status["audit_seq"] == 5
    stream = remote_copy.audit_stream(log, "web-01")
    same, lines = remote_copy.compare(log, wit.url, READ, host="web-01")
    assert same and lines == ["records 1 to 5 match the witness's copy"]
    log.append("event_classified", {"i": 5}, "2026-10-02T10:00:05Z")
    assert rc.flush() and rc.status["audit_seq"] == 6
    # A new sender (core restarted) asks the witness where it got to, and sends nothing twice.
    rc2 = remote_copy.RemoteCopy(log, wit.url, APPEND, host="web-01")
    assert rc2.flush() and rc2._sent[stream] == 6


def test_a_rebuilt_chain_is_refused_and_raised(tmp_path, wit):
    log = _audit(tmp_path)
    rc = remote_copy.RemoteCopy(log, wit.url, APPEND, host="web-01")
    rc.flush()
    _rebuild(log, 2, {"i": 2, "raw": "nothing happened"})
    assert log.verify() == (True, None)  # the chain on its own cannot tell
    # The next record continues the rebuilt chain, not the one the witness holds.
    log.append("event_classified", {"i": 9}, "2026-10-02T10:01:00Z")
    rc.flush()
    problems, _ = rc.take()
    assert len(problems) == 1 and "remote copy refused: record #6 does not follow #5" in problems[0]["raw"]
    rc.flush()
    assert rc.take()[0] == []  # raised once; nothing more goes to that stream
    same, lines = remote_copy.compare(log, wit.url, READ, host="web-01")
    assert not same and lines[0].startswith("record #2 (event_classified") and "content changed here" in lines[0]
    conflicts = (tmp_path / "witness" / "conflicts.jsonl").read_text().splitlines()
    assert len(conflicts) == 1


def test_a_deleted_database_leaves_the_copy(tmp_path, wit):
    log = _audit(tmp_path)
    remote_copy.RemoteCopy(log, wit.url, APPEND, host="web-01").flush()
    stream = remote_copy.audit_stream(log, "web-01")
    log.close()
    log.path.unlink()
    fresh = AuditLog(log.path)
    assert not remote_copy.compare(fresh, wit.url, READ, host="web-01")[0]
    same, lines = remote_copy.compare(fresh, wit.url, READ, stream=stream)
    assert not same and len(lines) == 5 and lines[0].startswith("record #1 (event_classified, 2026-10-02T10:00:00Z)")
    assert "Failed password for root from 203.0.113.0" in json.dumps(httpx.get(
        f"{wit.url}/records", params={"stream": stream}, headers={"Authorization": f"Bearer {READ}"}).json())


def test_log_lines_go_too_and_a_retry_is_not_a_copy(tmp_path, wit):
    log = _audit(tmp_path, 0)
    rc = remote_copy.RemoteCopy(log, wit.url, APPEND)
    batch = _lines(3)
    for e in batch:
        rc.add_line(e)
    rc.add_line({"event_id": "x", "raw": "no seal"})  # unsealed (demo generators): not sent
    assert rc.flush() and rc.status["lines_sent"] == 3
    for e in batch[1:] + _lines(2, 4, batch[-1]["chain"]["hash"]):
        rc.add_line(e)
    assert rc.flush()
    rows = (tmp_path / "witness" / "lines-web-01-abcd1234.jsonl").read_text().splitlines()
    assert [json.loads(r)["seq"] for r in rows] == [1, 2, 3, 4, 5]
    # A line edited after sealing is refused; the lines after it still get there.
    more = _lines(3, 6, json.loads(rows[-1])["hash"])
    more[0]["raw"] = "edited"
    for e in more:
        rc.add_line(e)
    assert rc.flush()
    rows = (tmp_path / "witness" / "lines-web-01-abcd1234.jsonl").read_text().splitlines()
    assert [json.loads(r).get("seq") for r in rows][-3:] == [None, 7, 8]  # a note, then 7 and 8


def test_witness_only_adds(tmp_path, wit):
    def call(method, path, token=None, **kw):
        h = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx.request(method, wit.url + path, headers=h, **kw)

    good = _lines(2, stream="s1")
    assert call("POST", "/append", APPEND, json={"stream": "lines-s1", "items": good}).json()["seq"] == 2
    assert call("POST", "/append", READ, json={"stream": "lines-s1", "items": good}).status_code == 401
    assert call("GET", "/records?stream=lines-s1", APPEND).status_code == 403  # the core can't read it back
    assert call("GET", "/records?stream=lines-s1").status_code == 401
    assert len(call("GET", "/records?stream=lines-s1", READ).json()) == 2
    for m in ("PUT", "DELETE", "PATCH"):
        assert call(m, "/records?stream=lines-s1", APPEND).status_code == 405
    forged = dict(_lines(1, 3, good[-1]["chain"]["hash"], stream="s1")[0], raw="edited after sealing")
    r = call("POST", "/append", APPEND, json={"stream": "lines-s1", "items": [forged]})
    assert r.status_code == 409 and "does not match its own hash" in r.json()["error"]
    assert call("POST", "/append", APPEND, json={"stream": "../etc", "items": []}).status_code == 400
    # Restarted, it knows where every stream got to.
    again = witness.Store(tmp_path / "witness")
    assert again.head("lines-s1")["seq"] == 2


def test_unreachable_witness_keeps_lines_until_it_is_back(tmp_path, wit, monkeypatch):
    log = _audit(tmp_path, 1)
    rc = remote_copy.RemoteCopy(log, "http://127.0.0.1:9", APPEND, timeout_s=0.5)  # nothing listens there
    for e in _lines(4):
        rc.add_line(e)
    monkeypatch.setattr(remote_copy, "UNREACHABLE_NOTE_S", 0.0)
    assert not rc.flush() and rc.status["ok"] is False and len(rc._lines) == 4
    assert rc.take()[1][0][0] == "remote_copy_unreachable"
    rc.url = wit.url
    rc.http.timeout = httpx.Timeout(5.0)  # 0.5 s was for the dead port; a slow Windows runner needs longer to append
    assert rc.flush() and rc.status["lines_sent"] == 4 and rc.status["audit_seq"] == 1
    assert rc.take()[1][0][0] == "remote_copy_restored"


def test_core_sends_as_it_goes_and_opens_an_incident_on_refusal(tmp_path, wit):
    s = Settings(db_path=tmp_path / "core" / "cactai.db", background=False, remote_copy_url=wit.url,
                 remote_copy_token=APPEND)
    core = Saguaro(s)
    try:
        core.remote.host = "web-01"
        core.ingest(_lines(3))
        assert core.remote.flush()
        assert core.remote.status["lines_sent"] == 3 and core.remote.status["audit_seq"] == core.audit.head()[0]
        core.remote._wake.clear()
        core.scribe.record(core.name, "test", {})
        assert core.remote._wake.is_set()  # every append wakes the sender at once
        assert core.remote.flush() and core.remote.status["audit_seq"] == 2
        # Root rebuilds record 2; the core's next send is refused and the tick opens an incident.
        _rebuild(core.audit, 2, {"edited": True})
        core.scribe.record(core.name, "test", {})
        core.remote.flush()
        core.tick()
        assert any(i["category"] == "log_tampering" and "remote copy refused" in i["explanation"]
                   for i in core.incidents.values())
    finally:
        core.remote.stop()
        core.audit.close()
