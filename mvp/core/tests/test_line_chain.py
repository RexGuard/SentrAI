"""The core checks the seal on every event a collector sends (CONTRACT.md "Line chain")."""

import copy

from app.integrity import GENESIS, IntegrityGuard, chain_hash

# The same vector is checked in lab/tests/test_line_chain.py: collector and core must agree.
VECTOR = {"event_id": "evt-1", "timestamp": "2026-10-02T10:00:00+00:00", "host": "web-01", "layer": "os",
          "source": "scout:auth.log", "raw": "Accepted publickey for deploy"}
VECTOR_HASH = "0e7f86fbba0ce4fc37758a0cbc31e050d92deb885a06d3ea20685f076626f910"


def test_hash_matches_the_collector():
    assert chain_hash(GENESIS, VECTOR) == VECTOR_HASH


def _stream(n, start=1, prev=GENESIS, stream="web-01-abcd1234"):
    out = []
    for seq in range(start, start + n):
        ev = {"event_id": f"evt-{seq}", "timestamp": "2026-10-02T10:00:00+00:00", "host": "web-01", "layer": "os",
              "source": "scout:auth.log", "raw": f"line {seq}", "src_ip": None}
        h = chain_hash(prev, ev)
        ev["chain"] = {"stream": stream, "seq": seq, "prev": prev, "hash": h}
        prev = h
        out.append(ev)
    return out


def _guard(tmp_path):
    from app.audit import AuditLog
    return IntegrityGuard(AuditLog(tmp_path / "a.db"))


def test_an_unbroken_stream_passes(tmp_path):
    g = _guard(tmp_path)
    assert [g.chained(e) for e in _stream(20)] == [None] * 20
    assert g.chained({"raw": "no seal (lab replay, old collector)"}) is None


def test_a_missing_batch_is_a_gap(tmp_path):
    g = _guard(tmp_path)
    evs = _stream(10)
    for e in evs[:4]:
        assert g.chained(e) is None
    found = g.chained(evs[7])  # 5, 6 and 7 never arrived
    assert found and found["source"] == "audit_integrity"
    assert "jumped from record #4 to #8: 3 event(s) never arrived" in found["raw"]


def test_a_line_changed_after_it_was_read(tmp_path):
    g = _guard(tmp_path)
    evs = _stream(3)
    g.chained(evs[0])
    edited = copy.deepcopy(evs[1])
    edited["raw"] = "line 2 (attacker's IP removed)"
    found = g.chained(edited)
    assert found and "does not match its seal" in found["raw"]


def test_a_resealed_insert_does_not_follow(tmp_path):
    g = _guard(tmp_path)
    evs = _stream(3)
    g.chained(evs[0])
    g.chained(evs[1])
    fake = _stream(1, start=3, prev="f" * 64)[0]  # sealed correctly, but on a made-up predecessor
    found = g.chained(fake)
    assert found and "does not follow the one before" in found["raw"]


def test_collector_replay_after_a_crash_and_restarts_fit(tmp_path):
    g = _guard(tmp_path)
    evs = _stream(6)
    for e in evs:
        g.chained(e)
    # Crashed before saving its place at #3: re-reads and re-seals from there.
    again = _stream(3, start=4, prev=evs[2]["chain"]["hash"])
    assert [g.chained(e) for e in again] == [None] * 3
    # Collector state wiped (fresh install / demo machine): starts again at #1.
    assert g.chained(_stream(1)[0]) is None


def test_core_opens_an_incident_for_a_gap(client):
    evs = _stream(5, stream="web-01-feed0001")
    client.post("/events", json=evs[:2])
    client.post("/events", json=evs[4:])
    inc = [i for i in client.get("/incidents").json() if i["category"] == "log_tampering"]
    assert inc and "never arrived" in inc[0]["explanation"]
