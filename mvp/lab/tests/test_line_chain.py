"""Every event the collector sends is sealed to the one before it (CONTRACT.md "Line chain")."""

from collector import collector
from collector.collector import GENESIS, LineChain, chain_hash

VECTOR = {"event_id": "evt-1", "timestamp": "2026-10-02T10:00:00+00:00", "host": "web-01", "layer": "os",
          "source": "scout:auth.log", "raw": "Accepted publickey for deploy"}
VECTOR_HASH = "0e7f86fbba0ce4fc37758a0cbc31e050d92deb885a06d3ea20685f076626f910"  # same as core/tests


def test_hash_matches_the_core():
    assert chain_hash(GENESIS, VECTOR) == VECTOR_HASH


def test_seal_links_each_event_and_resumes_from_a_checkpoint():
    c = LineChain()
    a = c.seal(collector.make_event("os", "x", "one"))
    b = c.seal(collector.make_event("os", "x", "two"))
    assert a["chain"]["seq"] == 1 and a["chain"]["prev"] == GENESIS
    assert b["chain"]["prev"] == a["chain"]["hash"] == chain_hash(GENESIS, a)
    resumed = LineChain(c.checkpoint())
    d = resumed.seal(collector.make_event("os", "x", "three"))
    assert d["chain"]["stream"] == a["chain"]["stream"] and d["chain"]["seq"] == 3
    assert d["chain"]["prev"] == b["chain"]["hash"]


def test_collector_seals_what_it_sends_and_saves_the_head_after_delivery(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTRAI_COLLECTOR_STATE", str(tmp_path / "state.json"))
    log = tmp_path / "app.log"
    log.write_text("one\n")
    src = collector.DiscoveredLogSource(log, "os")
    col = collector.Collector("http://127.0.0.1:9", tmp_path, sources=[src])
    col.store = collector.OffsetStore()
    col.collect()
    assert [e["chain"]["seq"] for e in col.pending] == [1]

    class Ok:
        def raise_for_status(self):
            pass

        def json(self):
            return {"risk_index": 0}

    monkeypatch.setattr(collector.requests.Session, "post", lambda self, url, json, timeout, headers=None: Ok())
    assert col.flush()
    assert collector.OffsetStore().get(collector.CHAIN_KEY)["seq"] == 1


def test_streaming_defaults():
    assert collector.POLL_S <= 0.1  # new lines leave within ~50 ms, not a 1 s batch


def test_an_agent_seals_events_under_the_name_it_joined_as(tmp_path, monkeypatch):
    # The panel stamps an agent's events with its joined name; sealing under any other name
    # (the demo logs' web-01, a syslog line's own host) would read as altered on the panel.
    monkeypatch.setenv("SENTRAI_COLLECTOR_STATE", str(tmp_path / "state.json"))
    log = tmp_path / "app.log"
    log.write_text("Oct 26 10:00:00 other-name sshd[1]: Accepted publickey for deploy\n")
    col = collector.Collector("http://127.0.0.1:9", tmp_path, host="lab-portal",
                              sources=[collector.DiscoveredLogSource(log, "os")])
    col.collect()
    (ev,) = col.pending
    assert ev["host"] == "lab-portal"
    assert ev["chain"]["hash"] == chain_hash(ev["chain"]["prev"], ev)
