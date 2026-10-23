"""Jev answers are cached per log template, so repeats of one line are asked about once."""

import time

from app.classifier import JevCache, JevClassifier, log_template
from app.jev_client import JevResult


class FakeJev:
    enabled = True

    def __init__(self):
        self.calls = 0

    def classify(self, event):
        self.calls += 1
        return JevResult("port_scan", 0.9, 0.8, {"port_scan": 0.9})


def _ev(raw, layer="web", source="nginx"):
    return {"raw": raw, "layer": layer, "source": source}


def test_template_strips_ips_times_and_ids():
    a = log_template(_ev('203.0.113.5 - - [19/Oct/2026:10:00:01 +0000] "GET /.git/config HTTP/1.1" 404'))
    b = log_template(_ev('198.51.100.7 - - [20/Oct/2026:23:59:59 +0000] "GET /.git/config HTTP/1.1" 404'))
    assert a == b and "<ip>" in a and "<ts>" in a
    c = log_template(_ev("Oct 19 10:00:01 web sshd[4242]: Failed password for root from 2001:db8::1 port 51515 ssh2"))
    d = log_template(_ev("Oct 20 11:11:11 web sshd[17]: Failed password for root from 203.0.113.9 port 2222 ssh2"))
    assert c == d
    assert log_template(_ev("GET /a 404")) != log_template(_ev("GET /b 404"))
    assert log_template(_ev("GET /a 404")) != log_template(_ev("GET /a 404", source="other"))


def test_repeat_lines_hit_the_cache():
    jev = FakeJev()
    step = JevClassifier(jev, JevCache(size=8))
    first = step.classify(_ev("GET /.env from 203.0.113.1 at 10:00:00"), 0)
    again = step.classify(_ev("GET /.env from 198.51.100.2 at 11:30:00"), 0)
    assert jev.calls == 1 and first.category == again.category == "port_scan"
    assert "cached" in again.reason and "cached" not in first.reason
    assert step.cache.stats() == {"size": 1, "max": 8, "hits": 1, "misses": 1}


def test_cache_hits_still_answer_after_the_time_budget():
    jev = FakeJev()
    step = JevClassifier(jev, JevCache())
    step.classify(_ev("GET /wp-login.php"), 0)
    step.deadline = 0  # budget spent: no new calls...
    assert step.classify(_ev("GET /wp-login.php"), 0) is not None  # ...but a known template is free
    assert step.classify(_ev("GET /phpmyadmin"), 0) is None and jev.calls == 1


def test_lru_eviction_ttl_and_off():
    cache = JevCache(size=2)
    r = JevResult("benign", 0.9, 0.1, {})
    cache.put("a", r)
    cache.put("b", r)
    cache.get("a")
    cache.put("c", r)
    assert cache.get("b") is None and cache.get("a") is r and len(cache) == 2  # b was least recently used
    expired = JevCache(ttl_s=0.000001)
    expired.put("k", r)
    time.sleep(0.05)  # longer than Windows' ~16 ms monotonic clock tick, so the clock has moved on
    assert expired.get("k") is None
    off = JevCache(size=0)
    off.put("k", r)
    assert off.get("k") is None


def test_disabled_jev_skips_the_cache():
    jev = FakeJev()
    jev.enabled = False
    step = JevClassifier(jev, JevCache())
    assert step.classify(_ev("GET /x"), 0) is None and jev.calls == 0 and step.cache.misses == 0
