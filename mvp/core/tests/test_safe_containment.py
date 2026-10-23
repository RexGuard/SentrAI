"""Safe containment: protected networks, infrastructure and accounts, and the per-incident bar."""

from app import protect
from app.agents import Needle, Proposal
from app.firewall import unsafe_reason
from app.risk import inaction_penalty
from app.saguaro import raw_summary

from .conftest import brute_force, ev


def test_matches_addresses_networks_and_mapped_ipv6():
    entries = {"127.0.0.1", "10.0.0.0/8", "fc00::/7", "localhost"}
    assert protect.matches("10.20.30.40", entries)
    assert protect.matches("::ffff:10.1.1.1", entries)
    assert protect.matches("fd12::1", entries)
    assert protect.matches("localhost", entries)
    assert not protect.matches("203.0.113.45", entries)
    assert not protect.matches("", entries) and not protect.matches(None, entries)
    assert not protect.matches("not-an-ip", {"bad/entry"})


def test_users_compare_without_case():
    users = protect.split(protect.DEFAULT_USERS)
    assert protect.user_matches("Administrator", users) and protect.user_matches("ROOT", users)
    assert protect.user_matches("www-data", users)
    assert not protect.user_matches("alice", users)


def test_detect_infra_reads_dns_and_gateway(tmp_path):
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("# comment\nnameserver 192.0.2.53\nnameserver 127.0.0.53\nnameserver junk\n")
    route = tmp_path / "route"
    # Default route via 192.0.2.1 (little-endian hex 0102000C0 -> 0100 02C0).
    route.write_text("Iface\tDestination\tGateway\tFlags\neth0\t00000000\t010200C0\t0003\neth0\t000200C0\t00000000\t0001\n")
    assert protect.detect_infra(resolv, route) == {"192.0.2.53", "192.0.2.1"}
    assert protect.detect_infra(tmp_path / "missing", tmp_path / "missing") == set()


def test_firewall_honours_protected_networks():
    assert unsafe_reason("10.9.8.7", {"10.0.0.0/8"}) == "protected address"
    assert unsafe_reason("203.0.113.9", {"10.0.0.0/8"}) is None


def _incident(**kw):
    inc = {"id": "RSK-1", "ai_confidence": 1.0, "needs_review": False, "severity": "high", "points": 45.0,
           "classified_by": "rules"}
    inc.update(kw)
    return inc


def _needle():
    return Needle(0.6, {"block_ip", "lock_user", "rate_limit"}, {"127.0.0.1"}, protect.split(protect.DEFAULT_USERS),
                  protect.nets(protect.PRIVATE_NETS), "high", 20.0)


def test_needle_gates_on_the_incident_itself():
    needle = _needle()
    props = [Proposal("block_ip", "203.0.113.45", "test")]
    assert needle.review(_incident(), props, 90, 80).approved
    low = needle.review(_incident(severity="medium", points=30.0), props, 95, 80)
    assert not low.approved and "severity medium is below high" in low.reasoning
    weak = needle.review(_incident(points=12.0), props, 95, 80)
    assert not weak.approved and "points 12 are below 20" in weak.reasoning


def test_private_addresses_wait_for_a_person():
    needle = _needle()
    props = [Proposal("block_ip", "192.168.1.50", "test"), Proposal("lock_user", "Admin", "test"), Proposal("rate_limit", "/login", "test")]
    review = needle.review(_incident(), props, 90, 80)
    assert [p.type for p in review.approved_proposals] == ["rate_limit"]
    assert {d["why"] for d in review.denied} == {"private network: a person decides", "protected account"}
    ok, _ = needle.screen(props)  # an operator's approval may block a private address
    assert [p.type for p in ok] == ["block_ip", "rate_limit"]


def test_medium_incident_is_not_auto_contained_above_threshold(client):
    client.post("/events", json=ev(30, "GET /search?q=<script>alert(1)</script> 200", ip="198.51.100.7",
                                   user=None, source="flask_access"))
    brute_force(client)
    client.post("/events", json=ev(10, "GET /search?q=' OR 1=1 -- 200", source="flask_access"))
    incs = {i["category"]: i for i in client.get("/incidents").json()}
    assert incs["brute_force"]["status"] == "contained" and incs["sql_injection"]["status"] == "contained"
    xss = incs["xss"]
    assert xss["status"] == "open" and xss["actions"] == []
    assert any(t["kind"] == "needle_denied" and "severity medium" in t["text"] for t in xss["timeline"])
    assert "198.51.100.7" not in client.get("/blocklist").json()["ips"]


def test_penalty_is_weighted_by_severity():
    assert inaction_penalty(3, severity="high") == 15
    assert inaction_penalty(3, severity="medium") == 7.5
    assert inaction_penalty(3, severity="critical") == 22.5
    assert inaction_penalty(30, severity="critical") == 45  # cap scales too
    assert inaction_penalty(3, severity="info") == 0


def test_audit_keeps_only_a_summary_of_raw_lines():
    line = "POST /login password=hunter2 " + "x" * 400 + "\x1b[31m"
    s = raw_summary(line)
    assert len(s["raw"]) == 203 and s["raw"].endswith("...") and s["raw_len"] == len(line)
    assert len(s["raw_sha256"]) == 64
    assert raw_summary("a\x00b")["raw"] == "a b"
