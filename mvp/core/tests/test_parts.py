"""The classifier and responder parts can be swapped or extended on their own."""

from app.classifier import Classification, Classifier, ClassifierChain, FallbackClassifier
from app.responders import BlocklistResponder, Responder, Responders

from .conftest import brute_force


class Always(Classifier):
    name = "always"

    def classify(self, event, now):
        return Classification("port_scan", 0.9, 0.9, "test")


class Never(Classifier):
    name = "never"

    def classify(self, event, now):
        return None


def test_chain_first_answer_wins_and_is_stamped():
    chain = ClassifierChain(Never(), Always(), FallbackClassifier())
    assert chain.classify({"raw": "x"}, 0).classified_by == "always"
    assert ClassifierChain(Never(), FallbackClassifier()).classify({"raw": "x"}, 0).classified_by == "fallback"
    assert ClassifierChain(Never()).classify({"raw": "x"}, 0).category == "benign"


def test_blocklist_is_counted_per_action():
    r = BlocklistResponder()
    a1 = {"type": "block_ip", "target": "203.0.113.9"}
    a2 = dict(a1)
    assert r.apply(a1) and r.apply(a2)
    r.revert(a1)
    assert r.blocklist()["ips"] == ["203.0.113.9"]  # still blocked by the second incident
    r.revert(a2)
    assert r.blocklist()["ips"] == []


def test_custom_responder_extends_the_allowlist():
    class Firewall(Responder):
        name = "firewall"
        actions = ("fw_drop",)

        def apply(self, action):
            return True

        def revert(self, action):
            pass

    rs = Responders(BlocklistResponder(), Firewall())
    assert rs.allowlist == {"block_ip", "lock_user", "fw_drop"}
    assert rs.for_type("fw_drop").name == "firewall"


def test_expired_block_made_permanent_is_enforced_again(client):
    brute_force(client)
    client.post("/incidents/RSK-2026-081/decision", json={"operator": "erick", "decision": "approve"})
    client.post("/demo/advance", json={"demo_hours": 2.1})
    assert client.get("/blocklist").json()["ips"] == []
    client.post("/incidents/RSK-2026-081/permanent", json={"operator": "erick", "justification": "known bad"})
    assert client.get("/blocklist").json()["ips"] == ["203.0.113.45"]
    client.post("/incidents/RSK-2026-081/rollback", json={"operator": "erick", "justification": "undo"})
    assert client.get("/blocklist").json() == {"ips": [], "users": []}
