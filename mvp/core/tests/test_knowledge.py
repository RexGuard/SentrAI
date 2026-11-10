"""Company Rules: a company teaches SentrAI its own guides and quick facts, and Sentry, the coach and the phone app
answer with them. Nothing is trained; passages are looked up per question."""
import base64
import io
import json
import zipfile

import pytest

from app import knowledge as kn

POLICY = """# Acme IT Security Policy

## Email
Never set up a rule that forwards work email to a personal address. Use the Outlook app on your phone.

## File sharing
Share files only with named people. Links that anyone can open are not allowed for customer files.

## Travel
Tell Maria in IT before you travel abroad so your sign-in is not blocked.

## Passwords
Use Bitwarden, the company password manager. Two-step sign-in must stay on for every account."""


def b64(data):
    return base64.b64encode(data if isinstance(data, bytes) else data.encode()).decode()


def docx(paragraphs):
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", f'<w:document xmlns:w="{ns}"><w:body>{body}</w:body></w:document>')
    return buf.getvalue()


@pytest.fixture
def kb(tmp_path):
    k = kn.Knowledge(tmp_path / "company" / "knowledge.json")
    k.add({"kind": "file", "name": "Acme Security Policy.md", "content_base64": b64(POLICY)}, "owner@acme.test")
    k.save_facts({"it_contact": "Maria Lopez (maria@acme.test)", "report_how": "Tap Something looks wrong in the app",
                  "allowed_apps": "Slack, Google Drive, Bitwarden", "blocked_apps": ["WhatsApp", "WeTransfer"],
                  "systems": [{"name": "Xero", "what": "accounts and invoices", "looks_after": "Finance",
                               "importance": "critical"}]}, "owner@acme.test")
    return k


def test_guides_are_cut_at_headings_and_found_by_everyday_words(kb):
    assert kb.overview()["guides"][0]["passages"] == 4
    top = kb.search("can I forward my mail to gmail?")[0]
    assert top["title"] == "Acme Security Policy" and top["text"].startswith("Email: Never set up a rule")
    assert kb.search("going on holiday to Japan")[0]["text"].startswith("Travel:")
    assert kb.search("share a file with a public link")[0]["text"].startswith("File sharing:")
    assert kb.search("who do I contact for help")[0]["text"].startswith("Who to contact")
    assert kb.search("restore last night's backup") == []


def test_answer_checks_the_app_lists(kb):
    a = kb.answer("is WhatsApp ok for work?")
    assert a["found"] and "WhatsApp is **not allowed**" in a["text"] and "Maria" in a["help"]
    assert "**approved**" in kb.answer("can we use slack")["text"]
    assert not kb.answer("what's for lunch on friday")["found"]
    with pytest.raises(kn.KnowledgeError, match="both"):
        kb.save_facts({"allowed_apps": ["WhatsApp"]}, "x")


def test_files_text_links_versions_and_limits(kb):
    g = kb.add({"kind": "file", "name": "Phones.docx",
                "content_base64": b64(docx(["Phones", "Every work phone needs a screen lock PIN of 6 digits."]))}, "o")
    assert g["title"] == "Phones" and "6 digits" in kb.search("phone screen lock")[0]["text"]
    html = kb.add({"kind": "file", "name": "wifi.html", "content_base64": b64(
        "<html><script>alert(1)</script><p>Guest wifi is for visitors only.</p></html>")}, "o")
    assert "alert" not in kb.guide(html["id"])["text"]
    link = kb.add({"kind": "link", "url": "https://intranet.acme.test/hr", "title": "HR handbook",
                   "text": "Leave, payroll and the code of conduct."}, "o")
    assert kb.search("code of conduct")[0]["url"] == "https://intranet.acme.test/hr"
    again = kb.add({"kind": "text", "title": "hr handbook", "text": "New version: conduct rules."}, "o")
    assert again["replaced"] and again["id"] == link["id"]
    secret = kb.add({"kind": "text", "title": "Server room", "text": "The server room door code changes monthly.",
                     "for_staff": False}, "o")
    assert kb.search("server room door code") and not kb.search("server room door code", staff=True)
    assert secret["id"] not in {x["id"] for x in kb.for_staff()["guides"]}
    for bad in ({"kind": "link", "url": "javascript:alert(1)"}, {"kind": "text", "text": "  "},
                {"kind": "file", "name": "a.exe", "content_base64": b64("MZ")},
                {"kind": "file", "name": "a.txt", "content_base64": "not base64!!"}):
        with pytest.raises(kn.KnowledgeError):
            kb.add(bad, "o")
    kb.remove(g["id"])
    assert all(h["title"] != "Phones" for h in kb.search("phone screen lock PIN digits"))


def test_model_prompt_marks_company_text_as_data(kb):
    p = kb.prompt()
    assert "search_company_rules" in p and "<company_facts_untrusted>" in p and "WhatsApp" in p and "Xero" in p


def test_endpoints_audit_chat_coach_and_phone(client):
    r = client.post("/ui/knowledge/guides", json={"kind": "file", "name": "Policy.md", "content_base64": b64(POLICY)})
    assert r.status_code == 200 and r.json()["passages"] == 4
    gid = r.json()["id"]
    assert client.post("/ui/knowledge/guides", json={"kind": "link", "url": "ftp://x"}).status_code == 400
    ov = client.post("/ui/knowledge/facts", json={"it_contact": "Maria in IT", "blocked_apps": "WhatsApp"}).json()
    assert ov["facts"]["blocked_apps"] == ["WhatsApp"] and len(ov["guides"]) == 1
    assert client.get("/ui/knowledge/ask", params={"q": "can I forward email to my gmail"}).json()["found"]
    types = [rec["type"] for rec in client.get("/audit").json()["records"]]
    assert {"knowledge_added", "knowledge_facts_changed"} <= set(types)
    assert POLICY[40:80] not in json.dumps(client.get("/audit").json())  # titles, never the text

    # Sentry without a model answers rule questions from the guides
    reply = client.post("/chat", json={"operator": "erick", "message": "Are staff allowed to use WhatsApp?"}).json()
    assert "not allowed" in reply["text"] and "Maria in IT" in reply["text"]
    reply = client.post("/chat", json={"operator": "erick", "message": "what's our policy on email forwarding?"}).json()
    assert "forwards work email to a personal address" in reply["text"] and "Policy" in reply["text"]
    # ... and a model gets a lookup tool whose answer is marked as company-written data
    chat = client.app.state.chat
    out = chat._dispatch("search_company_rules", {"query": "travel abroad"}, [], [], {"blocks": [], "followups": []})
    assert "<company_rules_untrusted>" in out and "Tell Maria" in out

    # the coach's notes quote the company's own rule and its IT contact
    client.post("/ui/coach/settings", json={"regions": ["sg"], "region_checks": {"sg": [0, 1, 2]},
                                            "notice_shared": True})
    client.post("/ui/coach/sample", json={})
    notes = json.loads(client.app.state.core.settings.db_path.parent.joinpath("people", "coach.json").read_text())["notes"]
    forwarding = next(n for n in notes if "forward" in n["text"].lower() and n.get("company_rule"))
    assert "Your company's rule (from \"Policy\")" in forwarding["text"] and "Ask Maria in IT" in forwarding["text"]

    assert client.delete(f"/ui/knowledge/guides/{gid}").status_code == 200
    assert client.delete(f"/ui/knowledge/guides/{gid}").status_code == 404
    assert not client.get("/ui/knowledge/ask", params={"q": "forward email to gmail"}).json()["passages"]


def test_phone_app_can_ask(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from app import auth
    from app.config import Settings
    from app.main import create_app
    from .test_mobile import TOKEN, coach_on, staff_key
    monkeypatch.setenv("SENTRAI_ACCOUNTS", str(tmp_path / "accounts.json"))
    auth._fails.clear(), auth._sessions.clear(), auth._pending.clear()
    app = create_app(Settings(db_path=tmp_path / "sentrai.db", background=False, demo_speed=60.0))
    with TestClient(app) as c:
        coach_on(c)
        c.post("/ui/knowledge/guides", headers=TOKEN, json={"kind": "text", "title": "Travel", "text":
               "Tell Maria in IT before you travel abroad."})
        c.post("/ui/knowledge/guides", headers=TOKEN, json={"kind": "text", "title": "Owners only", "for_staff": False,
               "text": "The alarm code for the travel safe is kept by Ravi."})
        c.post("/ui/knowledge/facts", headers=TOKEN, json={"it_contact": "Maria", "allowed_apps": "Slack"})
        assert c.post("/mobile/ask", json={"question": "travel"}).status_code == 401
        h, _ = staff_key(c)
        out = c.post("/mobile/ask", headers=h, json={"question": "I'm going on holiday abroad, what do I do?"}).json()
        assert out["found"] and out["passages"][0]["title"] == "Travel"
        assert all(p["title"] != "Owners only" for p in out["passages"])
        company = c.get("/mobile/company", headers=h).json()
        assert company["allowed_apps"] == ["Slack"] and [g["title"] for g in company["guides"]] == ["Travel"]
        assert c.post("/ui/knowledge/facts", headers=h, json={"it_contact": "evil"}).status_code == 403


def test_cli(client, tmp_path):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import sentrai_cli as cli
    from .test_cli import through

    def run(*argv):
        out = io.StringIO()
        code = cli.main(list(argv), call=through(client), out=out)
        return code, out.getvalue()

    f = tmp_path / "policy.md"
    f.write_text(POLICY, encoding="utf-8")
    assert "Learned \"policy\"" in run("rules", "add", str(f))[1]
    assert "Learned \"Wi-Fi\"" in run("rules", "text", "Wi-Fi", "--about", "Guests use the Guest network only.")[1]
    assert "Saved Xero" in run("rules", "system", "Xero", "--what", "invoices", "--importance", "critical")[1]
    text = run("rules", "facts", "--it-contact", "Maria", "--blocked", "WhatsApp, WeTransfer")[1]
    assert "Not allowed:  WhatsApp, WeTransfer" in text and "System: Xero (critical), invoices" in text
    assert "Travel:" in run("rules", "ask", "travel", "abroad")[1]
    gid = client.get("/ui/knowledge").json()["guides"][-1]["id"]
    assert "Removed" in run("rules", "remove", gid)[1]
    assert run("rules", "show")[0] != 0
