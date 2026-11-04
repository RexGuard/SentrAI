"""The API reference (docs/api/ on the website) and the core's own docs page stay true to the code.

Every endpoint the core serves has a ``### `METHOD /path` `` heading, with the path exactly as in the
code, on the reference page apidocs.GROUPS gives its first path segment, and every such heading names a
real endpoint. /openapi.json links each endpoint to that heading (apidocs.anchor), so the heading's id
must also be unique on its page. When this fails after adding an endpoint, add a section for it to the
page the message names; a new first path segment needs a new entry in GROUPS (or the endpoint lands on
the overview). A heading about another server carries a suffix, as in ``### `POST /append` (witness)``,
and is not checked.

The docs page itself (apidocs.py) is open but holds nothing until the token is typed; /openapi.json
needs the token; FastAPI's own /redoc and oauth2 redirect are gone.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from app import apidocs

ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "docs" / "api"
ENDPOINT = re.compile(r"^### `(GET|POST|PUT|PATCH|DELETE) (/[^`\s]*)`\s*$")
ANY_HEADING = re.compile(r"^#{1,6} (.+?)\s*$")
NO_AUTH = {"Authorization": ""}


def _heading_lines(page: Path):
    """(line number, text) of each line outside fenced code blocks."""
    fenced = False
    for n, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced:
            yield n, line


def _endpoints_on_pages() -> list[tuple[str, str, str, int]]:
    """(method, path, page, line) for every endpoint heading in docs/api/."""
    found = []
    for page in sorted(DOCS.glob("*.md")):
        for n, line in _heading_lines(page):
            h = ENDPOINT.match(line)
            if h:
                found.append((h.group(1), h.group(2), page.name, n))
    return found


def _ids(page: Path) -> Counter:
    """The ids kramdown gives the page's headings (what apidocs.anchor computes for endpoints)."""
    ids: Counter = Counter()
    for _, line in _heading_lines(page):
        h = ANY_HEADING.match(line)
        if h:
            ids[re.sub(r"[^\w\- ]", "", h.group(1).replace("`", "").lower()).replace(" ", "-")] += 1
    return ids


def test_reference_pages_exist():
    assert (DOCS / "index.md").exists(), f"the API reference lives in {DOCS}"
    missing = sorted(page for _, page, _, _ in apidocs.GROUPS if not (DOCS / f"{page}.md").exists())
    assert not missing, f"apidocs.GROUPS names reference pages that do not exist: {missing}"
    for page in DOCS.glob("*.md"):
        head = page.read_text(encoding="utf-8")[:400]
        assert head.startswith("---\n") and "\nnav: api\n" in head and "\ntitle: " in head, \
            f"{page.name} needs front matter with title and nav: api"


def test_site_nav_lists_every_page():
    urls = set(re.findall(r"^\s+url:\s*(\S+)", (ROOT / "_data" / "api.yml").read_text(encoding="utf-8"), re.M))
    pages = {"/docs/api/" if p.stem == "index" else f"/docs/api/{p.stem}.html" for p in DOCS.glob("*.md")}
    assert urls == pages, f"_data/api.yml and docs/api/ disagree: only in api.yml {urls - pages}, " \
                          f"only on disk {pages - urls}"


def test_every_endpoint_is_documented_on_its_page(client):
    documented = {(m, p): page for m, p, page, _ in _endpoints_on_pages()}
    missing, elsewhere = [], []
    for r in apidocs.endpoints(client.app):
        page = documented.get((r["method"], r["path"]))
        if page is None:
            missing.append(r)
        elif page != f"{r['page']}.md":
            elsewhere.append(f"  {r['method']} {r['path']} is on {page}, but /openapi.json links it to {r['page']}.md")
    assert not missing, ("endpoints with no `### `METHOD /path`` heading in docs/api/ (the path exactly as in "
                         "the code); add a section to the page named:\n"
                         + "\n".join(f"  {r['method']} {r['path']}  ->  docs/api/{r['page']}.md" for r in missing))
    assert not elsewhere, "endpoints on the wrong page (move the section, or change apidocs.GROUPS):\n" + \
        "\n".join(elsewhere)


def test_every_heading_is_an_endpoint(client):
    real = {(r["method"], r["path"]) for r in apidocs.endpoints(client.app)}
    stale = [(m, p, page, n) for m, p, page, n in _endpoints_on_pages() if (m, p) not in real]
    assert not stale, ("docs/api/ headings that name no endpoint of the core (removed, renamed, a different "
                       "{param} name, or a typo):\n" + "\n".join(f"  docs/api/{page}:{n}  {m} {p}"
                                                                  for m, p, page, n in stale))


def test_no_endpoint_documented_twice():
    seen: dict[tuple[str, str], str] = {}
    twice = []
    for m, p, page, n in _endpoints_on_pages():
        if (m, p) in seen:
            twice.append(f"  {m} {p}: {seen[m, p]} and {page}:{n}")
        seen.setdefault((m, p), f"{page}:{n}")
    assert not twice, "endpoints documented twice:\n" + "\n".join(twice)


def test_links_from_openapi_land_on_the_heading(client):
    ids = {page.name: _ids(page) for page in DOCS.glob("*.md")}
    spec = client.get("/openapi.json").json()
    bad = []
    for path, ops in spec["paths"].items():
        for method, op in ops.items():
            url = op["externalDocs"]["url"]
            assert url.startswith(apidocs.REFERENCE), url
            page, _, frag = url[len(apidocs.REFERENCE):].partition("#")
            page = page.replace(".html", ".md")
            if ids.get(page, Counter())[frag] != 1:
                bad.append(f"  {method.upper()} {path}: #{frag} appears {ids.get(page, Counter())[frag]} times on {page}")
    assert not bad, "links from /openapi.json that do not land on exactly one heading:\n" + "\n".join(bad)


def test_docs_page_is_open_but_empty(client):
    r = client.get("/docs", headers=NO_AUTH)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    for path in ("/incidents", "/fleet", "/audit", "/events", "/blocklist"):
        assert path not in r.text, f"{path} is on the docs page before the token is typed"
    assert "API token" in r.text and 'id="token" type="text" autocomplete="off"' in r.text
    assert 'type="password"' not in r.text  # a password box makes browsers offer to save the token as a login
    assert apidocs.SWAGGER in r.text and 'integrity="sha384-' in r.text


def test_openapi_needs_the_token(client):
    assert client.get("/openapi.json", headers=NO_AUTH).status_code == 401
    assert client.get("/openapi.json", headers={"Authorization": "", "X-SentrAI-Token": "test-token"}).status_code == 200
    spec = client.get("/openapi.json").json()
    schemes = spec["components"]["securitySchemes"]
    assert schemes["token"]["scheme"] == "bearer" and schemes["header"]["name"] == "X-SentrAI-Token"
    assert spec["security"] == [{"token": []}, {"header": []}]
    assert spec["paths"]["/health"]["get"]["security"] == []  # open
    assert "machine" in spec["paths"]["/events"]["post"]["description"].lower()  # the agent-key note
    tags = {op["tags"][0] for ops in spec["paths"].values() for op in ops.values()}
    assert tags <= {tag for tag, _, _, _ in apidocs.GROUPS}, f"endpoints outside every group: {tags}"
    assert "/docs" not in spec["paths"] and "/openapi.json" not in spec["paths"]


def test_fastapis_own_docs_are_gone(client):
    for path in ("/redoc", "/docs/oauth2-redirect"):
        assert client.get(path).status_code == 404, path
    assert client.get("/docs").status_code == 200  # the one page there is, with or without the token
