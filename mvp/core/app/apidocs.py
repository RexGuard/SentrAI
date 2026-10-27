"""The core's own API docs: GET /docs (a page that asks for the token) and GET /openapi.json (needs it).

FastAPI's built-in /docs, /redoc and /openapi.json are plain routes that skip the app's token check, so
anyone who could reach the core could read its whole API map. main.py turns them off and `install()`
adds these two instead, both behind require_token like every other endpoint. /docs is on OPEN_PATHS
because the page itself holds nothing (no endpoint names, no data): it asks for the token, fetches
/openapi.json with it and only then draws the endpoints. The token stays in the page's memory, never in
the address bar, a cookie or browser storage, and every "Try it out" request carries it as a header.

The page loads Swagger UI from cdn.jsdelivr.net at one fixed version, checked by its SHA-384 hash
(subresource integrity), so a changed file there never runs next to the token.

The written reference, with examples, is docs/api/ on the website (REFERENCE below).
"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

REFERENCE = "https://rexguard.github.io/SentrAI/docs/api/"

SWAGGER = "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.33.1"
SWAGGER_JS_SRI = "sha384-ZPehFMQommnnuaZ4rpxgkgTT2DKFVp4hZC/7pLit+9Lek9T1YGSo23eHFbvNkXkw"
SWAGGER_CSS_SRI = "sha384-Ov4/wv3j2bmct8cDc5X4ngJZohVPzEmc6uDPH8WeljUxO5vtoykvMEfbu9Vh6RaW"

# Endpoint groups, by the first part of the path, in the order the reference lists them, with the
# reference page each one is on (docs/api/<page>.md).
GROUPS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("Events and log sources", "events", "What the collectors, agents and other tools send in.",
     ("events", "webhook", "heartbeat", "log-sources")),
    ("Incidents", "incidents", "What SentrAI found, what staff reported, and what people decide about it.",
     ("incidents", "helpdesk", "staff-reports")),
    ("Reports and summaries", "reports", "Evidence reports and the one-page client summary.",
     ("reports", "summary")),
    ("Risk and protection", "status", "The risk index, each machine, the protection switch and the block list.",
     ("health", "risk", "machines", "agents", "limits", "protection", "blocklist")),
    ("Alerts and routing", "alerts", "Alerts waiting to go out, who gets them, and personal Telegram chats.",
     ("notifications", "routing", "telegram")),
    ("Central panel and agents", "fleet", "Machines joining a central panel, and what their agents may call.",
     ("fleet",)),
    ("Scans, quarantine and backups", "scans", "Process and threat scans, quarantined files and backups.",
     ("system", "threats", "quarantine", "backups")),
    ("Chat and AI", "chat", "Cyanide's chat, the guided setup and the AI model settings.",
     ("chat", "ai")),
    ("Integrations", "integrations", "Outside services SentrAI works with.",
     ("integrations", "extensions")),
    ("Audit trail", "audit", "The hash-chained record of everything SentrAI did.",
     ("audit",)),
)
OTHER = "Other"


def anchor(method: str, path: str) -> str:
    """The id the website gives an endpoint's heading (### `GET /incidents/{iid}`): kramdown's GFM ids keep
    letters, digits, '_' and '-', and turn spaces into '-', so this is get-incidentsiid."""
    return re.sub(r"[^\w\- ]", "", f"{method} {path}".lower()).replace(" ", "-")


def group_of(path: str) -> tuple[str, str]:
    """(tag, reference page) for a path, by its first part: /incidents/{iid}/why -> Incidents."""
    first = path.strip("/").split("/", 1)[0]
    for tag, page, _, firsts in GROUPS:
        if first in firsts:
            return tag, page
    return OTHER, "index"


DESCRIPTION = f"""SentrAI's core: the engine every other part talks to.

Every endpoint needs the API token unless it says otherwise: send `Authorization: Bearer <token>` or
`X-SentrAI-Token: <token>`. `python sentrai_config.py token` prints it. A machine that joined a
central panel sends its own key (`sa_...`) instead, and may only call the endpoints its agent needs.

The written reference, with examples and error codes, is at [{REFERENCE}]({REFERENCE}).
"""


def schema(app: FastAPI, open_routes: frozenset[tuple[str, str]], agent_routes: frozenset[tuple[str, str]]) -> dict:
    """The OpenAPI document, with how to sign in, each endpoint in its group linked to its section of the
    written reference, and the open ones marked."""
    if app.openapi_schema:
        return app.openapi_schema
    tags = [{"name": tag, "description": about, "externalDocs": {"url": f"{REFERENCE}{page}.html"}}
            for tag, page, about, _ in GROUPS]
    doc = get_openapi(title=app.title, version=app.version, description=DESCRIPTION, routes=app.routes, tags=tags)
    doc.setdefault("components", {})["securitySchemes"] = {
        "token": {"type": "http", "scheme": "bearer",
                  "description": "The API token (SENTRAI_API_TOKEN), or a machine's own agent key (sa_...)."},
        "header": {"type": "apiKey", "in": "header", "name": "X-SentrAI-Token",
                   "description": "The same API token, in its own header."},
    }
    doc["security"] = [{"token": []}, {"header": []}]
    for path, ops in doc.get("paths", {}).items():
        for method, op in ops.items():
            key = (method.upper(), path)
            tag, page = group_of(path)
            op["tags"] = [tag]
            op["externalDocs"] = {"description": "Examples and errors",
                                  "url": f"{REFERENCE}{page}.html#{anchor(method.upper(), path)}"}
            if key in open_routes:
                op["security"] = []  # open: no token
            elif key in agent_routes:
                op["description"] = (op.get("description", "") + "\n\nAlso answers a machine's own agent key "
                                     "(`sa_...`), for that machine only.").strip()
    app.openapi_schema = doc
    return doc


_SCRIPT = """
(function () {
  var form = document.getElementById("unlock"), box = document.getElementById("token"),
      note = document.getElementById("note");
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var token = box.value.trim();
    if (!token) { note.textContent = "Paste the token first."; return; }
    note.textContent = "Checking the token...";
    fetch("openapi.json", {headers: {"Authorization": "Bearer " + token}, cache: "no-store", credentials: "omit"})
      .then(function (r) {
        if (r.status === 401) throw new Error("That token is not right. On the machine running SentrAI, " +
                                              "python sentrai_config.py token prints it.");
        if (!r.ok) throw new Error("The core answered HTTP " + r.status + ".");
        return r.json();
      })
      .then(function (spec) {
        if (typeof window.SwaggerUIBundle !== "function") {
          throw new Error("The viewer could not load from cdn.jsdelivr.net. The written reference has every " +
                          "endpoint, and openapi.json opens with the token.");
        }
        box.value = "";
        form.hidden = true;
        var base = new URL(".", window.location.href).pathname;
        if (base !== "/" && !spec.servers) spec.servers = [{url: base.replace(/\\/$/, "")}];
        window.SwaggerUIBundle({
          spec: spec, dom_id: "#api", deepLinking: true, validatorUrl: null, persistAuthorization: false,
          requestInterceptor: function (req) { req.headers["Authorization"] = "Bearer " + token; return req; }
        });
      })
      .catch(function (err) { note.textContent = err.message; });
  });
})();
"""
_SCRIPT_HASH = "sha256-" + base64.b64encode(hashlib.sha256(_SCRIPT.encode()).digest()).decode()

PAGE = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>SentrAI core API</title>
<link rel="stylesheet" href="{SWAGGER}/swagger-ui.css" integrity="{SWAGGER_CSS_SRI}" crossorigin="anonymous">
<style>
  body {{ margin: 0; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; color: #18181b; background: #fafafa; }}
  #unlock {{ max-width: 34rem; margin: 12vh auto 0; padding: 2rem; background: #fff; border: 1px solid #e4e4e7;
             border-radius: 12px; }}
  #unlock h1 {{ margin: 0 0 .5rem; font-size: 1.4rem; }}
  #unlock p {{ line-height: 1.5; color: #3f3f46; }}
  #unlock label {{ display: block; margin: 1.2rem 0 .4rem; font-weight: 600; }}
  #unlock .row {{ display: flex; gap: .5rem; }}
  #unlock input {{ flex: 1; padding: .6rem .7rem; font: inherit; border: 1px solid #a1a1aa; border-radius: 8px; }}
  #unlock button {{ padding: .6rem 1rem; font: inherit; font-weight: 600; color: #fff; background: #18181b;
                    border: 0; border-radius: 8px; cursor: pointer; }}
  #unlock input:focus-visible, #unlock button:focus-visible {{ outline: 3px solid #7c3aed; outline-offset: 2px; }}
  #note {{ min-height: 1.5em; color: #b45309; }}
  code {{ font-family: ui-monospace, Consolas, monospace; background: #f4f4f5; padding: .1rem .3rem; border-radius: 4px; }}
  a {{ color: #6d28d9; }}
</style>
</head>
<body>
<form id="unlock" autocomplete="off">
  <h1>SentrAI core API</h1>
  <p>Paste the API token to see every endpoint and try them here. The token stays in this page
     only and is gone when you close it.</p>
  <p>On the machine running SentrAI, <code>python sentrai_config.py token</code> prints it.</p>
  <label for="token">API token</label>
  <div class="row">
    <input id="token" type="password" spellcheck="false" autocapitalize="off" required>
    <button type="submit">Show the API</button>
  </div>
  <p id="note" role="status" aria-live="polite"></p>
  <p>Examples and error codes for every endpoint: <a href="{REFERENCE}">the API reference</a>.</p>
</form>
<div id="api"></div>
<script src="{SWAGGER}/swagger-ui-bundle.js" integrity="{SWAGGER_JS_SRI}" crossorigin="anonymous"></script>
<script>{_SCRIPT}</script>
</body>
</html>
"""

# Only what the page needs: Swagger UI from the CDN, its own inline script (by hash), calls to this core.
CSP = ("default-src 'none'; "
       f"script-src '{_SCRIPT_HASH}' https://cdn.jsdelivr.net; "
       "style-src 'unsafe-inline' https://cdn.jsdelivr.net; "
       "img-src 'self' data:; font-src data:; connect-src 'self'; "
       "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def install(app: FastAPI, open_routes: frozenset[tuple[str, str]], agent_routes: frozenset[tuple[str, str]]) -> None:
    """Adds GET /docs and GET /openapi.json; the app's own token check guards the second one."""
    app.openapi = lambda: schema(app, open_routes, agent_routes)  # type: ignore[method-assign]

    @app.get("/docs", include_in_schema=False)
    def docs_page() -> HTMLResponse:
        return HTMLResponse(PAGE, headers={"Content-Security-Policy": CSP, "Cache-Control": "no-store"})

    @app.get("/openapi.json", include_in_schema=False)
    def openapi_json() -> JSONResponse:
        return JSONResponse(app.openapi(), headers={"Cache-Control": "no-store"})


def endpoints(app: FastAPI) -> list[dict[str, Any]]:
    """Every (method, path) the app serves, with its group and reference page (for the docs check)."""
    from fastapi.routing import APIRoute

    out = []
    for r in app.routes:
        if isinstance(r, APIRoute):
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                tag, page = group_of(r.path)
                out.append({"method": m, "path": r.path, "group": tag, "page": page})
    return out
