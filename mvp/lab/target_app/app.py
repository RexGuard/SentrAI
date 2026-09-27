"""Aegis Academy Student Portal — the CactAI demo target app.

A deliberately small, FICTIONAL student portal (Flask, 127.0.0.1:5000). It
produces realistic-looking logs for the collector and honors CactAI's
containment blocklist. Nothing here is a real system and no user input is
ever executed as a command.
"""
from __future__ import annotations

import os

from flask import (
    Flask, Response, render_template, request, redirect, url_for, abort
)

from . import db, logger, paths
from .blocklist import blocklist, start_poller

DEFAULT_CORE_URL = os.environ.get("CACTAI_CORE_URL", "http://127.0.0.1:8000")
ADMIN_USER = "admin"
HOST_NAME = "web-01"


def _load_admin_password() -> str:
    seed = paths.seed_dir() / "admin_password.txt"
    try:
        return seed.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        # Should not happen in the repo, but keep the app runnable.
        return "CactusDemo!2026"


def client_ip() -> str:
    """Attacker IP: X-Demo-Src-IP header (demo spoofing) else remote_addr."""
    return request.headers.get("X-Demo-Src-IP") or (request.remote_addr or "127.0.0.1")


def create_app(start_polling: bool = False, core_url: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["ADMIN_PASSWORD"] = _load_admin_password()
    core = core_url or DEFAULT_CORE_URL

    db.init_db()

    if start_polling:
        start_poller(core)

    # --- Containment enforcement ------------------------------------------
    @app.before_request
    def _enforce_blocklist():
        ip = client_ip()
        # The user under contention is whatever login/query is being attempted.
        user = request.form.get("user") or request.args.get("user")
        if blocklist.is_blocked(ip, user):
            logger.log_access(ip, request.method, request.path, 403, user=user)
            return render_template("blocked.html", ip=ip), 403
        return None

    # --- Routes -----------------------------------------------------------
    @app.get("/")
    def index():
        ip = client_ip()
        logger.log_access(ip, "GET", "/", 200)
        return render_template("login.html", error=None)

    @app.post("/login")
    def login():
        ip = client_ip()
        user = (request.form.get("user") or "").strip()
        password = request.form.get("password") or ""
        ok = user == ADMIN_USER and password == app.config["ADMIN_PASSWORD"]
        status = 200 if ok else 401
        logger.log_access(ip, "POST", "/login", status, user=user or None)
        logger.log_auth(ip, user or None, "success" if ok else "fail")
        if ok:
            return render_template("portal.html", user=user)
        return render_template("login.html", error="Invalid credentials."), 401

    @app.get("/search")
    def search():
        ip = client_ip()
        q = request.args.get("q", "")
        results = db.search_members(q)
        logger.log_access(ip, "GET", "/search", 200, pii=True)
        # Log the raw query separately at the DB layer (this is where an
        # SQLi payload becomes visible to the collector).
        logger.log_db(ip, request.args.get("user"), q, rows=len(results), pii=True)
        return render_template("results.html", q=q, members=results, mode="search")

    @app.get("/export")
    def export():
        ip = client_ip()
        members = db.all_members()
        logger.log_access(ip, "GET", "/export", 200, pii=True)
        logger.log_db(ip, request.args.get("user"), "SELECT * FROM members",
                      rows=len(members), pii=True)
        return render_template("results.html", q=None, members=members, mode="export")

    @app.get("/admin/run")
    def admin_run():
        """Simulated command endpoint. NEVER executes anything."""
        ip = client_ip()
        cmd = request.args.get("cmd", "")
        # OS-layer event only — logged, never run.
        logger.log_os(ip, request.args.get("user"),
                      f"web server spawned shell: {cmd}")
        logger.log_access(ip, "GET", "/admin/run", 200)
        return Response(
            f"[SIMULATED] command not executed. Logged os event for: {cmd}\n",
            mimetype="text/plain",
        )

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "core_reachable": blocklist.core_reachable}

    return app


def main() -> None:
    core = os.environ.get("CACTAI_CORE_URL", DEFAULT_CORE_URL)
    app = create_app(start_polling=True, core_url=core)
    print("Aegis Academy Student Portal (CactAI demo target)")
    print(f"  serving  http://127.0.0.1:5000")
    print(f"  logs     {paths.logs_dir()}")
    print(f"  core     {core} (blocklist poll every 2s, fail-open)")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
