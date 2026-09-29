"""Aegis Academy Student Portal — the SentrAI demo target app.

A deliberately small, FICTIONAL student portal (Flask, 127.0.0.1:5000). It
produces realistic-looking logs for the collector and honors SentrAI's
containment blocklist. Nothing here is a real system and no user input is
ever executed as a command.
"""
from __future__ import annotations

import os

from flask import (
    Flask, Response, render_template, request, redirect, url_for, abort
)

from . import db, logger, paths, spines
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


def create_app(start_polling: bool = False, core_url: str | None = None,
               spines_on: bool | None = None, tarpit_s: float | None = None) -> Flask:
    app = Flask(__name__)
    app.config["ADMIN_PASSWORD"] = _load_admin_password()
    core = core_url or DEFAULT_CORE_URL
    # Cactus spines (spines.py): off unless CACTAI_SPINES=1 or spines_on=True.
    spines_on = spines.enabled_from_env() if spines_on is None else spines_on
    tarpit = spines.Tarpit(spines.tarpit_delay_from_env() if tarpit_s is None else tarpit_s)
    app.config["SPINES"] = spines_on
    app.extensions["cactai_tarpit"] = tarpit

    db.init_db()
    db.set_honeytokens(spines_on)

    if start_polling:
        start_poller(core)

    def prick(kind: str, layer: str, ip: str, user: str | None, detail: str, pii: bool = False) -> None:
        """Record a spine touch; the first touch from an IP also engages the tarpit."""
        if tarpit.prick(ip) and tarpit.delay_s > 0:
            detail += f"; tarpit engaged ({tarpit.delay_s:g} s per request from {ip})"
        logger.log_spine(kind, layer, ip, user, detail, pii=pii)

    def check_honeytokens(ip: str, rows: list[dict], via: str) -> None:
        if not spines_on:
            return
        hits = spines.honeytoken_hits(rows)
        if hits:
            prick(spines.HONEYTOKEN_ROW, "db", ip, request.args.get("user"),
                  f"bait member rows {', '.join(hits)} returned by {via} ({len(rows)} rows)", pii=True)

    # --- Containment enforcement ------------------------------------------
    @app.before_request
    def _enforce_blocklist():
        ip = client_ip()
        # Tarpit: slow down decoy pages and anyone who already touched a spine.
        if spines_on and (request.path == spines.HONEYPOT_PATH or tarpit.is_pricked(ip)):
            tarpit.hold()
        # The user under contention is whatever login/query is being attempted.
        user = request.form.get("user") or request.args.get("user")
        if blocklist.is_blocked(ip, user):
            logger.log_access(ip, request.method, request.path, 403, user=user, blocked=True)
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
        if spines_on and user == spines.DECOY_USER:
            prick(spines.HONEYTOKEN_CREDENTIAL, "web", ip, user,
                  f"planted credential '{user}' (exists only in the decoy page source) tried on /login")
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
        check_honeytokens(ip, results, f"/search q={q!r}")
        return render_template("results.html", q=q, members=results, mode="search")

    @app.get("/export")
    def export():
        ip = client_ip()
        members = db.all_members()
        logger.log_access(ip, "GET", "/export", 200, pii=True)
        logger.log_db(ip, request.args.get("user"), "SELECT * FROM members",
                      rows=len(members), pii=True)
        check_honeytokens(ip, members, "/export")
        return render_template("results.html", q=None, members=members, mode="export")

    # --- Cactus spines (404 unless switched on) ---------------------------
    @app.get("/robots.txt")
    def robots():
        if not spines_on:
            abort(404)
        return Response(f"User-agent: *\nDisallow: {spines.HONEYPOT_PATH}\n", mimetype="text/plain")

    @app.route(spines.HONEYPOT_PATH, methods=["GET", "POST"])
    def honeypot():
        """Decoy staff login. Never signs anyone in; every touch is an alert."""
        if not spines_on:
            abort(404)
        ip = client_ip()
        page = dict(decoy_user=spines.DECOY_USER, decoy_password=spines.DECOY_PASSWORD)
        if request.method == "GET":
            logger.log_access(ip, "GET", spines.HONEYPOT_PATH, 200)
            prick(spines.HONEYPOT_PAGE, "web", ip, None,
                  f"decoy page {spines.HONEYPOT_PATH} opened (listed only in robots.txt as Disallow)")
            return render_template("honeypot.html", error=None, **page)
        tried = (request.form.get("user") or "").strip()
        logger.log_access(ip, "POST", spines.HONEYPOT_PATH, 401)
        # user=None on purpose: whoever posts here must not get a real account locked.
        prick(spines.HONEYPOT_LOGIN, "web", ip, None,
              f"sign-in attempted on decoy page {spines.HONEYPOT_PATH} as {tried or '(blank)'!r}")
        return render_template("honeypot.html", error="Invalid credentials.", **page), 401

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
    print("Aegis Academy Student Portal (SentrAI demo target)")
    print(f"  serving  http://127.0.0.1:5000")
    print(f"  logs     {paths.logs_dir()}")
    print(f"  core     {core} (blocklist poll every 2s, fail-open)")
    if app.config["SPINES"]:
        tarpit = app.extensions["cactai_tarpit"]
        print(f"  spines   ON: honeypot {spines.HONEYPOT_PATH}, honeytoken rows, tarpit {tarpit.delay_s:g}s")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
