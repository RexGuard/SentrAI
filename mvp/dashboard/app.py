"""SentrAI operator dashboard (Streamlit, http://127.0.0.1:8501).

The sidebar is the menu: Configuration (the home page), Approvals, Chat (talk with the
orchestrator), one page per part of the pipeline (Collector, Classifier, Action taker), Review,
Reports and Audit trail. A part's
menu button shows a bubble with the malicious activity that arrived since it was last opened.

Run from this folder:  .venv\\Scripts\\streamlit run app.py
"""
from __future__ import annotations

import hmac
import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st

from cactai_ui import shaping as sh
from cactai_ui import signin
from cactai_ui.api import CoreClient, CoreError

sys.path.append(str(Path(__file__).resolve().parents[1]))
import cactai_config as cfg  # noqa: E402
import setup_chat  # noqa: E402

cfg.load()

DEFAULT_CORE = os.environ.get("CACTAI_CORE_URL", "http://127.0.0.1:8000")
DEFAULT_OPERATOR = os.environ.get("CACTAI_OPERATOR", "operator")
REFRESH_SECONDS = 2

# SentrAI brand mark: assets/brand/mark-dark.svg (shield with an open eye), inlined so it needs no file.
SHIELD = ('<svg viewBox="0 0 64 64" aria-hidden="true">'
          '<path d="M32 4 L54 11.5 V29 C54 43.5 44.8 54.2 32 60 C19.2 54.2 10 43.5 10 29 V11.5 Z" fill="#16264a" '
          'stroke="#7fb2ff" stroke-width="3" stroke-linejoin="round"/>'
          '<path d="M17 32 C22.5 24 27 21.5 32 21.5 C37 21.5 41.5 24 47 32 C41.5 40 37 42.5 32 42.5 '
          'C27 42.5 22.5 40 17 32 Z" fill="#7fb2ff"/><circle cx="32" cy="32" r="6" fill="#0b111d"/>'
          '<circle cx="34.2" cy="29.8" r="1.8" fill="#e7edf6"/></svg>')
# Tab icon from the brand kit when it is in the checkout, else the emoji.
_FAVICON = Path(__file__).resolve().parents[2] / "assets" / "brand" / "favicon-32.png"
PAGE_ICON = str(_FAVICON) if _FAVICON.exists() else "🛡️"
st.set_page_config(page_title="SentrAI · Risk Console", page_icon=PAGE_ICON, layout="wide",
                   initial_sidebar_state="expanded")
CSS = (Path(__file__).parent / "cactai_ui" / "console.css").read_text(encoding="utf-8")
st.markdown(f"<style>{CSS}</style>", unsafe_allow_html=True)


# ------------------------------------------------------------------ login

def _client_ip() -> str:
    try:
        ip = st.context.ip_address
    except Exception:  # noqa: BLE001 - no browser behind this run
        ip = None
    return ip if isinstance(ip, str) and ip else "local"  # a test run has no real address


def check_login(email: str, password: str, account: dict[str, str]) -> bool:
    if not hmac.compare_digest(email.strip().lower().encode(), account["email"].strip().lower().encode()):
        cfg.check_password(password, cfg.hash_password("x"))  # same work either way, so timing tells nothing
        return False
    if account["plain"]:
        return hmac.compare_digest(password.encode(), account["plain"].encode())
    return cfg.check_password(password, account["hash"])


def login() -> None:
    """Ask for the dashboard email and password (setup wizard section 6) once per browser session.

    run_demo and deploy/install.sh make the sign-in on first run (python cactai_config.py admin).
    CACTAI_DASHBOARD_LOGIN=off skips it, for local testing only. The core API needs its token either way.
    """
    if not cfg.login_required() or st.session_state.get("signed_in"):
        return
    account = cfg.dashboard_login()
    _, mid, _ = st.columns([1, 1.2, 1])
    brand = ('<div class="brand"><div class="brand-mark">' + SHIELD + '</div><div>'
             '<div class="brand-name">Sentr<span>AI</span></div>'
             '<div class="brand-tag">Risk Console</div></div></div>')
    if not account["hash"] and not account["plain"]:
        with mid.container(border=True):
            st.markdown(brand, unsafe_allow_html=True)
            st.warning("No dashboard sign-in is set up yet. On this machine, run "
                       "`python cactai_config.py admin` (on a server: `sudo cactai-admin`), then reload this page.")
        st.stop()
    with mid.form("login"):
        st.markdown(brand, unsafe_allow_html=True)
        email = st.text_input("Email", autocomplete="username",
                              placeholder=account["email"] if account["email"].endswith(".local") else "")
        typed = st.text_input("Password", type="password", autocomplete="current-password")
        if st.form_submit_button("Sign in", type="primary", width="stretch"):
            ip = _client_ip()
            wait = signin.wait_seconds(ip)
            if wait:
                st.error(f"Too many wrong tries. Wait {int(wait) // 60 + 1} min and try again.")
            elif check_login(email, typed, account):
                signin.succeeded(ip)
                st.session_state.signed_in = account["email"]
                st.rerun()
            else:
                signin.failed(ip)
                st.error("Wrong email or password.")
    st.stop()

login()


# ------------------------------------------------------------------ helpers

def icon(name: str) -> str:
    """A Material Symbols icon (the font ships with Streamlit, so it works offline)."""
    return f'<span class="mi">{name}</span>'


def pill(text: str, color: str, pulse: bool = False) -> str:
    return (f'<span class="chip" style="color:{color};border-color:{color}55;background:{color}14">'
            f'<span class="dot{" pulse" if pulse else ""}" style="background:{color}"></span>{html.escape(text)}</span>')


def kpi(label: str, value: str, sub: str = "", color: str | None = None, ico: str = "") -> None:
    accent = f"--accent:{color};" if color else ""
    st.markdown(
        f'<div class="kpi" style="{accent}"><div class="kpi-label">{icon(ico) if ico else ""}{html.escape(label)}</div>'
        f'<div class="kpi-value" style="color:{color or "var(--ink)"}">{html.escape(value)}</div>'
        f'<div class="kpi-sub">{html.escape(sub) or "&nbsp;"}</div></div>',
        unsafe_allow_html=True,
    )


def section(title: str, note: str = "", ico: str = "") -> None:
    st.markdown(f'<div class="sec-title">{icon(ico) if ico else ""}{title} <small>{html.escape(note)}</small></div>',
                unsafe_allow_html=True)


def empty(text: str, ico: str = "inbox", good: bool = False) -> None:
    st.markdown(f'<div class="empty{" good" if good else ""}">{icon(ico)}<span>{html.escape(text)}</span></div>',
                unsafe_allow_html=True)


def safe(fn, default: Any = None) -> tuple[Any, str | None]:
    try:
        return fn(), None
    except CoreError as exc:
        return default, str(exc)


def run_action(label: str, fn, rerun: bool = True) -> None:
    """Run an operator action, flash the result, and refresh the live fragment immediately."""
    try:
        fn()
        st.session_state["flash"] = (f"{label}", "✅")
    except CoreError as exc:
        st.session_state["flash"] = (f"{label} failed: {exc}", "⚠️")
    if rerun:
        st.rerun(scope="fragment")


def show_flash() -> None:
    flash = st.session_state.pop("flash", None)
    if flash:
        st.toast(flash[0], icon=flash[1])




# ------------------------------------------------------------------ data

st.session_state.setdefault("core_url", DEFAULT_CORE)
st.session_state.setdefault("operator", DEFAULT_OPERATOR)
st.session_state.setdefault("auto_refresh", True)
st.session_state.setdefault("page", "config" if cfg.setup_done() else "chat")  # new machine: guided setup
st.session_state.setdefault("seen", {})
TOKEN = cfg.api_token()
client = CoreClient(st.session_state.core_url, token=TOKEN)
AUTO = REFRESH_SECONDS if st.session_state.auto_refresh else None
AUDIT_WINDOW = 500  # latest records the dashboard reads; the core still verifies the whole chain


@st.cache_data(ttl=1, show_spinner=False)
def _get(base_url: str, what: str) -> Any:
    c = CoreClient(base_url, token=TOKEN)
    return {"risk": c.risk, "incidents": c.incidents, "blocklist": c.blocklist, "agents": c.agents,
            "audit": lambda: c.audit(AUDIT_WINDOW)}[what]()


def fetch(what: str, default: Any = None) -> tuple[Any, str | None]:
    """One cached read per second, shared by the menu and the page."""
    return safe(lambda: _get(st.session_state.core_url, what), default)


def protection_off() -> bool:
    risk, _ = fetch("risk")
    return bool(isinstance(risk, dict) and risk.get("monitor_only"))


def audit_records() -> tuple[list[dict], bool | None, str | None]:
    payload, err = fetch("audit", [])
    records, valid = sh.normalize_audit(payload)
    if valid is None and records:
        valid = sh.verify_chain_links(records)
    return records, valid, err


# ------------------------------------------------------------------ menu

PAGES = {  # key: (Material icon, label, menu group)
    "config": ("tune", "Configuration", ""),
    "approvals": ("approval_delegation", "Approvals", "Decide"),
    "chat": ("forum", "Chat", "Decide"),
    "collector": ("input", "Collector", "Pipeline"),
    "classifier": ("category", "Classifier", "Pipeline"),
    "responder": ("shield", "Action taker", "Pipeline"),
    "review": ("speed", "Review", "Oversight"),
    "reports": ("description", "Reports", "Oversight"),
    "audit": ("link", "Audit trail", "Oversight"),
}


def go(page: str) -> None:
    st.session_state.page = page
    st.rerun()


def side_risk() -> None:
    """Live risk index and chain state, visible from every page."""
    risk, err = fetch("risk")
    if err or not isinstance(risk, dict):
        st.markdown(f'<div class="side-risk"><div class="lbl">Core</div>'
                    f'<div class="num" style="color:{sh.BAND_COLORS["critical"]}">Offline</div>'
                    f'<div class="foot"><span>retrying every {REFRESH_SECONDS} s</span></div></div>',
                    unsafe_allow_html=True)
        return
    band, idx = sh.resolve_band(risk), risk.get("risk_index")
    color, threshold = sh.band_color(band), float(risk.get("threshold") or 80)
    _, valid, _ = audit_records()
    chain = ("chain valid", sh.BAND_COLORS["green"]) if valid else ("chain broken", sh.BAND_COLORS["critical"]) \
        if valid is False else ("chain unknown", sh.UNKNOWN_COLOR)
    pct = max(0.0, min(100.0, float(idx or 0)))
    st.markdown(
        f'<div class="side-risk"><div class="row"><span class="lbl">Risk index</span>'
        f'<span class="lbl" style="color:{color}">{html.escape(band.upper())}</span></div>'
        f'<div class="num" style="color:{color}">{idx if idx is not None else "-"}<small> / 100</small></div>'
        f'<div class="bar"><i style="width:{pct:.0f}%;background:{color}"></i><b style="left:{threshold:.0f}%"></b></div>'
        f'<div class="foot"><span>threshold {threshold:.0f}</span>'
        f'<span style="color:{chain[1]}">{icon("link")} {chain[0]}</span></div>'
        + (f'<div class="side-off">{icon("shield")} Protection off · monitor only</div>' if risk.get("monitor_only") else "")
        + '</div>',
        unsafe_allow_html=True,
    )


@st.fragment(run_every=AUTO)
def menu() -> None:
    records, _, _ = audit_records()
    incidents, _ = fetch("incidents", [])
    page, seen = st.session_state.page, st.session_state.seen
    if page in sh.ALERT_TYPES:  # whatever arrives while you look at a page counts as seen
        seen[page] = sh.head_seq(records)
    bubbles = {**sh.unseen_counts(records, seen), "approvals": len(sh.pending_approvals(incidents or []))}

    side_risk()
    group = None
    for key, (ico, label, grp) in PAGES.items():
        if grp != group:
            group = grp
            if grp:
                st.markdown(f'<div class="nav-group">{grp}</div>', unsafe_allow_html=True)
        n = bubbles.get(key, 0)
        text = label + (f"  :red-badge[{n}]" if n else "")
        if st.button(text, key=f"nav_{key}", icon=f":material/{ico}:", width="stretch",
                     type="primary" if key == page else "secondary"):
            if key in sh.ALERT_TYPES:
                seen[key] = sh.head_seq(records)
            go(key)


with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="brand-mark">' + SHIELD + '</div><div>'
        '<div class="brand-name">Sentr<span>AI</span></div>'
        '<div class="brand-tag">Risk Console</div></div></div>',
        unsafe_allow_html=True,
    )
    menu()
    st.markdown('<div class="side-sep"></div>', unsafe_allow_html=True)
    st.toggle(f"Auto-refresh every {REFRESH_SECONDS} s", key="auto_refresh")
    if st.button("Reset demo", icon=":material/restart_alt:", width="stretch",
                 help="POST /demo/reset: clears state for a fresh take"):
        run_action("Demo reset", lambda: client.reset_demo(), rerun=False)
        st.session_state.seen = {}
    if st.session_state.get("signed_in") and st.button("Sign out", icon=":material/logout:", width="stretch",
                                                       help=f"Signed in as {st.session_state.signed_in}"):
        st.session_state.signed_in = False
        st.rerun()
    st.markdown('<div class="side-foot">A sentry doesn\'t chase you. It just guards the gate.</div>',
                unsafe_allow_html=True)


# ------------------------------------------------------------------ shared page parts

def header(title: str, note: str = "") -> dict | None:
    """Page title plus the live status chips. Returns /risk, or None when the core is offline."""
    risk, err = fetch("risk")
    now_s = datetime.now().strftime("%H:%M:%S")
    ico, _, group = PAGES[st.session_state.page]
    if err or not isinstance(risk, dict):
        chips = pill("Core offline", sh.BAND_COLORS["critical"])
    else:
        band = sh.resolve_band(risk)
        _, valid, _ = audit_records()
        label = sh.BAND_LABELS.get(band, band)
        if risk.get("monitor_only") and band == "critical":
            label = "CRITICAL · nothing applied (monitor only)"
        chips = (pill(f"Risk {risk.get('risk_index', '-')} · {label}", sh.band_color(band))
                 + (pill("Chain valid", sh.BAND_COLORS["green"]) if valid
                    else pill("Chain broken", sh.BAND_COLORS["critical"]) if valid is False
                    else pill("Chain unknown", sh.UNKNOWN_COLOR)))
        if risk.get("monitor_only"):
            chips = pill("Protection off", sh.BAND_COLORS["amber"]) + chips
    chips += pill(f"Live · {now_s}" if AUTO else f"Paused · {now_s}", sh.BAND_COLORS["green"] if AUTO else sh.UNKNOWN_COLOR,
                  pulse=bool(AUTO))
    st.markdown(
        f'<div class="page-head"><div class="page-title"><div class="page-icon">{icon(ico)}</div><div>'
        f'<div class="eyebrow">{html.escape(group or "Settings")}</div><h1>{html.escape(title)}</h1>'
        f'<div class="page-note">{html.escape(note)}</div></div></div>'
        f'<div class="chips">{chips}</div></div>',
        unsafe_allow_html=True,
    )
    if err or not isinstance(risk, dict):
        st.markdown(
            f'<div class="offline">{icon("cloud_off")}<div><b>Core API unreachable</b><br>'
            f'<small>{html.escape(err or "unexpected /risk payload")}</small><br><br>'
            f'Retrying every {REFRESH_SECONDS} s. Start the core (or <code>dev/fake_core.py</code>) '
            f'and check the Core URL on the Configuration page.</div></div>',
            unsafe_allow_html=True,
        )
        return None
    if risk.get("monitor_only"):
        protection_banner()
    return risk


def protection_banner() -> None:
    """Shown on every page while protection is off, so nobody mistakes monitoring for protection."""
    p, _ = safe(client.protection, {})
    who = f" by {p['changed_by']}" if p.get("changed_by") else ""
    why = f": {p['reason']}" if p.get("reason") else ""
    left = len(p.get("active_actions") or [])
    kept = f" {left} action(s) already in force stay until they expire or are rolled back." if left else ""
    st.markdown(
        f'<div class="protect-off">{icon("remove_moderator")}<div><b>Protection is off: monitor-only mode</b><br>'
        f'<small>Turned off{html.escape(who)}{html.escape(why)}</small><br>'
        f'SentrAI is still collecting, classifying and scoring, but applies no containment, autonomous or approved.'
        f'{kept} Turn it back on from the Configuration page.</div></div>',
        unsafe_allow_html=True,
    )


def table(df, empty_text: str, **kwargs) -> None:
    if df.empty:
        if empty_text:
            empty(empty_text)
    else:
        st.dataframe(df, hide_index=True, width="stretch", **kwargs)


def incident_summary(inc: dict) -> None:
    inc_id = str(inc.get("id"))
    sev_color = {"low": sh.BAND_COLORS["green"], "medium": sh.BAND_COLORS["amber"], "high": sh.BAND_COLORS["red"],
                 "critical": sh.BAND_COLORS["critical"]}.get(
        str(inc.get("severity")), sh.UNKNOWN_COLOR)
    st.markdown(
        f'<div class="inc-head">'
        f'<span class="inc-id">{html.escape(inc_id)}</span>'
        f'{pill(str(inc.get("severity", "?")).upper(), sev_color)}'
        f'{pill(sh.status_label(inc.get("status")), sh.TEXT_SECONDARY)}'
        + (pill("SLA BREACHED", sh.BAND_COLORS["critical"]) if inc.get("sla_breached") else "")
        + (pill(f"ACK · {inc.get('acked_by')}", sh.BAND_COLORS["green"]) if inc.get("acked")
           else pill("ACK · NONE", sh.BAND_COLORS["amber"]))
        + "</div>",
        unsafe_allow_html=True,
    )
    conf = inc.get("ai_confidence")
    st.markdown(
        '<div class="detail-grid">'
        f'<div><span>Category</span><b>{html.escape(sh.category_label(inc.get("category")))}</b></div>'
        f'<div><span>AI confidence</span><b>{conf if conf is not None else "-"}</b></div>'
        f'<div><span>Classified by</span><b>{html.escape(sh.CLASSIFIER_LABELS.get(str(inc.get("classified_by")), str(inc.get("classified_by"))))}</b></div>'
        f'<div><span>Contribution</span><b>{sh.incident_contribution(inc)} pts</b></div>'
        f'<div><span>Source IP</span><b>{html.escape(str(inc.get("src_ip") or "-"))}</b></div>'
        f'<div><span>User</span><b>{html.escape(str(inc.get("user") or "-"))}</b></div>'
        f'<div><span>Host / layer</span><b>{html.escape(str(inc.get("host") or "-"))} · {html.escape(str(inc.get("layer") or "-"))}</b></div>'
        f'<div><span>Opened</span><b>{html.escape(sh.short_time(inc.get("opened_at")))}</b></div>'
        '</div>',
        unsafe_allow_html=True,
    )
    if inc.get("explanation"):
        st.markdown(f'<p class="explain">{html.escape(str(inc["explanation"]))}</p>', unsafe_allow_html=True)
    st.markdown(f'<div class="reco">{icon("tips_and_updates")}<div><b>Recommended action</b>'
                f'{html.escape(str(inc.get("recommended_action") or "-"))}</div></div>',
                unsafe_allow_html=True)
    st.write("")


def decision_controls(inc: dict) -> None:
    """Approve / reject an open incident, or keep / roll back a contained one."""
    inc_id = str(inc.get("id"))
    op = st.session_state.operator
    can = sh.available_actions(inc)

    def ack_then(decision: str, just: str):
        def _run() -> None:
            try:
                client.ack(inc_id, op)
            except CoreError:
                pass
            client.decision(inc_id, op, decision, just)
        return _run

    if can["decide"]:
        if can["ack"] and st.button("Acknowledge", icon=":material/visibility:", key=f"ack_{inc_id}",
                                    help="Records that you have seen this alert (POST /ack)"):
            run_action(f"Acknowledged {inc_id}", lambda: client.ack(inc_id, op))
        with st.form(key=f"decide_{inc_id}", clear_on_submit=True, border=True):
            just = st.text_area("Justification (required to reject, written to the audit log)", key=f"just_{inc_id}",
                                height=80, placeholder="e.g. False positive: this IP is our penetration tester")
            c1, c2 = st.columns(2)
            off = protection_off()
            approve = c1.form_submit_button("Approve & Patch", icon=":material/check:", type="primary", width="stretch",
                                            disabled=off, help="Protection is off (monitor only): turn it on in "
                                                               "Configuration to apply a hotpatch." if off else None)
            reject = c2.form_submit_button("Reject with Justification", icon=":material/block:", width="stretch")
        if approve:
            run_action(f"Approved & patched {inc_id}", ack_then("approve", just.strip()))
        elif reject:
            if not just.strip():
                st.error("Rejecting requires a written justification.")
            else:
                run_action(f"Rejected {inc_id}", ack_then("reject", just.strip()))
    elif can["contain_controls"]:
        with st.form(key=f"contain_{inc_id}", clear_on_submit=True, border=True):
            just = st.text_area("Justification (written to the audit log)", key=f"cjust_{inc_id}", height=70,
                                placeholder="e.g. Verified attacker; keep the block")
            c1, c2 = st.columns(2)
            rb = c1.form_submit_button("Rollback", icon=":material/undo:", width="stretch")
            perm = c2.form_submit_button("Make Permanent", icon=":material/push_pin:", type="primary", width="stretch")
        if rb:
            run_action(f"Rolled back {inc_id}",
                       lambda: client.rollback(inc_id, op, just.strip() or "Rolled back by operator from dashboard"))
        elif perm:
            run_action(f"Made permanent {inc_id}",
                       lambda: client.permanent(inc_id, op, just.strip() or "Made permanent by operator from dashboard"))
    else:
        st.caption(f"No operator action available (status: {inc.get('status')}).")


# ------------------------------------------------------------------ pages

def page_config() -> None:
    header("Configuration", f"Saved to {cfg.config_path()} · read by every part when it starts")
    o1, o2 = st.columns([4, 1], vertical_alignment="center")
    o1.caption("Rather answer a few questions? Cyanide can walk you through setup in the Chat page instead.")
    if o2.button("Set up with Cyanide", icon=":material/forum:", width="stretch"):
        start_setup()
    current = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
    values, new_password = {}, ""
    preset = cfg.SECTIONS[0]
    with st.container(border=True):
        section(preset.title, preset.about, "verified_user")
        values |= preset_settings(current)
        protection_switch()

    # Everything else is folded away; the arrow on each row opens it.
    with st.expander("Dashboard"):  # no icon, so the row shows its arrow
        st.caption("This browser session only.")
        c1, c2 = st.columns(2)
        # Own widget keys: Streamlit drops a widget's state when you leave the page.
        st.session_state.core_url = c1.text_input("Core API URL", value=st.session_state.core_url).strip()
        st.session_state.operator = c2.text_input("Operator name (recorded on your approvals)",
                                                  value=st.session_state.operator).strip() or "operator"
    for s in cfg.SECTIONS[1:]:
        with st.expander(s.title):
            st.caption(s.about)
            if s.key == "ai":
                values |= ai_settings(current)
                continue
            fields = [f for f in s.fields if f.env not in cfg.PRESET_FIELDS]  # those live under the preset
            if len(fields) < len(s.fields):
                st.caption("Detection and response values are set under Security preset.")
            cols = st.columns(2)
            for n, f in enumerate(fields):
                if f.generated:  # shown, never edited here: every part must restart with the same value
                    values[f.env] = current[f.env]
                    cols[n % 2].text_input(f.prompt, value=current[f.env], key=f"cfg_{f.env}", type="password",
                                           disabled=True, help=f"Environment variable {f.env}. Generated by setup; "
                                           "python cactai_config.py token prints it.")
                    continue
                if f.hashed:  # never shown: a new one replaces it, blank keeps it
                    typed = cols[n % 2].text_input("New dashboard password (blank keeps the current one)",
                                                   key=f"cfg_{f.env}", type="password",
                                                   help=f"At least {cfg.MIN_PASSWORD} characters. Saved only as a "
                                                        "hash; applies at the next sign-in.")
                    if typed and len(typed) < cfg.MIN_PASSWORD:
                        cols[n % 2].error(f"Use at least {cfg.MIN_PASSWORD} characters; the old password stays.")
                        typed = ""
                    values[f.env], new_password = current[f.env], typed
                    continue
                values[f.env] = cols[n % 2].text_input(
                    f.prompt, value=current[f.env], key=f"cfg_{f.env}", help=f"Environment variable {f.env}",
                    type="password" if f.secret else "default").strip()
    if st.button("Save settings", icon=":material/save:", type="primary"):
        bad = [f.prompt for f in cfg.FIELDS.values() if not cfg.valid(f, values[f.env])]
        if bad:
            st.error("Please enter a number for: " + "; ".join(bad))
        else:
            if new_password:  # hashed only on Save: hashing is slow on purpose
                values[cfg.HASH_ENV] = cfg.hash_password(new_password)
            path = cfg.save(values)
            cfg.mark_setup_done("dashboard")
            ai, err = safe(client.ai_reload)
            if err:
                st.success(f"Saved to {path}. Start the demo (run_demo.ps1) so the core picks them up.")
            else:
                st.success(f"Saved to {path}. Cyanide switched to the new AI settings ({ai.get('chat')}). "
                           "Restart the demo (stop_demo.ps1, then run_demo.ps1) for the other settings.")


def protection_switch() -> None:
    """Protection on/off. Takes effect at once in the running core (no Save) and is kept across restarts."""
    p, err = safe(client.protection)
    st.markdown('<div class="side-sep"></div>', unsafe_allow_html=True)
    if err or not isinstance(p, dict):
        st.caption(f"Protection switch: the core is not reachable ({err}).")
        return
    op = st.session_state.operator

    def switch(on: bool, reason: str = "") -> None:
        try:
            client.set_protection(on, op, reason)
            st.session_state["flash"] = ("Protection is on" if on else "Protection is off: monitor-only mode", "✅")
        except CoreError as exc:
            st.session_state["flash"] = (f"Could not switch protection: {exc}", "⚠️")
        _get.clear()
        st.rerun()

    if p.get("monitor_only"):
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        c1.markdown(f'{pill("Protection off", sh.BAND_COLORS["amber"])} Monitor only: incidents are scored '
                    f'and alerted, nothing is blocked.', unsafe_allow_html=True)
        if c2.button("Turn protection on", icon=":material/shield:", type="primary", width="stretch",
                     help="Incidents already over the threshold are contained right away."):
            switch(True)
        return
    c1, c2 = st.columns([3, 1], vertical_alignment="bottom")
    reason = c1.text_input("Protection is on. To test without blocking anything, turn it off (monitor only).",
                           key="protect_reason", placeholder="Reason, recorded in the audit trail (required)",
                           help="POST /protection. SentrAI keeps collecting, classifying and scoring, but applies "
                                "no containment, autonomous or approved, until it is turned back on.")
    if c2.button("Turn protection off", icon=":material/remove_moderator:", width="stretch"):
        if not reason.strip():
            st.error("Write why protection is being turned off; it goes into the audit trail.")
        else:
            switch(False, reason.strip())


def preset_settings(current: dict[str, str]) -> dict[str, str]:
    """Strict, Moderate, Balanced or Advanced. Changing a value by hand switches to Advanced."""
    pick = f"cfg_{cfg.PRESET_ENV}"
    keys = {env: f"cfg_{env}" for env in cfg.PRESET_FIELDS}
    st.session_state.setdefault(pick, current[cfg.PRESET_ENV])
    for env, key in keys.items():  # widgets take their start value from session state, so a preset can fill them
        st.session_state.setdefault(key, current[env])

    def fill() -> None:
        if st.session_state[pick] != cfg.ADVANCED:  # Advanced keeps the values as they are
            for env, value in cfg.preset_values(st.session_state[pick]).items():
                st.session_state[keys[env]] = value

    def to_advanced() -> None:
        chosen = {cfg.PRESET_ENV: st.session_state[pick]} | {env: st.session_state[k] for env, k in keys.items()}
        if cfg.overrides(chosen):
            st.session_state[pick] = cfg.ADVANCED

    name = st.segmented_control("Preset", cfg.PRESET_CHOICES, key=pick, required=True, on_change=fill,
                                format_func=cfg.preset_label,
                                help="Environment variable CACTAI_PRESET. A preset fills in the values below; "
                                     "changing any of them by hand switches to Advanced.")
    advanced = name == cfg.ADVANCED
    st.caption(cfg.ADVANCED_ABOUT + " Pick a preset to go back to its values." if advanced
               else cfg.PRESETS[name].about)
    values = {cfg.PRESET_ENV: name} | {env: st.session_state[key].strip() for env, key in keys.items()}
    color = sh.BAND_COLORS["amber"] if advanced else sh.BAND_COLORS["green"]
    chips = "".join(pill(text, color) for text, _ in cfg.describe(values))
    st.markdown(f'<div class="chips">{chips}</div>', unsafe_allow_html=True)

    with st.expander("Advanced settings", expanded=advanced):
        cols = st.columns(2)
        for n, env in enumerate(cfg.PRESET_FIELDS):
            f = cfg.FIELDS[env]
            uses = ", ".join(f"{p.label} {p.values[env]}" for p in cfg.PRESETS.values())
            cols[n % 2].text_input(f.prompt, key=keys[env], on_change=to_advanced,
                                   help=f"Environment variable {env}. Presets: {uses}.")
    return values


def ai_settings(current: dict[str, str]) -> dict[str, str]:
    """Section 5: one provider list, one key, and a button that asks the provider for its models."""
    keys = {env: f"cfg_{env}" for env in ("CACTAI_LLM_PROVIDER", "CACTAI_LLM_API_KEY", "CACTAI_LLM_BASE_URL",
                                          cfg.MODEL_ENV)}
    for env, key in keys.items():  # widgets take their start value from session state, so a pick can fill the model
        st.session_state.setdefault(key, current[env])
    c1, c2 = st.columns(2)
    provider = c1.selectbox("Provider", cfg.cactai_llm.PROVIDERS, key=keys["CACTAI_LLM_PROVIDER"],
                            format_func=lambda p: cfg.cactai_llm.LABEL[p],
                            help="Environment variable CACTAI_LLM_PROVIDER")
    api_key = c2.text_input("API key", key=keys["CACTAI_LLM_API_KEY"], type="password",
                            help="Environment variable CACTAI_LLM_API_KEY. Leave blank to run on fixed playbooks.").strip()
    if provider == "compatible":
        base_url = st.text_input("Base URL", key=keys["CACTAI_LLM_BASE_URL"], placeholder="https://llm.example.com/v1",
                                 help="Environment variable CACTAI_LLM_BASE_URL").strip()
    else:
        base_url = st.session_state[keys["CACTAI_LLM_BASE_URL"]].strip()
        st.caption(f"Endpoint: {base_url or cfg.cactai_llm.BASE_URL.get(provider, '')}")

    default = cfg.cactai_llm.DEFAULT_MODEL.get(provider) or "none, type one"
    m1, m2 = st.columns([3, 1], vertical_alignment="bottom")
    model = m1.text_input("Model", key=keys[cfg.MODEL_ENV], placeholder=f"blank for the default ({default})",
                          help="Environment variable CACTAI_LLM_MODEL; a value set in the environment "
                               "before SentrAI starts wins over this one.").strip()
    ai = {"CACTAI_LLM_PROVIDER": provider, "CACTAI_LLM_API_KEY": api_key, "CACTAI_LLM_BASE_URL": base_url,
          cfg.MODEL_ENV: model}
    if m2.button("Fetch models", icon=":material/refresh:", width="stretch", disabled=not api_key,
                 help="Ask the provider which models this key can use"):
        with st.spinner("Asking the provider for its models..."):
            try:
                st.session_state.ai_models = (provider, cfg.fetch_models(ai), None)
            except cfg.cactai_llm.LLMError as exc:
                st.session_state.ai_models = (provider, [], str(exc))

    fetched_for, models, error = st.session_state.get("ai_models") or ("", [], None)
    if fetched_for == provider and error:
        st.warning(f"Could not list the models: {error}. You can still type the model name.")
    elif fetched_for == provider and not models:
        st.info("The provider listed no models for this key. Type the model name instead.")
    elif fetched_for == provider:
        def pick() -> None:
            st.session_state[keys[cfg.MODEL_ENV]] = st.session_state.ai_model_pick

        st.selectbox(f"Available models ({len(models)})", models, key="ai_model_pick", on_change=pick,
                     index=models.index(model) if model in models else None, placeholder="Pick a model")
    ai_connection(ai)
    return ai


def ai_connection(ai: dict[str, str]) -> None:
    """What Cyanide uses right now, and a button that makes one real request with the values above."""
    now, err = safe(client.ai_status)
    t1, t2 = st.columns([3, 1], vertical_alignment="center")
    if err:
        t1.caption("Cyanide: core not running, so this can't show what it uses. Start the demo to test through it.")
    elif now.get("online"):
        t1.caption(f"Cyanide now: 🟢 online · {now.get('provider')} · {now.get('model')}"
                   f" · key from {now.get('key_source') or 'unknown'}")
    else:
        t1.caption(f"Cyanide now: 🔴 offline · {now.get('off_reason') or now.get('chat')}")
    body = {"provider": ai["CACTAI_LLM_PROVIDER"], "api_key": ai["CACTAI_LLM_API_KEY"],
            "base_url": ai["CACTAI_LLM_BASE_URL"], "model": ai[cfg.MODEL_ENV]}
    if t2.button("🔌 Test connection", width="stretch", disabled=bool(err),
                 help="Send one short request to the provider with the settings above (saved or not), "
                      "through the same code Cyanide uses"):
        with st.spinner("Sending a test request to the provider..."):
            result, test_err = safe(lambda: client.ai_test(body))
        st.session_state.ai_test = (body, result if not test_err else {"ok": False, "error": test_err})
    tested, result = st.session_state.get("ai_test") or (None, None)
    if tested != body:  # the form changed since the test: that result no longer applies
        result = None
    if result and result.get("ok"):
        st.success(f"Connected: {result.get('provider')} answered with model {result.get('model')} "
                   f"in {result.get('ms')} ms.")
        if not now or now.get("model") != result.get("model") or not now.get("online"):
            st.info("These settings work. Press Save settings to switch Cyanide to them.")
    elif result:
        st.error(f"Connection failed: {result.get('error')}")
        if result.get("hint"):
            st.caption(result["hint"])


@st.fragment(run_every=AUTO)
def page_approvals() -> None:
    show_flash()
    if header("Approvals", "requests waiting on a person · nothing permanent happens without one") is None:
        return
    incidents, err = fetch("incidents", [])
    if err:
        st.warning(f"Could not load incidents: {err}")
    waiting = sh.pending_approvals(incidents or [])
    if not waiting:
        empty("Nothing waiting for a decision. All quiet at the gate.", "check_circle", good=True)
        return
    for n, inc in enumerate(waiting):
        can = sh.available_actions(inc)
        verb = "Approve or reject" if can["decide"] else "Keep or roll back"
        title = f"{verb} · {inc.get('id')} · {sh.category_label(inc.get('category'))} · {sh.incident_contribution(inc)} pts"
        with st.expander(title, expanded=n == 0):
            incident_summary(inc)
            decision_controls(inc)
            table(sh.action_rows(inc), "No containment actions yet.")


CHAT_STARTERS = ("What is happening right now?", "Which incident should I deal with first?",
                 "Why did you block the last IP address?")


def page_chat() -> None:
    """Talk with the orchestrator. It reads everything; it can only suggest, the operator decides.

    Not auto-refreshed, so a rerun never interrupts typing.
    """
    show_flash()
    online = header("Chat", "ask the orchestrator what it sees and why it acted · it suggests, you decide") is not None
    if st.session_state.get("setup_chat"):  # scripted, so it works with the core offline too
        setup_conversation()
        return
    if not cfg.setup_done() and not st.session_state.get("setup_later"):
        with st.container(border=True):
            s1, s2, s3 = st.columns([6, 2, 1], vertical_alignment="center")
            s1.markdown("**New here?** Cyanide can set SentrAI up with you in a few plain questions, "
                        "so you don't need the Configuration page.")
            if s2.button("Set up with Cyanide", icon=":material/forum:", type="primary", width="stretch"):
                start_setup()
            if s3.button("Not now", width="stretch"):
                st.session_state.setup_later = True
                st.rerun()
    if not online:
        return
    hist, err = safe(client.chat_history, {})
    if err:
        st.warning(f"Chat is not available on this core: {err}")
        return
    assistant = str(hist.get("assistant") or "Cyanide")
    messages = hist.get("messages") or []
    incidents, _ = fetch("incidents", [])
    by_id = {str(i.get("id")): i for i in incidents or [] if i.get("id")}

    c1, c2, c4, c3 = st.columns([4, 5, 2, 2], vertical_alignment="bottom")
    if c4.button("Setup", icon=":material/tune:", width="stretch", help="Let Cyanide walk you through setup"):
        start_setup()
    about = c1.selectbox("Talk about", [""] + sorted(by_id, reverse=True), key="chat_about",
                         format_func=lambda i: f"{i} · {sh.category_label(by_id[i].get('category'))}" if i
                         else "The whole operation")
    c2.caption(f"{assistant} · {hist.get('model') or 'model unknown'} · read-only: every action still needs "
               "your click and goes through the normal approval checks")
    if c3.button("Clear chat", icon=":material/delete_sweep:", width="stretch", disabled=not messages):
        safe(client.clear_chat)
        st.rerun()

    with st.container(height=540, border=True):
        if not messages:
            st.caption(f"Ask {assistant} about incidents, its decisions, or what to do next.")
        for m in messages:
            chat_message(m, assistant, by_id)

    if not messages:
        cols = st.columns(len(CHAT_STARTERS))
        for col, q in zip(cols, CHAT_STARTERS):
            if col.button(q, width="stretch", key=f"starter_{q}"):
                st.session_state["chat_pending"] = q
    prompt = st.chat_input(f"Ask {assistant}…") or st.session_state.pop("chat_pending", None)
    if prompt:
        with st.spinner(f"{assistant} is looking into it…"):
            _, err = safe(lambda: client.chat(st.session_state.operator, prompt, about or None))
        if err:
            st.session_state["flash"] = (f"Chat failed: {err}", "⚠️")
        st.rerun()


def start_setup() -> None:
    st.session_state.setup_chat = setup_chat.SetupChat()
    go("chat")


def setup_conversation() -> None:
    """Cyanide asks the setup questions (mvp/setup_chat.py); the user answers with a button or by typing.

    Kept in this browser session only, never in the core's chat history, because some answers are
    secrets. Nothing is saved until the user confirms the summary.
    """
    sc: setup_chat.SetupChat = st.session_state.setup_chat
    t1, t2 = st.columns([5, 1], vertical_alignment="center")
    t1.caption("Guided setup · nothing is saved until you confirm the summary · the Configuration page "
               "shows the same settings")
    if t2.button("Close setup" if sc.state in ("saved", "cancelled") else "Leave setup",
                 icon=":material/close:", width="stretch"):
        del st.session_state.setup_chat
        st.session_state.setup_later = True
        st.rerun()
    with st.container(height=540, border=True):
        for m in sc.messages:
            mine = m["role"] == "user"
            with st.chat_message("user" if mine else "assistant", avatar="👤" if mine else "🧪"):
                st.markdown(m["text"].replace("\n", "  \n") if mine else m["text"])
    answer = None
    options = sc.options()
    if options:
        cols = st.columns(min(len(options), 4))
        for n, (value, label) in enumerate(options):
            if cols[n % len(cols)].button(label, key=f"setup_{len(sc.messages)}_{value}", width="stretch",
                                          type="primary" if n == 0 and sc.state == "review" else "secondary"):
                answer = value
    if sc.secret:
        with st.form(f"setup_secret_{len(sc.messages)}", clear_on_submit=True, border=False):
            f1, f2 = st.columns([5, 1], vertical_alignment="bottom")
            typed = f1.text_input("Your answer (hidden; it is never shown in the chat)", type="password")
            if f2.form_submit_button("Send", type="primary", width="stretch") and typed:
                answer = typed
    elif sc.state in ("asking", "review"):
        answer = st.chat_input("Type your answer…") or answer
    if not answer:
        return
    with st.spinner("Cyanide is reading your answer…"):
        sc.answer(answer, interpret=setup_interpreter)
    if sc.state == "save":
        save_setup(sc)
    st.rerun()


def setup_interpreter(question: str, options: list[tuple[str, str]], answer: str) -> dict | None:
    """The AI model's reading of an answer the script could not match; None when the core is offline."""
    result, err = safe(lambda: client.setup_interpret(question, options, answer))
    return None if err or not isinstance(result, dict) else result


def save_setup(sc: "setup_chat.SetupChat") -> None:
    values = sc.values()
    bad = [f.prompt for f in cfg.FIELDS.values() if not cfg.valid(f, values.get(f.env, f.default))]
    if bad:
        sc.state = "review"
        sc.messages.append({"role": "assistant", "text": "I can't save yet; these values are not valid: "
                            + "; ".join(bad) + ". Fix them on the Configuration page, or start over."})
        return
    path = cfg.save(values)
    cfg.mark_setup_done("chat")
    for key in [k for k in st.session_state if str(k).startswith("cfg_")]:  # Configuration shows the new values
        del st.session_state[key]
    st.session_state.operator = values.get("CACTAI_OPERATOR") or st.session_state.operator
    ai, err = safe(client.ai_reload)
    note = f"Saved to {path}. "
    note += ("The core isn't running, so start SentrAI (run_demo) and every part will use these settings."
             if err else f"I've switched to the new AI settings ({ai.get('chat')}). Restart SentrAI "
                         "(stop_demo, then run_demo) so the other parts pick up the rest.")
    sc.saved(note + " You can change anything later here or on the Configuration page.")


def chat_message(m: dict, assistant: str, by_id: dict[str, dict]) -> None:
    mine = m.get("role") == "operator"
    who = m.get("operator") or st.session_state.operator if mine else assistant
    with st.chat_message("user" if mine else "assistant", avatar="👤" if mine else "🧪"):
        meta = f"**{who}** · {sh.short_time(m.get('ts'))}"
        if m.get("incident"):
            meta += f" · about {m['incident']}"
        if not mine and m.get("source") == "fallback":
            meta += " · core explanation (no AI)"
        st.caption(meta)
        st.markdown(str(m.get("text") or "").replace("\n", "  \n"))  # keep the core's line breaks
        if m.get("looked_at"):
            st.caption("Looked at: " + ", ".join(dict.fromkeys(m["looked_at"])))
        for n, s in enumerate(m.get("suggestions") or []):
            chat_suggestion(m.get("id"), n, s, by_id.get(str(s.get("incident"))))


def chat_suggestion(mid: Any, n: int, s: dict, inc: dict | None) -> None:
    """A suggested decision. Pressing it calls the same endpoints as the Approvals page."""
    if s.get("kind") == "watch_log":
        watch_suggestion(mid, n, s)
        return
    inc_id, decision = str(s.get("incident")), str(s.get("decision"))
    ok, why_not = sh.suggestion_state(inc, decision)
    label = str(s.get("label") or f"{decision} {inc_id}")
    if not ok:
        st.caption(f"💡 Suggested: {label} · {why_not}")
        return
    op = st.session_state.operator
    with st.form(key=f"sugg_{mid}_{n}", border=True):
        st.markdown(f"💡 **Suggested: {html.escape(label)}**")
        just = st.text_input("Justification (written to the audit log)", value=str(s.get("reason") or ""),
                             key=f"sugg_just_{mid}_{n}")
        go_ = st.form_submit_button(f"Confirm: {label}", type="primary" if decision != "reject" else "secondary")
    if not go_:
        return
    just = just.strip()
    if decision == "reject" and not just:
        st.error("Rejecting requires a written justification.")
        return

    def _run() -> None:
        if decision in ("approve", "reject"):
            try:
                client.ack(inc_id, op)
            except CoreError:
                pass
            client.decision(inc_id, op, decision, just)
        elif decision == "ack":
            client.ack(inc_id, op)
        elif decision == "rollback":
            client.rollback(inc_id, op, just or "Rolled back by operator after chat")
        else:
            client.permanent(inc_id, op, just or "Made permanent by operator after chat")

    run_action(label, _run, rerun=False)
    st.cache_data.clear()
    st.rerun()


def watch_suggestion(mid: Any, n: int, s: dict) -> None:
    """A log file Cyanide found in a process scan. Pressing Watch adds it to the collector."""
    label = str(s.get("label") or "Watch log")
    with st.container(border=True):
        st.markdown(f"💡 **Suggested: {html.escape(label)}**")
        if s.get("reason"):
            st.caption(str(s["reason"]))
        if st.button(f"Confirm: {label}", key=f"sugg_{mid}_{n}", type="primary"):
            run_action(label, lambda: client.watch_log(str(s.get("file_id")), st.session_state.operator), rerun=False)
            st.rerun()


@st.fragment(run_every=AUTO)
def page_collector() -> None:
    show_flash()
    if header("Collector", "part 1 · turns raw logs into events and ships them to the core") is None:
        return
    records, _, _ = audit_records()
    agents, _ = fetch("agents", [])
    agents = agents or []
    layer = [a for a in agents if "analyzed" in a]
    watchdog = next((a for a in agents if a.get("name") == "Watchdog"), {})
    collectors = watchdog.get("collectors") or []
    malicious = sh.records_of(records, "event_classified")
    silent = sh.records_of(records, "collector_silent")

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        kpi("Events analysed", str(sum(int(a.get("analyzed") or 0) for a in layer)), "by the layer agents")
    with k2:
        kpi("Malicious events", str(len(malicious)), "attached to incidents",
            sh.BAND_COLORS["critical"] if malicious else None)
    with k3:
        kpi("Collectors", str(len(collectors)), "sending heartbeats")
    with k4:
        kpi("Silent alerts", str(len(silent)), "collector stopped reporting",
            sh.BAND_COLORS["amber"] if silent else None)
    st.write("")

    left, right = st.columns(2)
    with left, st.container(border=True):
        section("Log sources", "from the settings file", "folder_open")
        logs_dir = Path(os.environ.get("CACTAI_LAB_LOGS") or cfg.FIELDS["CACTAI_LAB_LOGS"].default)
        st.caption(f"Folder: {logs_dir}")
        rows = []
        for env in ("CACTAI_LOG_ACCESS", "CACTAI_LOG_AUTH", "CACTAI_LOG_DB", "CACTAI_LOG_OS"):
            path = logs_dir / (os.environ.get(env) or cfg.FIELDS[env].default)
            rows.append({"Log": cfg.FIELDS[env].prompt.replace(" file name", ""), "File": path.name,
                         "Size": f"{path.stat().st_size / 1024:.1f} KB" if path.exists() else "not created yet"})
        extra, _ = safe(client.log_sources, [])
        for x in extra or []:
            rows.append({"Log": f"{x.get('layer', '?')} · {x.get('found_by') or 'Scout'}", "File": x.get("path"),
                         "Size": "watched"})
        table(sh.pd.DataFrame(rows), "")
    with right, st.container(border=True):
        section("Heartbeats", "Watchdog flags a collector that goes quiet", "monitor_heart")
        table(sh.pd.DataFrame([{"Collector": c.get("collector", "-"), "State": "⚠️ silent" if c.get("silent") else "✅ alive",
                                "Last seen": datetime.fromtimestamp(float(c["last_seen_ts"])).strftime("%H:%M:%S")
                                if c.get("last_seen_ts") else "-"} for c in collectors]),
              "No heartbeat received yet. Start the collector.")
        section("Events per layer agent", "", "hub")
        table(sh.pd.DataFrame([{"Agent": a.get("name"), "Events analysed": a.get("analyzed", 0)} for a in layer]),
              "No agent data.")
    scout_proposals()
    log_discovery()
    with st.container(border=True):
        section("Malicious events collected", "newest first", "warning")
        table(sh.classification_rows(records)[["Time", "Event", "Category", "Layer agent", "Incident", "Raw log line"]],
              "No malicious events yet.")


def scout_proposals() -> None:
    """Log files Scout proposed (python -m scout find), waiting for the operator's yes or no."""
    waiting, err = safe(client.pending_log_sources, [])
    if err or not waiting:
        return
    with st.container(border=True):
        section("Scout proposals", "log files Scout found · nothing is watched until you press Watch",
                "travel_explore")
        for p in waiting:
            c1, c2, c3 = st.columns([6, 1, 1])
            c1.markdown(f"**{html.escape(str(p.get('name')))}** · `{p.get('path')}` · {p.get('layer')}  \n"
                        f"<span style='opacity:.7'>{html.escape(str(p.get('why') or ''))}</span>",
                        unsafe_allow_html=True)
            pid = p.get("id")
            for col, approve, label in ((c2, True, "Watch"), (c3, False, "Dismiss")):
                if col.button(label, key=f"scout_{'yes' if approve else 'no'}_{pid}",
                              icon=":material/visibility:" if approve else ":material/close:"):
                    run_action(f"Collector now watches {p.get('name')}" if approve else f"Dismissed {p.get('name')}",
                               lambda a=approve: client.decide_log_source(pid, st.session_state.operator, a),
                               rerun=False)
                    st.rerun()


def log_discovery() -> None:
    """Process scan: the core lists running programs and their log files; the operator picks what to watch."""
    with st.container(border=True):
        section("Find logs on this computer", "read-only scan of running programs · nothing is watched until you "
                                              "press Watch", "travel_explore")
        if st.button("Scan running programs", icon=":material/radar:", key="scan_system"):
            with st.spinner("Scanning running programs…"):
                run_action("Scan finished", lambda: client.scan_system(st.session_state.operator), rerun=False)
        latest, err = safe(client.latest_scan, None)
        if err or not latest or not latest.get("scanned_at"):
            st.caption("No scan yet. Cyanide can also run one when you ask it in Chat.")
            return
        st.caption(f"Last scan {sh.short_time(latest.get('scanned_at'))}: {latest.get('scanned', 0)} processes, "
                   f"{latest.get('recognised', 0)} recognised, {latest.get('skipped_protected', 0)} protected "
                   f"ones skipped.")
        if latest.get("error"):
            st.warning(f"The scan hit a problem: {latest['error']}")
        found = latest.get("suggestions") or []
        known = [s for s in found if s.get("recognised", True)]
        other = [s for s in found if not s.get("recognised", True)]
        if not known:
            empty("No log files found for the programs SentrAI recognises.", "search_off")
        for s in known[:10]:
            scan_suggestion(s)
        if other:
            with st.expander(f"Other log files open by programs SentrAI doesn't recognise ({len(other)})"):
                for s in other[:10]:
                    scan_suggestion(s)
        for note in latest.get("notes") or []:
            st.caption(f"ℹ️ {note}")


def scan_suggestion(s: dict) -> None:
    """One place the scan found logs, with a Watch button per file not yet watched."""
    files = s.get("files") or []
    state = "✅ already watched" if s.get("already_watched") else f"{len(files)} log file(s)"
    st.markdown(f"**{html.escape(str(s.get('program')))}** · `{s.get('path')}` · {s.get('layer')} · {state}  \n"
                f"<span style='opacity:.7'>{html.escape(', '.join(s.get('reasons') or []))}</span>",
                unsafe_allow_html=True)
    for f in files:
        c1, c2 = st.columns([5, 1])
        c1.caption(f"{f.get('name')} · {int(f.get('size') or 0) / 1024:.1f} KB · changed "
                   f"{sh.short_time(f.get('modified'))}")
        if f.get("watched"):
            c2.caption("watched")
        elif c2.button("Watch", key=f"watch_{f.get('id')}", icon=":material/visibility:"):
            run_action(f"Collector now watches {f.get('name')}",
                       lambda fid=f.get("id"): client.watch_log(fid, st.session_state.operator), rerun=False)
            st.rerun()


@st.fragment(run_every=AUTO)
def page_classifier() -> None:
    if header("Classifier", "part 2 · rules, then Jev (AI), then fallback keywords; first answer wins") is None:
        return
    records, _, _ = audit_records()
    agents, _ = fetch("agents", [])
    jev = next((a for a in agents or [] if a.get("name") == "Jev"), {})
    rows = sh.classification_rows(records)
    opened = sh.records_of(records, "incident_opened")

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        kpi("Attacks identified", str(len(opened)), "incidents opened", sh.BAND_COLORS["critical"] if opened else None)
    with k2:
        kpi("Malicious events", str(len(rows)), "classified as an attack")
    with k3:
        by_rules = int((rows["Classified by"] == "Rules").sum()) if not rows.empty else 0
        kpi("Settled by rules", str(by_rules), "confidence 1.0")
    with k4:
        status = str(jev.get("status") or "unknown")
        kpi("Jev (AI)", "off" if status.startswith("disabled") else "on", status.split("(")[0][:48])
    st.write("")

    with st.container(border=True):
        section("Rules in use", "change them on the Configuration page", "rule")
        preset = cfg.preset_label(os.environ.get(cfg.PRESET_ENV, cfg.DEFAULT_PRESET))
        st.markdown(
            f"- Security preset: **{preset}**\n"
            f"- Brute force: **{os.environ.get('BRUTE_FORCE_COUNT', '5')}** failed logins within "
            f"**{os.environ.get('BRUTE_FORCE_WINDOW_S', '60')} s**\n"
            f"- Bulk exfiltration: **{os.environ.get('EXPORT_ROWS_THRESHOLD', '100')}** rows or more in one export\n"
            "- Signatures: SQL injection, XSS, privilege escalation, port scans, misconfiguration")
    with st.container(border=True):
        section("Classifications", "newest first · 0.4-0.6 malicious means needs review, never auto-contained", "label")
        table(rows, "No malicious classifications yet.", column_config={
            "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
            "Malicious": st.column_config.ProgressColumn("Malicious", min_value=0, max_value=1, format="%.2f")})


@st.fragment(run_every=AUTO)
def page_responder() -> None:
    show_flash()
    if header("Action taker", "part 3 · temporary, reversible fixes enforced by the app blocklist") is None:
        return
    records, _, _ = audit_records()
    incidents, _ = fetch("incidents", [])
    blocklist, bl_err = fetch("blocklist", {"ips": [], "users": []})
    containment = sh.build_containment_rows(blocklist, incidents or [])
    history = sh.all_action_rows(incidents or [])

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        kpi("Active containment", str(len(containment)), "in force now", sh.BAND_COLORS["amber"] if len(containment) else None)
    with k2:
        kpi("Blocked IPs", str(len((blocklist or {}).get("ips") or [])), "via GET /blocklist")
    with k3:
        kpi("Locked accounts", str(len((blocklist or {}).get("users") or [])), "via GET /blocklist")
    with k4:
        kpi("Actions taken", str(len(history)), f"expire after {os.environ.get('HOTPATCH_TTL_HOURS', '2')} demo h")
    st.write("")

    with st.container(border=True):
        section("Active containment", "enforced via /blocklist", "block")
        if bl_err:
            st.warning(f"Could not load blocklist: {bl_err}")
        table(containment, "Nothing contained right now.")
    left, right = st.columns([7, 5])
    with left, st.container(border=True):
        section("Action history", "every action is reversible and expires unless a person keeps it", "history")
        table(history, "No actions taken yet.")
    with right, st.container(border=True):
        section("Countersign reviews", "two-key check before any autonomous action", "key")
        render_feed(sh.build_activity_feed(sh.records_of(records, "needle_review", "action_applied",
                                                         "auto_rollback", "action_rolled_back"), limit=15))


@st.fragment(run_every=AUTO)
def page_review() -> None:
    risk = header("Review", "threshold level and the risk accumulated so far")
    if risk is None:
        return
    incidents, inc_err = fetch("incidents", [])
    incidents = incidents or []
    idx, band = risk.get("risk_index"), sh.resolve_band(risk)
    color, threshold = sh.band_color(band), float(risk.get("threshold") or 80)
    active = [i for i in incidents if i.get("status") in sh.ACTIVE_STATUSES]
    penalty = sum(float(i.get("inaction_penalty") or 0) for i in active)

    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        kpi("Risk index", f"{idx if idx is not None else '-'} / 100", f"raw score {risk.get('raw_score', '-')}", color)
    with k2:
        kpi("Threshold", f"{threshold:.0f}", "autonomous containment above this")
    with k3:
        gap = threshold - float(idx or 0)
        kpi("Headroom", f"{gap:.0f}" if gap > 0 else "over", "points until the threshold",
            sh.BAND_COLORS["critical"] if gap <= 0 else None)
    with k4:
        kpi("Open incidents", str(len(active)), f"{len(incidents)} total")
    with k5:
        kpi("Inaction penalty", f"+{penalty:.0f}", "+5 per demo-hour unacknowledged",
            sh.BAND_COLORS["amber"] if penalty else None)
    st.write("")

    g, h = st.columns([5, 7])
    with g, st.container(border=True):
        section("Risk gauge", f"threshold {threshold:.0f} · white line", "speed")
        st.plotly_chart(sh.gauge_figure(idx, threshold, band), width="stretch", config={"displayModeBar": False}, key="gauge")
        st.markdown(f'<div style="text-align:center;margin-top:-.4rem">{pill(sh.BAND_LABELS.get(band, band), color)}</div>',
                    unsafe_allow_html=True)
    with h, st.container(border=True):
        section("Risk over time", "step line · bands green / amber / red / critical", "show_chart")
        hist = sh.history_frame(risk.get("history"))
        if hist.empty:
            empty("No history yet. The core adds a point on every risk change.", "show_chart")
        else:
            st.plotly_chart(sh.history_figure(hist, threshold), width="stretch", config={"displayModeBar": False}, key="history")

    with st.container(border=True):
        section("Risk accumulated", "points = base × confidence × criticality, plus the inaction penalty; "
                "index = 100·(1−e^(−raw/60))", "calculate")
        if inc_err:
            st.warning(f"Could not load incidents: {inc_err}")
        table(sh.risk_breakdown(incidents), "All quiet at the gate. No incidents.", column_config={
            "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
            "Inaction penalty": st.column_config.NumberColumn("Inaction penalty", format="+%.0f pts")})


@st.fragment(run_every=AUTO)
def page_reports() -> None:
    header("Reports", "one evidence report per contained incident · GET /reports/{id}")
    incidents, err = fetch("incidents", [])
    records, _, _ = audit_records()
    with_report = {str((r.get("data") or {}).get("incident")) for r in sh.records_of(records, "report_generated")}
    by_id = {str(i.get("id")): i for i in incidents or [] if i.get("id")}
    if err or not by_id:
        empty("No incidents yet, so no reports.", "description")
        return
    newest = sorted(by_id, key=lambda i: str(by_id[i].get("opened_at") or ""), reverse=True)
    ids = sorted(newest, key=lambda i: i not in with_report)  # ready reports first
    rows = [{"Incident": i, "Category": sh.category_label(by_id[i].get("category")),
             "Report": "✅ ready" if i in with_report else "-"} for i in ids]
    left, right = st.columns([4, 8])
    with left, st.container(border=True):
        section("All incidents", f"{len(with_report & set(by_id))} reports ready", "inventory_2")
        table(sh.pd.DataFrame(rows), "")
    with right, st.container(border=True):
        inc_id = st.selectbox("Open report for", ids, key="report_inc", format_func=lambda i: f"{i} · {sh.category_label(by_id[i].get('category'))}")
        report_viewer(inc_id)


@st.fragment(run_every=AUTO)
def page_audit() -> None:
    if header("Audit trail", "every step by every agent and person, hash-chained") is None:
        return
    records, valid, err = audit_records()
    agents, _ = fetch("agents", [])
    left, right = st.columns([7, 5])
    with left, st.container(border=True):
        badge = (pill("Chain valid", sh.BAND_COLORS["green"]) if valid
                 else pill("Chain broken", sh.BAND_COLORS["critical"]) if valid is False
                 else pill("Chain unknown", sh.UNKNOWN_COLOR))
        section(f"Agent activity &nbsp;{badge}", f"latest {len(records)} hash-chained records", "timeline")
        if err:
            st.warning(f"Could not load audit log: {err}")
        render_feed(sh.build_activity_feed(records, limit=60))
    with right, st.container(border=True):
        section("Agents", "who does what", "groups")
        table(sh.pd.DataFrame([{"Agent": a.get("name"), "Role": a.get("role"),
                                "Can act": "yes" if a.get("can_execute") else "no"} for a in agents or []]),
              "Agent list unavailable.")


def render_feed(feed: list[dict]) -> None:
    if not feed:
        empty("No audit records yet.", "receipt_long")
        return
    rows = []
    for e in feed:
        rows.append(
            f'<div class="feed-row"><div class="feed-time">{html.escape(e["time"])}<br>'
            f'<span class="feed-hash">#{e["seq"] if e["seq"] is not None else "-"}</span></div>'
            f'<div class="feed-rail"><i style="background:{e["color"]}"></i></div>'
            f'<div class="feed-body"><span class="agent" style="color:{e["color"]}">{e["icon"]} {html.escape(e["agent"])}</span>'
            f' · <span class="feed-type">{html.escape(e["type"])}</span><br>'
            f'<span class="feed-sum">{html.escape(e["summary"])}</span> '
            f'<span class="feed-hash">{html.escape(e["hash"])}</span></div></div>'
        )
    st.markdown(f'<div class="feed">{"".join(rows)}</div>', unsafe_allow_html=True)


def report_viewer(inc_id: str) -> None:
    section("Evidence report", f"GET /reports/{inc_id}.md", "verified")
    md, err = safe(lambda: client.report_md(inc_id))
    if err or not md:
        empty("No report for this incident yet. Scribe writes one when autonomous containment fires.", "hourglass_empty")
        return
    d0, d1, d2 = st.columns(3)
    pdf, perr = safe(lambda: client.report_pdf(inc_id))
    if pdf and not perr:
        d0.download_button("PDF", pdf, icon=":material/picture_as_pdf:", help="Download the evidence report as PDF", file_name=f"{inc_id}-evidence-report.pdf",
                           mime="application/pdf", type="primary", width="stretch", key=f"dl_pdf_{inc_id}")
    d1.download_button("Markdown", md, icon=":material/download:", file_name=f"{inc_id}-evidence-report.md",
                       mime="text/markdown", width="stretch", key=f"dl_md_{inc_id}")
    rep_json, jerr = safe(lambda: client.report_json(inc_id))
    if rep_json is not None and not jerr:
        d2.download_button("JSON", json.dumps(rep_json, indent=2), icon=":material/data_object:", file_name=f"{inc_id}-evidence-report.json",
                           mime="application/json", width="stretch", key=f"dl_json_{inc_id}")
    with st.container(height=520, border=True):
        st.markdown(sh.demote_headings(md))


{
    "config": page_config, "approvals": page_approvals, "chat": page_chat, "collector": page_collector, "classifier": page_classifier,
    "responder": page_responder, "review": page_review, "reports": page_reports, "audit": page_audit,
}[st.session_state.page]()
