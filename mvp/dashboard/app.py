"""SentrAI operator dashboard (Streamlit, http://127.0.0.1:8501).

The sidebar is the menu: Approvals, Chat (talk with the orchestrator), one page per part of the
pipeline (Collector, Classifier, Action taker), Review, Reports, Audit trail and Configuration. The
console opens on Approvals when something waits on a person, otherwise on Review. A part's
menu button shows a bubble with the malicious activity that arrived since it was last opened.

Run from this folder:  .venv\\Scripts\\streamlit run app.py
"""
from __future__ import annotations

import hmac
import html
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import streamlit as st

from sentrai_ui import shaping as sh
from sentrai_ui import signin
from sentrai_ui import theme as th
from sentrai_ui.api import READ_ONLY_MESSAGE, CoreClient, CoreError

sys.path.append(str(Path(__file__).resolve().parents[1]))
import sentrai_accounts as acc  # noqa: E402
import sentrai_config as cfg  # noqa: E402
import setup_chat  # noqa: E402

cfg.load()

DEFAULT_CORE = os.environ.get("SENTRAI_CORE_URL", "http://127.0.0.1:8000")
DEFAULT_OPERATOR = os.environ.get("SENTRAI_OPERATOR", "operator")
# The machine list on Review: this computer first, then any other SentrAI cores listed in SENTRAI_PEERS
# ("Office PC=http://10.0.0.5:8000, Web server=https://web:8000"). They share this console's API token.
NODE_NAME = os.environ.get("SENTRAI_NODE_NAME") or "This computer"
PEERS = sh.parse_peers(os.environ.get("SENTRAI_PEERS"))
REFRESH_SECONDS = 2

# Look: Black or White theme plus an accent, picked under Configuration > Appearance and saved with the settings.
LOOK = cfg.appearance()
THEME = LOOK.get("theme") if LOOK.get("theme") in th.THEMES else th.DEFAULT_THEME
ACCENT = LOOK.get("accent") or th.DEFAULT_ACCENT
sh.set_palette(th.chart_colors(THEME))


# SentrAI logo: assets/brand/mark.svg and wordmark.svg, copied into sentrai_ui so the console needs no other folder.
def _logo_svg(name: str) -> str:
    svg = (Path(__file__).parent / "sentrai_ui" / name).read_text(encoding="utf-8")
    svg = re.sub(r'\s*<title>.*?</title>|\s(width|height)="[\d.]+"', "", svg)
    return svg.replace('role="img" aria-label="SentrAI"', 'aria-hidden="true"').replace("\n", "")


BRAND = ('<div class="brand"><div class="brand-mark">' + _logo_svg("mark.svg") + '</div><div>'
         '<div class="brand-name" role="img" aria-label="SentrAI">' + _logo_svg("wordmark.svg") + '</div>'
         '<div class="brand-tag">Risk Console</div></div></div>')
# Tab icon from the brand kit when it is in the checkout, else the emoji.
_FAVICON = Path(__file__).resolve().parents[2] / "assets" / "brand" / "favicon-32.png"
PAGE_ICON = str(_FAVICON) if _FAVICON.exists() else "🛡️"
st.set_page_config(page_title="SentrAI · Risk Console", page_icon=PAGE_ICON, layout="wide",
                   initial_sidebar_state="auto")  # collapsed on a phone, so the page shows first
CSS = (Path(__file__).parent / "sentrai_ui" / "console.css").read_text(encoding="utf-8")
st.markdown(f"<style>{th.font_css()}{th.css(THEME, ACCENT)}{CSS}</style>", unsafe_allow_html=True)
# The "Who gets what" map editor (Incidents page): Streamlit draws it inline, no iframe, from these two
# files. Components v2 came with Streamlit 1.51; an older install shows the routing as tables only.
_UI = Path(__file__).parent / "sentrai_ui"
ROUTING_EDITOR = st.components.v2.component(
    "routing_editor", js=(_UI / "routing_editor.mjs").read_text(encoding="utf-8"),
    css=(_UI / "routing_editor.css").read_text(encoding="utf-8")) if hasattr(st.components, "v2") else None
LIMITS_MAP = st.components.v2.component(
    "limits_map", js=(_UI / "limits_map.mjs").read_text(encoding="utf-8"),
    css=(_UI / "limits_map.css").read_text(encoding="utf-8")) if hasattr(st.components, "v2") else None
FLOW_MAP = st.components.v2.component(
    "flow_map", js=(_UI / "flow_map.mjs").read_text(encoding="utf-8"),
    css=(_UI / "flow_map.css").read_text(encoding="utf-8")) if hasattr(st.components, "v2") else None


def _apply_streamlit_theme() -> bool:
    """Point Streamlit's own theme (buttons, toggles, tables) at the saved look. True when it changed.

    Streamlit sends the theme when a run starts, so a change shows from the next run on."""
    changed = False
    for key, value in th.streamlit_options(THEME, ACCENT).items():
        if st.get_option(key) != value:
            st._config.set_option(key, value)
            changed = True
    return changed


if _apply_streamlit_theme():
    st.rerun()


# ------------------------------------------------------------------ sign-in

def _client_ip() -> str:
    try:
        ip = st.context.ip_address
        forwarded = st.context.headers.get("X-Forwarded-For") or ""
    except Exception:  # noqa: BLE001 - no browser behind this run
        ip, forwarded = None, ""
    return signin.client_address(ip, forwarded)


# ------------------------------------------------------------------ staff report page (no sign-in)

def report_page() -> None:
    """The open page staff use to report something suspicious: <dashboard address>/?report.

    No sign-in, and it shows nothing from SentrAI: it only sends the report (with this console's API
    token) and shows the reporter what to do now. The core caps how often one address may send.
    SENTRAI_REPORT_CODE asks for a shared code first (put it on the staff noticeboard);
    SENTRAI_REPORT_PAGE=off turns the page off.
    """
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown(BRAND, unsafe_allow_html=True)
        if os.environ.get("SENTRAI_REPORT_PAGE", "on").strip().lower() in ("off", "0", "no", "false"):
            st.info("Reporting from this page is turned off. Please tell your IT contact directly.")
            return
        done = st.session_state.get("report_sent")
        if done:
            st.success(f"Thank you. Your report {done['id']} reached the security team.", icon=":material/check_circle:")
            st.markdown(f"**It sounds like:** {html.escape(done.get('kind_label') or 'something to check')}"
                        + (" · **treated as urgent**" if done.get("urgency") == "high" else ""))
            st.markdown("**What to do now**\n\n" + "\n".join(f"1. {html.escape(a)}" for a in done.get("advice") or []))
            st.caption("Someone will look at it and may contact you. If it gets worse, tell your manager or IT contact.")
            if st.button("Report something else", icon=":material/add:"):
                st.session_state.pop("report_sent", None)
                st.rerun()
            return
        st.markdown("### Report something suspicious")
        st.caption("Seen a strange email, a pop-up, a login you didn't make, or a stranger near the computers? "
                   "Tell us in your own words. You don't need to be sure; it is always fine to report.")
        code_needed = os.environ.get("SENTRAI_REPORT_CODE", "").strip()
        core = CoreClient(st.session_state.get("core_url") or DEFAULT_CORE, token=cfg.api_token())
        if "report_machines" not in st.session_state:  # a central panel lists its machines; once per visit
            st.session_state.report_machines = core.machine_names()
        machines = st.session_state.report_machines
        with st.form("staff_report", clear_on_submit=False):
            text = st.text_area("What did you notice?", height=150, max_chars=4000,
                                placeholder="e.g. I got an email from 'IT support' asking me to confirm my password. "
                                            "I clicked the link but did not type anything.")
            a, b = st.columns(2)
            reporter = a.text_input("Your name (optional)", max_chars=120)
            where = b.text_input("Where? (computer, room or account)", max_chars=120,
                                 placeholder="e.g. front desk PC")
            contact = st.text_input("How can we reach you? (optional)", max_chars=120,
                                    placeholder="phone, email or extension")
            host = st.selectbox("Which computer is it about?", ["Not sure", *machines]) if machines else "Not sure"
            code = st.text_input("Report code (on the staff noticeboard)", type="password") if code_needed else ""
            if st.form_submit_button("Send report", type="primary", icon=":material/send:", width="stretch"):
                if code_needed and not hmac.compare_digest(code.strip().encode(), code_needed.encode()):
                    st.error("That report code is not right. Ask your manager for it.")
                elif len(text.strip()) < 10:
                    st.error("Please describe what you saw in a sentence or two.")
                else:
                    try:
                        with st.spinner("Sending..."):
                            sent = core.report_suspicious(text, reporter, contact, where, sender=_client_ip(),
                                                          host="" if host == "Not sure" else host)
                        st.session_state.report_sent = sent
                        st.rerun()
                    except CoreError as exc:
                        if exc.status in (400, 429):
                            st.error(str(exc).split(": ", 1)[-1])
                        else:
                            st.error("The report could not be sent right now. Please tell your IT contact directly.")


if "report" in st.query_params:
    report_page()
    st.stop()


def _base_url() -> str:
    """This console's address as the browser sees it, for invite links."""
    try:
        url = st.context.url
    except Exception:  # noqa: BLE001 - no browser behind this run
        url = None
    return (url or "http://127.0.0.1:8501").split("?")[0].rstrip("/")


def _when(ts: float | None) -> str:
    return datetime.fromtimestamp(ts).strftime("%d %b %Y, %H:%M") if ts else "never"


def _qr_svg(text: str) -> str:
    """The authenticator's QR code as inline SVG ("" when segno is not installed: the key is shown anyway)."""
    try:
        import segno
    except ImportError:
        return ""
    return segno.make(text, error="m").svg_inline(scale=5, border=2, dark="#000000", light="#ffffff")


def _wait_too_long(ip: str) -> bool:
    """Wrong passwords, codes and setup codes all count: 5 from one address, then a wait."""
    wait = signin.wait_seconds(ip)
    if wait:
        st.error(f"Too many wrong tries. Wait {int(wait) // 60 + 1} min and try again.")
    return bool(wait)


def _signed_in(email: str, note: str = "") -> None:
    ip = _client_ip()
    before, where = acc.record_sign_in(email, ip)
    signin.succeeded(ip)
    for key in ("pending", "totp_secret", "recovery_codes"):
        st.session_state.pop(key, None)
    st.session_state.signed_in = email
    st.session_state.flash = (note or f"Last sign-in: {_when(before)}" + (f" from {where}" if where else ""), "🔐")
    # A machine's link (?machine=...) still opens that machine once signed in; anything else (an invite) goes.
    st.query_params.from_dict({k: st.query_params[k] for k in ("machine", "tab") if k in st.query_params})
    st.rerun()


def _new_password_fields() -> tuple[str, str]:
    p1 = st.text_input(f"Password (at least {acc.MIN_PASSWORD} characters)", type="password",
                       autocomplete="new-password")
    p2 = st.text_input("Type it again", type="password", autocomplete="new-password")
    return p1, p2


def _register_owner(box) -> None:
    """A new machine's first screen: the setup code makes this person the Owner."""
    with box.form("register"):
        st.markdown(BRAND, unsafe_allow_html=True)
        st.markdown("#### Create your Owner account")
        st.caption("This machine has no accounts yet. Type the setup code that `python sentrai_config.py admin` "
                   "(on a server: `sudo sentrai-admin`) printed. It works once.")
        code = st.text_input("Setup code", placeholder="ABCD-EFGH-JKLM")
        name = st.text_input("Your name", autocomplete="name")
        email = st.text_input("Email", autocomplete="username")
        p1, p2 = _new_password_fields()
        if st.form_submit_button("Create account", type="primary", width="stretch"):
            ip = _client_ip()
            if _wait_too_long(ip):
                return
            if p1 != p2:
                st.error("The two passwords differ.")
                return
            try:
                owner = acc.register_owner(code, name, email, p1)
            except acc.AccountError as e:
                signin.failed(ip)
                st.error(str(e))
                return
            st.session_state.pending = owner["email"]
            st.rerun()


def _accept_invite(box, code: str, invite: dict) -> None:
    with box.form("invite"):
        st.markdown(BRAND, unsafe_allow_html=True)
        verb = "Set a new password" if invite["reset"] else "Join SentrAI"
        st.markdown(f"#### {verb}")
        st.caption(f"For **{invite['email']}** as **{acc.ROLE_LABEL[invite['role']]}**. "
                   "You'll add an authenticator app next.")
        name = st.text_input("Your name", autocomplete="name") if not invite["reset"] else ""
        p1, p2 = _new_password_fields()
        if st.form_submit_button("Continue", type="primary", width="stretch"):
            if p1 != p2:
                st.error("The two passwords differ.")
                return
            try:
                person = acc.accept_invite(code, name, p1)
            except acc.AccountError as e:
                st.error(str(e))
                return
            st.query_params.clear()
            st.session_state.pending = person["email"]
            st.rerun()


def _password_step(box) -> None:
    with box.form("login"):
        st.markdown(BRAND, unsafe_allow_html=True)
        email = st.text_input("Email", autocomplete="username")
        typed = st.text_input("Password", type="password", autocomplete="current-password")
        if st.form_submit_button("Sign in", type="primary", width="stretch"):
            ip = _client_ip()
            if _wait_too_long(ip):
                return
            person = acc.check_password(email, typed)
            if not person:
                signin.failed(ip)
                st.error("Wrong email or password.")
                return
            st.session_state.pending = person["email"]
            st.rerun()


def _add_authenticator(box, email: str) -> None:
    """Right after the password, for an account without one: scan, then type a code to prove it works."""
    if "totp_secret" not in st.session_state:
        st.session_state.totp_secret = acc.start_authenticator(email)
    secret = st.session_state.totp_secret
    with box.form("enrol"):
        st.markdown(BRAND, unsafe_allow_html=True)
        st.markdown("#### Add an authenticator app")
        st.caption("Every sign-in asks for a 6-digit code from your phone. Scan this with Google Authenticator, "
                   "Microsoft Authenticator, 1Password or any app that takes TOTP codes.")
        qr = _qr_svg(acc.totp_uri(email, secret))
        if qr:
            st.markdown(f'<div style="text-align:center;margin:.4rem 0">{qr}</div>', unsafe_allow_html=True)
        st.caption("Can't scan? Type this key into the app:")
        st.code(" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)), language=None)
        code = st.text_input("6-digit code from the app", max_chars=8, autocomplete="one-time-code")
        if st.form_submit_button("Confirm", type="primary", width="stretch"):
            ip = _client_ip()
            if _wait_too_long(ip):
                return
            try:
                st.session_state.recovery_codes = acc.confirm_authenticator(email, code)
            except acc.AccountError as e:
                signin.failed(ip)
                st.error(str(e))
                return
            st.session_state.pop("totp_secret", None)
            st.rerun()


def _show_recovery_codes(box, email: str) -> None:
    with box.container(border=True):
        st.markdown(BRAND, unsafe_allow_html=True)
        st.markdown("#### Save your recovery codes")
        st.caption("If you lose your phone, each of these signs you in once instead of an app code. "
                   "They are shown only now.")
        codes = st.session_state.recovery_codes
        st.code("\n".join(codes), language=None)
        st.download_button("Download", "\n".join(codes) + "\n", file_name="sentrai-recovery-codes.txt",
                           icon=":material/download:", width="stretch")
        if st.button("I saved them", type="primary", width="stretch"):
            _signed_in(email)


def _code_step(box, email: str) -> None:
    with box.form("code"):
        st.markdown(BRAND, unsafe_allow_html=True)
        st.caption(f"Signing in as {email}")
        code = st.text_input("6-digit code from your authenticator app, or a recovery code",
                             autocomplete="one-time-code")
        ok = st.form_submit_button("Verify", type="primary", width="stretch")
        back = st.form_submit_button("Use another account", width="stretch")
    if back:
        st.session_state.pop("pending", None)
        st.rerun()
    if ok:
        ip = _client_ip()
        if _wait_too_long(ip):
            return
        used = acc.check_second_factor(email, code)
        if not used:
            signin.failed(ip)
            st.error("That code doesn't match. Type the newest code from the app.")
            return
        note = ""
        if used == "recovery":
            note = (f"Recovery code used; {acc.recovery_left(email)} left. To move to a new phone, "
                    "ask an Owner or Admin to reset your sign-in on the Team page.")
        _signed_in(email, note)


def login() -> dict | None:
    """Who is using the console: their account ({email, name, role, ...}), or None with the sign-in off.

    A new machine opens on the register screen (setup code from `sentrai_config.py admin`); an invite
    link (?invite=...) opens the join screen; everyone else signs in with email, password and an
    authenticator code. SENTRAI_DASHBOARD_LOGIN=off skips all of it, for local testing and recordings.
    """
    if not cfg.login_required():
        return None
    if st.session_state.get("signed_in"):
        me = acc.get(st.session_state.signed_in)
        if me and me["authenticator"]:
            return me
        st.session_state.signed_in = False  # removed, or reset by an Admin, since this browser signed in
    _, box, _ = st.columns([1, 1.2, 1])
    pending = st.session_state.get("pending")
    invite_code = st.query_params.get("invite", "")
    if pending and acc.get(pending):
        if "recovery_codes" in st.session_state:
            _show_recovery_codes(box, pending)
        elif not acc.get(pending)["authenticator"]:
            _add_authenticator(box, pending)
        else:
            _code_step(box, pending)
    elif invite_code and (invite := acc.invite_for(invite_code)):
        _accept_invite(box, invite_code, invite)
    elif not acc.has_accounts():
        if acc.setup_code_waiting():
            _register_owner(box)
        else:
            with box.container(border=True):
                st.markdown(BRAND, unsafe_allow_html=True)
                st.warning("No one can sign in yet. On this machine, run `python sentrai_config.py admin` "
                           "(on a server: `sudo sentrai-admin`) for a one-time setup code, then reload this page.")
    else:
        if invite_code:
            box.error("This invite link is wrong or has expired. Ask whoever invited you for a new one.")
        _password_step(box)
    st.stop()


ME = login()
# Sign-in off: a local demo console, so everything is allowed, unless SENTRAI_DASHBOARD_ROLE=auditor (or admin)
# asks to see the console as that role, for checks and screenshots.
ROLE = ME["role"] if ME else (os.environ.get("SENTRAI_DASHBOARD_ROLE", "").strip().lower() or "owner")


def can(permission: str) -> bool:
    return acc.can(ROLE, permission)


def locked(permission: str = "act") -> bool:
    """True when the signed-in role may not do this: the button shows greyed out with the reason."""
    return not can(permission)


def why_locked(permission: str = "act", otherwise: str | None = None) -> str | None:
    return READ_ONLY_MESSAGE if locked(permission) else otherwise


# ------------------------------------------------------------------ helpers

def icon(name: str) -> str:
    """An icon from the bundled Lucide set, by the name sentrai_ui/icons/icons.json lists (works offline)."""
    return f'<span class="mi" aria-hidden="true">{name}</span>'


def pill(text: str, color: str, pulse: bool = False) -> str:
    # Text leans a fifth toward the ink, so a tinted chip still reads at AA on both themes.
    return (f'<span class="chip" style="color:color-mix(in srgb, {color} 78%, var(--ink));'
            f'border-color:{color}55;background:{color}14">'
            f'<span class="dot{" pulse" if pulse else ""}" style="background:{color}"></span>{html.escape(text)}</span>')


def stats(*items: tuple) -> None:
    """One strip of headline numbers: (label, value, note[, colour]). A colour only when the number needs attention."""
    cells = []
    for label, value, sub, *rest in items:
        color = rest[0] if rest else None
        style = f' style="color:{color}"' if color else ""
        cells.append(f'<div class="stat"><div class="stat-label">{html.escape(label)}</div>'
                     f'<div class="stat-value"{style}>{html.escape(value)}</div>'
                     f'<div class="stat-sub">{html.escape(sub) or "&nbsp;"}</div></div>')
    st.markdown(f'<div class="stats" style="--n:{len(cells)}">{"".join(cells)}</div>', unsafe_allow_html=True)


def status(text: str, color: str, pulse: bool = False) -> str:
    """A quiet status line for the page header: a coloured dot and plain text."""
    return (f'<span class="status"><span class="dot{" pulse" if pulse else ""}" style="background:{color}"></span>'
            f'{html.escape(text)}</span>')


def section(title: str, note: str = "", ico: str = "") -> None:
    st.markdown(f'<div class="sec-title">{icon(ico) if ico else ""}{title} <small>{html.escape(note)}</small></div>',
                unsafe_allow_html=True)


def short_path(path) -> str:
    """A path with the home folder as ~, so screenshots don't show whose computer it is."""
    path, home = str(path), str(Path.home())
    return "~" + path[len(home):] if path.startswith(home) else path


def code(text) -> str:
    """Inline code for markdown shown with unsafe_allow_html: a file name can hold a backtick or a tag."""
    return f"<code>{html.escape(str(text))}</code>"


def empty(text: str, ico: str = "inbox", good: bool = False) -> None:
    st.markdown(f'<div class="empty{" good" if good else ""}">{icon(ico)}<span>{html.escape(text)}</span></div>',
                unsafe_allow_html=True)


OK_ICON, WARN_ICON = ":material/check_circle:", ":material/warning:"


def safe(fn, default: Any = None) -> tuple[Any, str | None]:
    try:
        return fn(), None
    except CoreError as exc:
        return default, str(exc)


def run_action(label: str, fn, rerun: bool = True) -> None:
    """Run an operator action, flash the result, and refresh the live fragment immediately."""
    try:
        fn()
        st.session_state["flash"] = (f"{label}", OK_ICON)
    except CoreError as exc:
        st.session_state["flash"] = (f"{label} failed: {exc}", WARN_ICON)
    if rerun:
        st.rerun(scope="fragment")


def show_flash() -> None:
    flash = st.session_state.pop("flash", None)
    if flash:
        st.toast(flash[0], icon=flash[1])




# ------------------------------------------------------------------ data

st.session_state.setdefault("core_url", DEFAULT_CORE)
st.session_state.setdefault("operator", DEFAULT_OPERATOR)
if ME:  # approvals and scans are recorded under the account that made them
    st.session_state.operator = ME["name"]
st.session_state.setdefault("auto_refresh", True)
st.session_state.setdefault("seen", {})
TOKEN = cfg.api_token()
client = CoreClient(st.session_state.core_url, token=TOKEN, read_only=not can("act"))
AUTO = REFRESH_SECONDS if st.session_state.auto_refresh else None
AUDIT_WINDOW = 500  # latest records the dashboard reads; the core still verifies the whole chain


@st.cache_data(ttl=1, show_spinner=False)
def _get(base_url: str, what: str) -> Any:
    c = CoreClient(base_url, token=TOKEN)
    return {"risk": c.risk, "incidents": c.incidents, "blocklist": c.blocklist, "agents": c.agents,
            "machines": c.machines, "fleet": c.fleet_agents, "extensions": c.extensions,
            "audit": lambda: c.audit(AUDIT_WINDOW), "staff": c.staff_reports}[what]()


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


def panel_mode(risk: Any) -> bool:
    """This core is a central panel: it scores each joined machine on its own (SENTRAI_RISK_SCOPE=host)."""
    return isinstance(risk, dict) and risk.get("risk_scope") == "host"


def machines() -> list[dict]:
    """Every SentrAI machine this console watches: on a central panel, the machines that joined it;
    otherwise this computer first, then the cores listed in SENTRAI_PEERS."""
    risk, err = fetch("risk")
    if panel_mode(risk):
        found, _ = fetch("machines", [])
        agents, _ = fetch("fleet", [])
        return sh.panel_machines(found or [], agents or [], risk)
    found = [sh.machine(NODE_NAME, "Local", risk, err)]
    for name, url in PEERS:
        peer, perr = safe(lambda url=url: _get(url, "risk"))
        found.append(sh.machine(name, "Remote", peer, perr))
    return found


# One machine's page has its own address (?machine=web-01&tab=incidents), like a server's page in a game panel.
MACHINE_TABS = {"Overview": "", "Incidents": "incidents", "Blocks": "blocks", "Services": "services",
                "Scans and backups": "scans", "Agent": "agent"}  # tab label: its name in the address


def follow_address() -> None:
    """Keep the page in step with the address bar: a machine's link opens its page (on the tab it names),
    and the browser's Back button, which takes ?machine= out of the address, returns to the machine list."""
    host = st.query_params.get("machine")
    if host:
        st.session_state.page, st.session_state.machine = "machine", host
        slug = st.query_params.get("tab", "")
        st.session_state.machine_tab = next((t for t, s in MACHINE_TABS.items() if s == slug), "Overview")
    elif st.session_state.get("page") == "machine":
        st.session_state.page = "machines"


follow_address()
if "page" not in st.session_state:  # land on what needs a person; a new machine starts with guided setup
    st.session_state.page = sh.start_page(fetch("incidents", [])[0]) if cfg.setup_done() else "chat"


# ------------------------------------------------------------------ menu

PAGES = {  # key: (Material icon, label, menu group)
    "approvals": ("approval_delegation", "Approvals", "Decide"),
    "incidents": ("assignment_ind", "Incidents", "Decide"),
    "staff": ("campaign", "Staff reports", "Decide"),
    "chat": ("forum", "Chat", "Decide"),
    "flow": ("account_tree", "How it works", "Pipeline"),
    "collector": ("input", "Collector", "Pipeline"),
    "classifier": ("category", "Classifier", "Pipeline"),
    "responder": ("shield", "Action taker", "Pipeline"),
    "machines": ("dns", "Machines", "Oversight"),
    "review": ("speed", "Review", "Oversight"),
    "reports": ("description", "Reports", "Oversight"),
    "audit": ("link", "Audit trail", "Oversight"),
    "backups": ("backup", "Backups", "Oversight"),
    "team": ("group", "Team", "Oversight"),  # Owners and Admins, when people sign in
    "extensions": ("extension", "Extensions", "Settings"),
    "config": ("tune", "Configuration", "Settings"),
}


def page_allowed(key: str) -> bool:
    return key != "team" or bool(ME and can("people"))


def go(page: str) -> None:
    st.session_state.page = page
    if st.query_params:  # leaving a machine's page: its address goes too, in one step for the Back button
        st.query_params.clear()
    st.rerun()


def open_machine(host: str, tab: str = "Overview") -> None:
    """Go to one machine's own page; follow_address() sets it up from the new address on the rerun."""
    st.query_params.from_dict({"machine": host, **({"tab": MACHINE_TABS[tab]} if MACHINE_TABS.get(tab) else {})})
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
    chain = ("chain intact", sh.BAND_COLORS["green"]) if valid else ("chain broken", sh.BAND_COLORS["critical"]) \
        if valid is False else ("chain unknown", sh.UNKNOWN_COLOR)
    pct = max(0.0, min(100.0, float(idx or 0)))
    st.markdown(
        f'<div class="side-risk"><div class="row"><span class="lbl">Risk index</span>'
        f'<span class="lbl" style="color:{color}">{html.escape(band.upper())}</span></div>'
        f'<div class="num" style="color:{color}">{idx if idx is not None else "-"}<small> / 100</small></div>'
        f'<div class="bar"><i style="width:{pct:.0f}%;background:{color}"></i><b style="left:{threshold:.0f}%"></b></div>'
        f'<div class="foot"><span>threshold {threshold:.0f}</span>'
        f'<span style="color:{chain[1]}">{icon("link")} {chain[0]}</span></div>'
        + (f'<div class="side-off">{icon("remove_moderator")} Protection off · monitor only</div>' if risk.get("monitor_only") else "")
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
    staff, _ = fetch("staff", {})
    bubbles = {**sh.unseen_counts(records, seen), "approvals": len(sh.pending_approvals(incidents or [])),
               "incidents": sh.board_counts(incidents or [])["overdue"],
               "staff": int(((staff or {}).get("counts") or {}).get("new") or 0)}

    side_risk()
    group = None
    for key, (ico, label, grp) in PAGES.items():
        if not page_allowed(key):
            continue
        if grp != group:
            group = grp
            if grp:
                st.markdown(f'<div class="nav-group">{grp}</div>', unsafe_allow_html=True)
        n = bubbles.get(key, 0)
        text = label + (f"  :red-badge[{n}]" if n else "")
        if st.button(text, key=f"nav_{key}", icon=f":material/{ico}:", width="stretch",
                     type="primary" if key == page or (key, page) == ("machines", "machine") else "secondary"):
            if key in sh.ALERT_TYPES:
                seen[key] = sh.head_seq(records)
            go(key)


with st.sidebar:
    st.markdown(BRAND, unsafe_allow_html=True)
    menu()
    st.markdown('<div class="side-sep"></div>', unsafe_allow_html=True)
    st.toggle(f"Auto-refresh every {REFRESH_SECONDS} s", key="auto_refresh")
    if ME:
        st.caption(f"{ME['name']} · {acc.ROLE_LABEL[ME['role']]}")
        if st.button("Sign out", icon=":material/logout:", width="stretch", help=f"Signed in as {ME['email']}"):
            st.session_state.signed_in = False
            st.rerun()
    st.markdown('<div class="side-foot">A sentry doesn\'t chase you. It just guards the gate.</div>',
                unsafe_allow_html=True)


# ------------------------------------------------------------------ shared page parts

def header(title: str, note: str = "", eyebrow: str = "") -> dict | None:
    """Page title plus the live status chips. Returns /risk, or None when the core is offline.

    The risk number lives in the sidebar card only, so each screen says it once."""
    risk, err = fetch("risk")
    now_s = datetime.now().strftime("%H:%M:%S")
    ico, _, group = PAGES.get(st.session_state.page, PAGES["machines"])
    if err or not isinstance(risk, dict):
        chips = status("Core offline", sh.BAND_COLORS["critical"])
    else:
        _, valid, _ = audit_records()
        chips = ((status("Log chain intact", sh.BAND_COLORS["green"]) if valid
                    else status("Log chain broken", sh.BAND_COLORS["critical"]) if valid is False
                    else status("Log chain unknown", sh.UNKNOWN_COLOR)))
        if risk.get("monitor_only"):
            chips = status("Protection off", sh.BAND_COLORS["amber"]) + chips
    chips += status(f"Live {now_s}" if AUTO else f"Paused {now_s}", sh.BAND_COLORS["green"] if AUTO else sh.UNKNOWN_COLOR,
                    pulse=bool(AUTO))
    st.markdown(
        f'<div class="page-head"><div class="page-title">'
        f'<div class="eyebrow">{icon(ico)} {html.escape(eyebrow or group)}</div><h1>{html.escape(title)}</h1>'
        f'<div class="page-note">{html.escape(note)}</div></div>'
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
    kept = f" {sh.plural(left, 'action')} already in force stay until they expire or are rolled back." if left else ""
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


def severity_color(inc: dict) -> str:
    return {"low": sh.BAND_COLORS["green"], "medium": sh.BAND_COLORS["amber"], "high": sh.BAND_COLORS["red"],
            "critical": sh.BAND_COLORS["critical"]}.get(str(inc.get("severity")), sh.UNKNOWN_COLOR)


def incident_summary(inc: dict) -> None:
    inc_id = str(inc.get("id"))
    sev_color = severity_color(inc)
    st.markdown(
        f'<div class="inc-head">'
        f'<span class="inc-id">{html.escape(inc_id)}</span>'
        f'{pill(str(inc.get("severity", "unknown")).capitalize() + " severity", sev_color)}'
        f'{pill(sh.status_label(inc.get("status")), sh.TEXT_SECONDARY)}'
        + (pill("SLA breached", sh.BAND_COLORS["critical"]) if inc.get("sla_breached") else "")
        + (pill(f"Seen by {inc.get('acked_by')}", sh.BAND_COLORS["green"]) if inc.get("acked")
           else pill("Not acknowledged", sh.BAND_COLORS["amber"]))
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
    rep = inc.get("reputation") or {}
    if rep and not rep.get("error"):  # AbuseIPDB: context for the person deciding, not evidence
        seen = f"reported {sh.plural(rep.get('reports', 0), 'time')} by others, {rep.get('score', 0)}% abuse confidence"
        where = " · ".join(re.sub(r"[\[\]()*_`<>#|~\\$]", "", str(x)) for x in (rep.get("isp"), rep.get("country")) if x)
        st.caption(f":material/travel_explore: AbuseIPDB: {seen}" + (f" · {where}" if where else "")
                   + (" · Tor exit node" if rep.get("tor") else ""))
    st.markdown(f'<div class="reco">{icon("tips_and_updates")}<div><b>Recommended action</b>'
                f'{html.escape(str(inc.get("recommended_action") or "-"))}</div></div>',
                unsafe_allow_html=True)
    st.write("")


def decision_controls(inc: dict, where: str = "") -> None:
    """Approve / reject an open incident, or keep / roll back a contained one."""
    if locked():
        st.caption(f":material/visibility: {READ_ONLY_MESSAGE}")
        return
    inc_id = str(inc.get("id"))
    kid = f"{where}{inc_id}"  # the same incident can be open in two places on a page
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
        if can["ack"] and st.button("Acknowledge", icon=":material/visibility:", key=f"ack_{kid}",
                                    help="Records that you have seen this alert (POST /ack)"):
            run_action(f"Acknowledged {inc_id}", lambda: client.ack(inc_id, op))
        with st.form(key=f"decide_{kid}", clear_on_submit=True, border=True):
            just = st.text_area("Justification (required to reject, written to the audit log)", key=f"just_{kid}",
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
        with st.form(key=f"contain_{kid}", clear_on_submit=True, border=True):
            just = st.text_area("Justification (written to the audit log)", key=f"cjust_{kid}", height=70,
                                placeholder="e.g. Verified attacker; keep the block")
            sure = st.checkbox("Keep this block forever. It will no longer expire on its own.", key=f"sure_{kid}")
            c1, c2 = st.columns(2)
            # Rollback is the safe default, so it gets the filled style; the permanent choice needs the tick above.
            rb = c1.form_submit_button("Roll back", icon=":material/undo:", type="primary", width="stretch")
            perm = c2.form_submit_button("Make permanent", icon=":material/push_pin:", width="stretch")
        if rb:
            run_action(f"Rolled back {inc_id}",
                       lambda: client.rollback(inc_id, op, just.strip() or "Rolled back by operator from dashboard"))
        elif perm and not sure:
            st.error("Tick \"Keep this block forever\" first. Nothing was changed.")
        elif perm:
            run_action(f"Made permanent {inc_id}",
                       lambda: client.permanent(inc_id, op, just.strip() or "Made permanent by operator from dashboard"))
    else:
        st.caption(f"No operator action available (status: {inc.get('status')}).")


def quick_actions(inc: dict, where: str) -> None:
    """The one or two buttons an incident row needs. Justification is optional here, and the full form is in Details."""
    inc_id, op = str(inc.get("id")), st.session_state.operator
    can, off, ro = sh.available_actions(inc), locked(), why_locked()
    k = f"{where}_{inc_id}"
    c1, c2 = st.columns(2)
    if can["decide"]:
        no_patch = protection_off()
        if c1.button("Approve", icon=":material/check:", type="primary", key=f"qa_{k}", width="stretch",
                     disabled=off or no_patch,
                     help=ro or ("Protection is off (monitor only): turn it on in Configuration to apply a hotpatch."
                                 if no_patch else "Approve & patch, written to the audit log")):
            def _approve() -> None:
                if can["ack"]:
                    client.ack(inc_id, op)
                client.decision(inc_id, op, "approve", "")
            run_action(f"Approved & patched {inc_id}", _approve)
        with c2.popover("Reject", icon=":material/block:", width="stretch", disabled=off, help=ro):
            just = st.text_input("Why (required, written to the audit log)", key=f"qrj_{k}",
                                 placeholder="e.g. False positive: our penetration tester")
            if st.button("Reject", key=f"qr_{k}", width="stretch", disabled=not just.strip()):
                def _reject() -> None:
                    if can["ack"]:
                        client.ack(inc_id, op)
                    client.decision(inc_id, op, "reject", just.strip())
                run_action(f"Rejected {inc_id}", _reject)
    elif can["contain_controls"]:
        # Rollback is the safe default, so it is one click; keeping a block forever asks once more.
        if c1.button("Roll back", icon=":material/undo:", type="primary", key=f"qb_{k}", width="stretch",
                     disabled=off, help=ro or "Undo the block now"):
            run_action(f"Rolled back {inc_id}",
                       lambda: client.rollback(inc_id, op, "Rolled back by operator from dashboard"))
        with c2.popover("Make permanent", icon=":material/push_pin:", width="stretch", disabled=off, help=ro):
            st.caption("The block will no longer expire on its own.")
            just = st.text_input("Why (optional, written to the audit log)", key=f"qpj_{k}",
                                 placeholder="e.g. Verified attacker")
            if st.button("Keep this block forever", key=f"qp_{k}", type="primary", width="stretch"):
                run_action(f"Made permanent {inc_id}", lambda: client.permanent(
                    inc_id, op, just.strip() or "Made permanent by operator from dashboard"))
    elif can["ack"]:
        if c1.button("Acknowledge", icon=":material/visibility:", key=f"qk_{k}", width="stretch", disabled=off,
                     help=ro or "Records that you have seen this alert"):
            run_action(f"Acknowledged {inc_id}", lambda: client.ack(inc_id, op))


def incident_row(inc: dict, where: str, note: str = "", details=None) -> None:
    """One short line per incident with its quick buttons; everything else waits behind Details."""
    with st.container(border=True):
        a, b = st.columns([3, 2], vertical_alignment="center")
        sev = str(inc.get("severity") or "unknown").capitalize()
        a.markdown(
            f'<div class="inc-row"><div class="inc-head">'
            f'<span class="inc-id">{html.escape(str(inc.get("id")))}</span>{pill(sev, severity_color(inc))}'
            f'<b>{html.escape(sh.category_label(inc.get("category")))}</b></div>'
            f'<div class="inc-sub">{html.escape(sh.incident_target(inc))} · {sh.incident_contribution(inc)} pts'
            + (f' · {html.escape(note)}' if note else "") + '</div></div>',
            unsafe_allow_html=True)
        with b:
            quick_actions(inc, where)
        if details is not None:
            with st.expander("Details", icon=":material/info:"):
                details()


# ------------------------------------------------------------------ pages

def matches(query: str, *texts: str) -> bool:
    """Every word of the search appears somewhere in the texts (case-insensitive)."""
    hay = " ".join(texts).lower()
    return all(word in hay for word in query.lower().split())


class fold:
    """A settings group: a closed expander normally, an open card while searching (so the hits show)."""

    def __init__(self, title: str, searching: bool, ico: str = "") -> None:
        self.title, self.searching, self.ico = title, searching, ico

    def __enter__(self):
        self.box = st.container(border=True) if self.searching else st.expander(self.title)
        self.box.__enter__()
        if self.searching:
            section(self.title, ico=self.ico)
        return self

    def __exit__(self, *exc):
        return self.box.__exit__(*exc)


APPEARANCE_WORDS = "appearance look theme colour color accent black white dark light mono violet blue custom logo"


def page_config() -> None:
    header("Configuration", f"Saved to {short_path(cfg.config_path())} · read by every part when it starts")
    o1, o2 = st.columns([4, 1], vertical_alignment="center")
    query = o1.text_input("Search settings", key="cfg_search", icon=":material/search:", label_visibility="collapsed",
                          placeholder="Search settings: telegram, threshold, password, theme...").strip()
    if o2.button("Set up with Cyanide", icon=":material/forum:", width="stretch",
                 help="Rather answer a few questions? Cyanide walks you through setup in the Chat page."):
        start_setup()
    # Unsaved edits survive a search hiding their field (Streamlit forgets a widget it does not draw).
    draft = st.session_state.setdefault("cfg_draft", {})
    current = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read() | draft
    values, shown = dict(current), 0

    if not query or matches(query, APPEARANCE_WORDS):
        shown += 1
        with st.container(border=True):
            section("Appearance", "Saved at once, for everyone who opens this console", "palette")
            appearance_settings()

    preset = cfg.SECTIONS[0]
    preset_words = [preset.title, preset.about, "protection monitor only"] + \
        [f"{cfg.FIELDS[e].prompt} {e}" for e in cfg.PRESET_FIELDS] + [p.label for p in cfg.PRESETS.values()]
    if not query or matches(query, *preset_words):
        shown += 1
        with st.container(border=True):
            section(preset.title, preset.about, "verified_user")
            values |= preset_settings(current)
            protection_switch()

    if not query or matches(query, "Dashboard core api url operator name approvals"):
        shown += 1
        with fold("Dashboard", bool(query), "dashboard"):
            st.caption("This browser session only.")
            c1, c2 = st.columns(2)
            # Own widget keys: Streamlit drops a widget's state when you leave the page.
            st.session_state.core_url = c1.text_input("Core API URL", value=st.session_state.core_url).strip()
            if ME:
                c2.text_input("Operator name (recorded on your approvals)", value=ME["name"], disabled=True,
                              help="Your account's name. Everything you approve is recorded under it.")
            else:
                st.session_state.operator = c2.text_input("Operator name (recorded on your approvals)",
                                                          value=st.session_state.operator).strip() or "operator"
    for s in cfg.SECTIONS[1:]:
        fields = [f for f in s.fields if f.env not in cfg.PRESET_FIELDS]  # those live under the preset
        whole = not query or matches(query, s.title, s.about)
        if s.key == "ai":  # one panel: provider, key, model and the connection test belong together
            if whole or any(matches(query, f.prompt, f.env) for f in s.fields):
                shown += 1
                with fold(s.title, bool(query), "smart_toy"):
                    st.caption(s.about)
                    values |= ai_settings(current)
            continue
        hits = fields if whole else [f for f in fields if matches(query, f.prompt, f.env)]
        if not hits:
            continue
        shown += 1
        with fold(s.title, bool(query), "tune"):
            st.caption(s.about)
            if len(fields) < len(s.fields) and whole:
                st.caption("Detection and response values are set under Security preset.")
            cols = st.columns(2)
            for n, f in enumerate(hits):
                if f.generated:  # shown, never edited here: every part must restart with the same value
                    cols[n % 2].text_input(f.prompt, value=current[f.env], key=f"cfg_{f.env}", type="password",
                                           disabled=True, help=f"Environment variable {f.env}. Generated by setup; "
                                           "python sentrai_config.py token prints it.")
                    continue
                values[f.env] = cols[n % 2].text_input(
                    f.prompt, value=current[f.env], key=f"cfg_{f.env}", help=f"Environment variable {f.env}",
                    type="password" if f.secret else "default").strip()
    shown += extension_settings(query, current, values)
    if not shown:
        st.markdown(f'<div class="search-none">{icon("search_off")} No setting matches "{html.escape(query)}". '
                    'Try a shorter word, like "email", "block" or "key".</div>', unsafe_allow_html=True)
    saved = cfg.read()
    draft.update({env: v for env, v in values.items() if env in cfg.FIELDS and v != saved.get(env, cfg.FIELDS[env].default)})
    for env in [e for e in draft if values.get(e) == saved.get(e, cfg.FIELDS[e].default)]:
        draft.pop(env)  # changed back by hand
    if st.button("Save settings", icon=":material/save:", type="primary", disabled=not can("configure"),
                 help=None if can("configure") else "Auditors can read the settings but not change them."):
        bad = [f.prompt for f in cfg.FIELDS.values() if not cfg.valid(f, values[f.env])]
        if bad:
            st.error("Please enter a number for: " + "; ".join(bad))
        else:
            path = cfg.save(values)
            draft.clear()
            cfg.mark_setup_done("dashboard")
            ai, err = safe(client.ai_reload)
            if err:
                st.success(f"Saved to {path}. Start SentrAI (run.ps1 or run.sh) so the core picks them up.")
            else:
                _, ext_err = safe(client.reload_extensions)  # new keys and tokens take effect now
                st.success(f"Saved to {path}. Cyanide switched to the new AI settings ({ai.get('chat')})"
                           + ("" if ext_err else " and the extensions use theirs now")
                           + ". Restart SentrAI (stop, then run) for the other settings.")


def extension_settings(query: str, current: dict[str, str], values: dict[str, str]) -> int:
    """Each added extension's settings, from its extension.json. One that is not added shows up when a search
    finds it, with a word on what saving does. Returns how many sections it drew."""
    rows, _ = safe(client.extensions, None)
    by_name = {r.get("name"): r for r in rows or [] if not r.get("built_in")}
    drawn = 0
    for name, s in cfg.EXTENSION_SECTIONS.items():
        row = by_name.get(name)
        on = bool(row.get("added")) if row else any(current.get(e) for e in s.on_when)  # core away: the settings rule
        if query:
            hits = list(s.fields) if matches(query, s.title, s.about, "extension") else \
                [f for f in s.fields if matches(query, f.prompt, f.env)]
        else:
            hits = list(s.fields) if on else []
        if not hits:
            continue
        drawn += 1
        with fold(f"{s.title} extension", bool(query), "extension"):
            st.caption(s.about)
            if not on:
                by = (row or {}).get("added_by")
                st.caption(":material/info: " + (
                    "Off: the server's SENTRAI_EXTENSIONS decides which extensions are on." if by == "SENTRAI_EXTENSIONS"
                    else "Removed on the Extensions page. Its settings are kept; add it there to use them."
                    if by == "dashboard" else "Not added yet. Saving its key turns it on."))
            plain, advanced = [f for f in hits if not f.advanced], [f for f in hits if f.advanced]
            for group, label in ((plain, ""), (advanced, "Advanced")):
                if not group:
                    continue
                if label:
                    st.caption(label)
                cols = st.columns(2)
                for n, f in enumerate(group):
                    values[f.env] = setting_input(cols[n % 2], f, current)
    return drawn


def setting_input(col, f, current: dict[str, str]) -> str:
    """One setting's widget: a list when it has choices, a box otherwise (hidden for a key or token)."""
    tip = f"Environment variable {f.env}"
    if f.choices:
        value = current.get(f.env) or f.default
        options = list(f.choices) if value in f.choices else [value, *f.choices]
        return col.selectbox(f.prompt, options, index=options.index(value), key=f"cfg_{f.env}", help=tip)
    return col.text_input(f.prompt, value=current[f.env], key=f"cfg_{f.env}", help=tip,
                          type="password" if f.secret else "default").strip()


def _save_look() -> None:
    if not can("configure"):
        return
    accent = st.session_state.look_accent
    if accent == th.CUSTOM:
        accent = th.parse_hex(st.session_state.get("look_custom", "")) or th.ACCENTS["violet"][1]
    cfg.save_appearance(st.session_state.look_theme, accent)


def appearance_settings() -> None:
    """Black or White, and the accent colour: Mono, a preset, or any colour from the picker."""
    custom = th.parse_hex(ACCENT) if ACCENT not in th.ACCENTS else None
    c1, c2, c3 = st.columns([1.1, 1.6, 1], vertical_alignment="bottom")
    c1.segmented_control("Theme", list(th.THEMES), key="look_theme", default=THEME, required=True,
                         format_func=lambda k: th.THEMES[k].label, on_change=_save_look)
    accents = [*th.ACCENTS, th.CUSTOM]
    c2.segmented_control("Accent colour", accents, key="look_accent", default=th.CUSTOM if custom else
                         (ACCENT if ACCENT in th.ACCENTS else th.DEFAULT_ACCENT), required=True,
                         format_func=lambda k: th.ACCENTS[k][0] if k in th.ACCENTS else "Custom",
                         on_change=_save_look,
                         help="Mono uses white on Black and black on White. Violet is the logo's colour.")
    if st.session_state.get("look_accent") == th.CUSTOM:
        c3.color_picker("Custom colour", value=custom or th.ACCENTS["violet"][1], key="look_custom",
                        on_change=_save_look)
    p = th.palette(THEME, ACCENT)
    warn = th.risk_like(th.accent_hex(ACCENT))
    st.markdown(
        f'<div class="preview"><div class="brand-mark" style="width:2rem;height:2rem">{_logo_svg("mark.svg")}</div>'
        f'<span class="btn">Approve block</span><span class="soft">Selected</span>'
        f'<span class="lnk">A link</span>'
        f'<span style="margin-left:auto;font-size:.8rem;color:var(--ink-muted)">accent {p["brand-fill"]} · '
        f'risk colours stay green / amber / red</span></div>', unsafe_allow_html=True)
    if warn:
        st.caption(f"This colour looks like the {warn} risk colour, so buttons may read as alerts. "
                   "A blue, violet or neutral accent keeps them apart.")


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
            st.session_state["flash"] = ("Protection is on" if on else "Protection is off: monitor-only mode", OK_ICON)
        except CoreError as exc:
            st.session_state["flash"] = (f"Could not switch protection: {exc}", WARN_ICON)
        _get.clear()
        st.rerun()

    if p.get("monitor_only"):
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        c1.markdown(f'{pill("Protection off", sh.BAND_COLORS["amber"])} Monitor only: incidents are scored '
                    f'and alerted, nothing is blocked.', unsafe_allow_html=True)
        if c2.button("Turn protection on", icon=":material/shield:", type="primary", width="stretch", disabled=locked(),
                     help=why_locked(otherwise="Incidents already over the threshold are contained right away.")):
            switch(True)
        return
    c1, c2 = st.columns([3, 1], vertical_alignment="bottom")
    reason = c1.text_input("Protection is on. To test without blocking anything, turn it off (monitor only).",
                           key="protect_reason", placeholder="Reason, recorded in the audit trail (required)",
                           help="POST /protection. SentrAI keeps collecting, classifying and scoring, but applies "
                                "no containment, autonomous or approved, until it is turned back on.")
    if c2.button("Turn protection off", icon=":material/remove_moderator:", width="stretch", disabled=locked(), help=why_locked()):
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
                                help="Environment variable SENTRAI_PRESET. A preset fills in the values below; "
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
    keys = {env: f"cfg_{env}" for env in ("SENTRAI_LLM_PROVIDER", "SENTRAI_LLM_API_KEY", "SENTRAI_LLM_BASE_URL",
                                          cfg.MODEL_ENV)}
    for env, key in keys.items():  # widgets take their start value from session state, so a pick can fill the model
        st.session_state.setdefault(key, current[env])
    c1, c2 = st.columns(2)
    provider = c1.selectbox("Provider", cfg.sentrai_llm.PROVIDERS, key=keys["SENTRAI_LLM_PROVIDER"],
                            format_func=lambda p: cfg.sentrai_llm.LABEL[p],
                            help="Environment variable SENTRAI_LLM_PROVIDER")
    api_key = c2.text_input("API key", key=keys["SENTRAI_LLM_API_KEY"], type="password",
                            help="Environment variable SENTRAI_LLM_API_KEY. Leave blank to run on fixed playbooks.").strip()
    if provider == "compatible":
        base_url = st.text_input("Base URL", key=keys["SENTRAI_LLM_BASE_URL"], placeholder="https://llm.example.com/v1",
                                 help="Environment variable SENTRAI_LLM_BASE_URL").strip()
    else:
        base_url = st.session_state[keys["SENTRAI_LLM_BASE_URL"]].strip()
        st.caption(f"Endpoint: {base_url or cfg.sentrai_llm.BASE_URL.get(provider, '')}")

    default = cfg.sentrai_llm.DEFAULT_MODEL.get(provider) or "none, type one"
    m1, m2 = st.columns([3, 1], vertical_alignment="bottom")
    model = m1.text_input("Model", key=keys[cfg.MODEL_ENV], placeholder=f"blank for the default ({default})",
                          help="Environment variable SENTRAI_LLM_MODEL; a value set in the environment "
                               "before SentrAI starts wins over this one.").strip()
    ai = {"SENTRAI_LLM_PROVIDER": provider, "SENTRAI_LLM_API_KEY": api_key, "SENTRAI_LLM_BASE_URL": base_url,
          cfg.MODEL_ENV: model}
    if m2.button("Fetch models", icon=":material/refresh:", width="stretch", disabled=not api_key,
                 help="Ask the provider which models this key can use"):
        with st.spinner("Asking the provider for its models..."):
            try:
                st.session_state.ai_models = (provider, cfg.fetch_models(ai), None)
            except cfg.sentrai_llm.LLMError as exc:
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
        t1.caption("Cyanide: core not running, so this can't show what it uses. Start SentrAI (run.sh or run.ps1) to test through it.")
    elif now.get("online"):
        t1.caption(f"Cyanide now: :green[:material/radio_button_checked: online] · {now.get('provider')} · {now.get('model')}"
                   f" · key from {now.get('key_source') or 'unknown'}")
    else:
        t1.caption(f"Cyanide now: :red[:material/radio_button_unchecked: offline] · {now.get('off_reason') or now.get('chat')}")
    body = {"provider": ai["SENTRAI_LLM_PROVIDER"], "api_key": ai["SENTRAI_LLM_API_KEY"],
            "base_url": ai["SENTRAI_LLM_BASE_URL"], "model": ai[cfg.MODEL_ENV]}
    if t2.button("Test connection", icon=":material/power:", width="stretch", disabled=bool(err),
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


EXTENSIONS_GUIDE = "https://rexguard.github.io/SentrAI/docs/extensions.html"
NOT_SET = sh.UNKNOWN_COLOR
EXTENSION_GROUPS = (("added", "Added", "extension", "on now: each one works while SentrAI runs"),
                    ("available", "Available", "add_circle", "installed but not added: add one to use it"),
                    ("built_in", "Built in", "deployed_code", "part of SentrAI itself, so always there"))


def page_extensions() -> None:
    show_flash()
    if header("Extensions", "Outside services SentrAI works with · add or remove each one while SentrAI runs") is None:
        return
    rows, err = safe(client.extensions, [])
    if err:
        st.warning(f"Could not ask the core which extensions are added: {err}")
        return
    ext = [r for r in rows if not r.get("built_in")]
    added = [r for r in ext if r.get("added")]
    problems = [r for r in rows if r.get("added") and (r.get("last_error") or r.get("error"))]
    edge = next((r for r in ext if r.get("name") == "cloudflare"), {})
    stats(("Added", f"{len(added)} of {len(ext)}", "extensions on"),
          ("Edge blocking", "On" if edge.get("added") and edge.get("configured") else "Off",
           "Cloudflare blocks what SentrAI blocks"),
          ("Problems", str(len(problems)), "last call failed" if problems else "none",
           sh.BAND_COLORS["amber"] if problems else None))
    managed = any(r.get("added_by") == "SENTRAI_EXTENSIONS" for r in ext)
    if managed:
        st.info("The server's SENTRAI_EXTENSIONS setting decides which extensions are on, so they cannot be "
                "added or removed here. Change it where SentrAI is started, then restart it.",
                icon=":material/lock:")
    results = st.session_state.setdefault("integration_tests", {})
    groups = {"added": added, "available": [r for r in ext if not r.get("added")],
              "built_in": [r for r in rows if r.get("built_in")]}
    for key, title, ico, note in EXTENSION_GROUPS:
        group = groups[key]
        if not group:
            continue
        section(title, note, ico)
        cols = st.columns(2)
        for n, r in enumerate(group):
            with cols[n % 2], st.container(border=True):
                extension_card(r, results, managed)
    st.caption("Removing an extension keeps its settings, so adding it back restores it. Installing one means "
               "putting its folder in mvp/extensions (or a folder named in SENTRAI_EXTENSIONS_DIR) and restarting "
               f"SentrAI; deleting the folder uninstalls it. See the [extensions guide]({EXTENSIONS_GUIDE}).")


def extension_chip(r: dict) -> str:
    trouble = r.get("error") or r.get("last_error")
    if r.get("built_in"):
        return pill("Built in", sh.BAND_COLORS["green"] if r.get("configured") else NOT_SET)
    if not r.get("added"):
        return pill("Available", NOT_SET)
    if trouble:
        return pill("Problem", sh.BAND_COLORS["amber"])
    return pill("Added", sh.BAND_COLORS["green"]) if r.get("configured") else pill("Not set up", sh.BAND_COLORS["amber"])


def removal_note(r: dict) -> str:
    """What removing it will do, said before the person confirms."""
    title = r.get("title") or r["name"]
    what = {"Blocking": f"Blocks it added at {title} are taken out there again; SentrAI's own blocks stay.",
            "Alerts": f"Alerts stop going to {title} within 15 seconds; the console and email still get them.",
            "Classifier": f"Events are classified by the rules and the keyword fallback, without {title}.",
            "Lookups": f"New incidents get no {title} lookups; what earlier ones show stays."}.get(r.get("kind"), "")
    return f"{what} Its settings are kept, so adding it back restores it.".strip()


def removed_message(r: dict, out: dict) -> tuple[str, str]:
    title = r.get("title") or r["name"]
    cleanup = out.get("cleanup") or {}
    left = cleanup.get("left_in_place") or []
    if left:
        where = ", ".join(str(x.get("target")) for x in left[:3])
        return (f"Removed {title}, but {sh.plural(len(left), 'block')} could not be taken out of it ({where}). "
                "Remove them there by hand: each incident's timeline says which.", WARN_ICON)
    gone = cleanup.get("released") or 0
    return (f"Removed {title}" + (f". It took {sh.plural(gone, 'block')} out of {title}." if gone else "."), OK_ICON)


def extension_card(r: dict, results: dict, managed: bool) -> None:
    name, title = r["name"], r.get("title") or r["name"]
    trouble = r.get("error") or r.get("last_error")
    kind = html.escape(str(r.get("kind") or ""))
    st.markdown(f'<div class="sec-title">{html.escape(title)} {extension_chip(r)} <small>{kind}</small></div>',
                unsafe_allow_html=True)
    st.write(r.get("what") or "")
    st.caption(r.get("detail") or "")
    if trouble and (r.get("added") or r.get("built_in")):
        st.caption(f":orange[:material/warning:] {trouble}")
    if r.get("changed_by") and r.get("added_by") == "dashboard":
        st.caption(f"{'Added' if r.get('added') else 'Removed'} by {r['changed_by']}, {sh.day_time(r.get('changed_at'))}")
    in_config = any(f in cfg.FIELDS for f in r.get("settings") or [])
    no_change = None if not managed else "The server's SENTRAI_EXTENSIONS decides which extensions are on."
    slots = iter(st.columns(4))  # buttons fill from the left, so a card without a test has no gap
    if not r.get("built_in"):
        b = next(slots)
        if not r.get("added"):
            if b.button("Add", key=f"add_{name}", icon=":material/add:", type="primary", width="stretch",
                        disabled=managed or locked("configure"), help=no_change or why_locked("configure",
                        f"Turn {title} on now. It uses the settings saved for it.")):
                out, add_err = safe(lambda: client.add_extension(name, st.session_state.operator))
                st.session_state["flash"] = ((f"Could not add {title}: {add_err}", WARN_ICON) if add_err else
                                             (f"Added {title}" + ("" if (out or {}).get("configured") else
                                              ". Save its settings on the Configuration page to set it up."), OK_ICON))
                _get.clear()
                st.rerun()
        elif b.button("Remove", key=f"remove_{name}", icon=":material/remove:", width="stretch",
                      disabled=managed or locked("configure"),
                      help=no_change or why_locked("configure", f"Turn {title} off. Its settings are kept.")):
            st.session_state["confirm_remove"] = name
    if r.get("testable") and r.get("added"):
        if next(slots).button("Test", key=f"test_{name}", icon=":material/power:", width="stretch",
                              disabled=locked("configure"),
                              help=why_locked("configure", "One harmless call to the service with the saved key")):
            with st.spinner(f"Testing {title}..."):
                out, test_err = safe(lambda: client.test_extension(name))
            results[name] = out if not test_err else {"ok": False, "error": test_err}
    if in_config and next(slots).button("Settings", key=f"set_{name}", icon=":material/tune:", width="stretch"):
        st.session_state.cfg_search = str(title).split()[0].lower()
        go("config")
    if r.get("docs"):
        next(slots).link_button("How to set up", r["docs"], icon=":material/open_in_new:", width="stretch")
    if not in_config and r.get("settings"):
        st.caption("Set with environment variables: " + ", ".join(f"`{f}`" for f in r.get("settings") or []))
    if st.session_state.get("confirm_remove") == name and r.get("added"):
        with st.container(border=True):
            st.markdown(f"**Remove {html.escape(title)}?** {html.escape(removal_note(r))}")
            c1, c2 = st.columns(2)
            if c1.button(f"Remove {title}", key=f"remove_yes_{name}", icon=":material/remove:", type="primary",
                         width="stretch", disabled=managed or locked("configure")):
                st.session_state.pop("confirm_remove", None)
                out, rm_err = safe(lambda: client.remove_extension(name, st.session_state.operator))
                st.session_state["flash"] = ((f"Could not remove {title}: {rm_err}", WARN_ICON) if rm_err
                                             else removed_message(r, out or {}))
                results.pop(name, None)
                _get.clear()
                st.rerun()
            if c2.button("Keep it", key=f"remove_no_{name}", width="stretch"):
                st.session_state.pop("confirm_remove", None)
                st.rerun()
    result = results.get(name)
    if result and result.get("ok"):
        st.success(result.get("detail") or "Connected.")
    elif result:
        st.error(f"Test failed: {result.get('error')}")


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
    st.markdown(f'<div class="lead">{icon("pending_actions")}<span>{html.escape(sh.approvals_headline(waiting))}</span></div>',
                unsafe_allow_html=True)
    for inc in waiting:
        verb = "Approve or reject" if sh.available_actions(inc)["decide"] else "Keep or roll back"

        def details(inc=inc) -> None:
            incident_summary(inc)
            if inc.get("category") == "staff_report":
                st.info("Someone at the business reported this. Read it and close it with a note under Staff reports; "
                        "closing every report on it closes this incident too.", icon=":material/campaign:")
                if st.button("Open Staff reports", key=f"to_staff_{inc.get('id')}", icon=":material/arrow_forward:"):
                    go("staff")
            decision_controls(inc)
            table(sh.action_rows(inc), "No containment actions yet.")
        incident_row(inc, "appr", verb, details)


STAFF_FILTERS = {"Open": "open", "New": "new", "Reviewing": "reviewing", "Resolved": "resolved",
                 "Not a threat": "not_a_threat", "All": None}
STAFF_STATUS = {"new": ("New", "amber"), "reviewing": ("Reviewing", "green"), "resolved": ("Resolved", None),
                "not_a_threat": ("Not a threat", None)}
URGENCY_COLOR = {"high": "critical", "medium": "amber", "low": "green"}


def report_link() -> str:
    """The open report page's address, from the address this console was opened on."""
    try:
        base = str(st.context.url or "").split("?", 1)[0].rstrip("/")
    except Exception:  # noqa: BLE001 - no browser behind this run
        base = ""
    return f"{base or 'http://<this dashboard>'}/?report"


@st.fragment(run_every=AUTO)
def page_staff() -> None:
    show_flash()
    if header("Staff reports", "what people at the business flagged · a person reads and closes each one") is None:
        return
    data, err = fetch("staff", {})
    if err:
        st.warning(f"Could not load staff reports: {err}")
    data = data or {}
    counts = data.get("counts") or {}
    stats(("New", str(counts.get("new", 0)), "nobody has picked these up",
           sh.BAND_COLORS["amber"] if counts.get("new") else None),
          ("Reviewing", str(counts.get("reviewing", 0)), "someone is on it"),
          ("Resolved", str(counts.get("resolved", 0)), "real problems dealt with"),
          ("Not a threat", str(counts.get("not_a_threat", 0)), "checked and harmless"))
    with st.container(border=True):
        section("Share the report page", "no sign-in; it shows nothing from SentrAI", "share")
        st.markdown(f"Staff can report from {code(report_link())}. Put it on the noticeboard or in the staff chat. "
                    "Each report is sorted straight away (the AI model when one is set up, keywords otherwise), "
                    "tells the reporter what to do now, and opens a *needs review* incident that is never "
                    "acted on automatically.", unsafe_allow_html=True)
    choice = st.segmented_control("Show", list(STAFF_FILTERS), default="Open", key="staff_filter") or "Open"
    want = STAFF_FILTERS[choice]
    reports = [r for r in data.get("reports") or [] if want is None or r.get("status") == want
               or (want == "open" and r.get("status") in ("new", "reviewing"))]
    if not reports:
        empty("No staff reports here." if choice != "Open" else "No open staff reports. All quiet.", "campaign",
              good=choice == "Open")
        return
    for n, r in enumerate(reports):
        tri = r.get("triage") or {}
        label, _ = STAFF_STATUS.get(str(r.get("status")), (str(r.get("status")), None))
        title = (f"{r.get('id')} · {r.get('kind_label') or tri.get('kind')} · {str(tri.get('urgency', '')).capitalize()} · "
                 f"{r.get('reporter') or 'anonymous'} · {label}")
        with st.expander(title, expanded=n == 0 and r.get("status") == "new"):
            staff_report_detail(r)


def staff_report_detail(r: dict) -> None:
    tri = r.get("triage") or {}
    rid = str(r.get("id"))
    label, color = STAFF_STATUS.get(str(r.get("status")), (str(r.get("status")), None))
    urg = str(tri.get("urgency") or "medium")
    st.markdown(
        '<div class="inc-head">'
        f'<span class="inc-id">{html.escape(rid)}</span>'
        f'{pill(urg.capitalize() + " urgency", sh.BAND_COLORS[URGENCY_COLOR.get(urg, "amber")])}'
        f'{pill(label, sh.BAND_COLORS[color] if color else sh.TEXT_SECONDARY)}'
        + (pill(f"With {r['assignee']}", sh.TEXT_SECONDARY) if r.get("assignee") else "")
        + '</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="detail-grid">'
        f'<div><span>Reported by</span><b>{html.escape(str(r.get("reporter") or "anonymous"))}</b></div>'
        f'<div><span>Contact</span><b>{html.escape(str(r.get("contact") or "-"))}</b></div>'
        f'<div><span>Where</span><b>{html.escape(str(r.get("where") or "-"))}'
        + (f' · {html.escape(str(r["host"]))}' if r.get("host") else "") + '</b></div>'
        f'<div><span>Received</span><b>{html.escape(sh.short_time(r.get("received_at")))} · '
        f'{html.escape(str(r.get("channel") or "-"))}</b></div>'
        f'<div><span>Sorted by</span><b>{"AI model" if tri.get("by") == "ai" else "Keyword rules"}</b></div>'
        f'<div><span>Incident</span><b>{html.escape(str(r.get("incident") or "-"))}</b></div>'
        '</div>', unsafe_allow_html=True)
    section("What they wrote", "", "chat")
    st.text(str(r.get("text") or ""))
    left, right = st.columns(2)
    with left:
        section("Summary", "", "summarize")
        st.markdown(html.escape(str(tri.get("summary") or "-")))
        section("Check first", "", "search")
        st.markdown(html.escape(str(tri.get("for_tech") or "-")))
    with right:
        section("What the reporter was told", "", "support_agent")
        st.markdown("\n".join(f"1. {html.escape(str(a))}" for a in tri.get("advice") or []) or "-")
    if r.get("notes"):
        section("Notes", "", "sticky_note_2")
        for note in r["notes"]:
            st.markdown(f"**{html.escape(str(note.get('by')))}** · {html.escape(sh.short_time(note.get('at')))}  \n"
                        f"{html.escape(str(note.get('text')))}")
    if r.get("status") not in ("new", "reviewing"):
        return
    with st.form(f"staff_{rid}", border=False):
        a, b = st.columns([1, 2])
        who = a.text_input("Handled by", value=r.get("assignee") or st.session_state.operator, key=f"sa_{rid}")
        note = b.text_input("Note", key=f"sn_{rid}", placeholder="What you found or did (needed to close)")
        c1, c2, c3 = st.columns(3)
        save = c1.form_submit_button("Save", icon=":material/save:", width="stretch",
                                     disabled=locked(), help=why_locked())
        resolve = c2.form_submit_button("Resolved", icon=":material/task_alt:", type="primary", width="stretch",
                                        disabled=locked(), help=why_locked())
        harmless = c3.form_submit_button("Not a threat", icon=":material/do_not_disturb_on:", width="stretch",
                                         disabled=locked(), help=why_locked())
    status = "resolved" if resolve else "not_a_threat" if harmless else None
    if save or status:
        if status and not note.strip():
            st.warning("Add a short note saying what you found before closing it.")
            return
        run_action(f"{rid} updated", lambda: client.update_staff_report(
            rid, st.session_state.operator, status=status, assignee=who.strip(), note=note.strip() or None),
            rerun=False)
        _get.clear()  # the menu bubble and counts show the change at once
        st.rerun()


def owner_controls(inc: dict, contacts: list[dict], where: str = "") -> None:
    """Who has the incident, its hand-over history, and the Assign / Mark resolved forms."""
    inc_id, op = str(inc.get("id")), st.session_state.operator
    kid = f"{where}{inc_id}"  # the same incident can be open in two places on a page
    owner, backup = inc.get("owner") or "Nobody yet", inc.get("backup")
    level = int(inc.get("escalation_level") or 0)
    st.markdown(
        f'<div class="detail-grid">'
        f'<div><span>Owner</span><b>{html.escape(str(owner))}</b></div>'
        f'<div><span>Backup</span><b>{html.escape(str(backup or "-"))}</b></div>'
        f'<div><span>Given by</span><b>{html.escape(str(inc.get("assigned_by") or "-"))}</b></div>'
        f'<div><span>Escalations</span><b>{level}</b></div>'
        '</div>', unsafe_allow_html=True)
    history = sh.owner_history(inc)
    if history:
        st.caption("  \n".join(html.escape(h) for h in history[-6:]))
    if inc.get("status") not in sh.OPEN_STATUSES:
        if inc.get("resolution"):
            st.caption(f"Resolved by {inc.get('resolved_by')}: {inc.get('resolution')}")
        return
    names = [str(c.get("name")) for c in contacts if c.get("name")]
    a, b = st.columns(2)
    with a, st.form(key=f"assign_{kid}", clear_on_submit=True, border=True):
        me, other = f"Me ({op})", "Someone else"
        choice = st.selectbox("Give it to", [me, *[n for n in names if n != owner], other], key=f"to_{kid}")
        typed = st.text_input("Name, if someone else", key=f"toname_{kid}")
        note = st.text_input("Note (optional)", key=f"tonote_{kid}", placeholder="e.g. You know this server best")
        go_assign = st.form_submit_button("Assign", icon=":material/person_add:", width="stretch",
                                          disabled=locked(), help=why_locked())
    with b, st.form(key=f"resolve_{kid}", clear_on_submit=True, border=True):
        done = st.text_area("What was done (required, written to the audit log)", key=f"done_{kid}", height=108,
                            placeholder="e.g. Password reset for admin, attacker IP blocked at the router")
        go_resolve = st.form_submit_button("Mark resolved", icon=":material/task_alt:", type="primary", width="stretch",
                                           disabled=locked(), help=why_locked())
    if go_assign:
        who = op if choice == me else typed.strip() if choice == other else choice
        if not who:
            st.error("Type the name of the person to give it to.")
        else:
            run_action(f"{inc_id} given to {who}", lambda: client.assign(inc_id, who, op, note.strip()))
    elif go_resolve:
        if not done.strip():
            st.error("Write a short note on what was done first. Nothing was changed.")
        else:
            run_action(f"Resolved {inc_id}", lambda: client.resolve(inc_id, op, done.strip()))


def incident_card(inc: dict, contacts: list[dict], where: str = "") -> None:
    incident_summary(inc)
    owner_controls(inc, contacts, where)
    if sh.available_actions(inc)["decide"] or sh.available_actions(inc)["contain_controls"]:
        decision_controls(inc, where)


@st.fragment(run_every=AUTO)
def page_incidents() -> None:
    show_flash()
    if header("Incidents", "who owns each incident, and what still needs a person") is None:
        return
    incidents, err = fetch("incidents", [])
    if err:
        st.warning(f"Could not load incidents: {err}")
    incidents = incidents or []
    routing, rerr = safe(client.routing, {})
    contacts = (routing or {}).get("contacts") or []
    person = sh.find_person(routing, (ME or {}).get("email", ""), st.session_state.operator)
    me = str(person.get("name")) if person else st.session_state.operator
    c = sh.board_counts(incidents, me)
    stats(("Open", str(c["open"]), "not resolved yet"),
          ("Needs attention", str(c["attention"]), f"{c['unassigned']} with no owner",
           sh.BAND_COLORS["amber"] if c["attention"] else None),
          ("Overdue", str(c["overdue"]), "past the SLA, nobody answered",
           sh.BAND_COLORS["critical"] if c["overdue"] else None),
          ("Escalated", str(c["escalated"]), "handed to a backup contact",
           sh.BAND_COLORS["amber"] if c["escalated"] else None),
          ("Yours", str(c["mine"]), f"owned by {me}"))

    with st.container(border=True):
        my_part_section(routing, incidents, contacts, person, rerr)

    with st.container(border=True):
        section("Needs attention", "most urgent first", "notification_important")
        todo = sh.needs_attention(incidents)
        if not todo:
            empty("Nothing needs a person right now. Every open incident is in hand.", "check_circle", good=True)
        for inc in todo:
            note = f"{inc.get('owner') or 'no owner'} · {'; '.join(sh.attention(inc))}"
            incident_row(inc, "todo", note, lambda inc=inc: incident_card(inc, contacts, "todo_"))

    with st.container(border=True):
        section("All incidents", "owner, backup and what each one still needs", "assignment_ind")
        t1, t2 = st.columns(2)
        closed = t1.toggle("Show resolved and rejected", key="board_closed")
        mine = t2.toggle(f"Only mine ({me})", key="board_mine")
        shown = [i for i in incidents if not mine or str(i.get("owner") or "").lower().lstrip("@") == me.lower().lstrip("@")]
        table(sh.board_rows(shown, include_closed=closed), "No incidents. All quiet at the gate.")
        ids = [str(i.get("id")) for i in shown if closed or i.get("status") in sh.OPEN_STATUSES]
        if ids:
            pick = st.selectbox("Open one to assign, resolve or decide", ["-", *ids], key="board_pick")
            inc = next((i for i in shown if str(i.get("id")) == pick), None)
            if inc is not None:
                with st.container(border=True):
                    incident_card(inc, contacts)

    if can("configure"):  # Owners and Admins change the whole map; everyone else has their own part above
        with st.container(border=True):
            section("Who gets what", "routing rules: the first match owns the incident", "alt_route")
            whole_team_map(routing, contacts, rerr)
    else:
        with st.container(border=True):
            section("The whole team", "everyone's part, to look at", "alt_route")
            if st.toggle("Show the whole team's map", key="whole_map"):
                whole_team_map(routing, contacts, rerr)


def whole_team_map(routing: dict, contacts: list[dict], rerr: str | None) -> None:
    if rerr and not st.session_state.get("rt_last"):
        st.caption(f"Could not load the routing rules: {rerr}")
    else:
        if rerr:  # a blip in the core must not throw away what someone is half-way through changing
            routing = st.session_state["rt_last"]
            st.caption(f"Could not reach the core ({rerr}). Showing the last copy; saving works again "
                       "once it is back.")
        st.session_state["rt_last"] = routing
        st.caption(f"From {routing.get('source')}. Unanswered alerts go to the owner's backup after "
                   f"{(routing.get('follow_up') or {}).get('escalate_after_reminders', '?')} reminders.")
        routing_editor(routing)
        with st.expander("The same as tables"):
            table(sh.routing_rows(routing), "", )
            table(sh.contact_rows(routing), "")
        if any("telegram_linked" in c for c in contacts):  # the core says so only while Telegram is added
            telegram_links(contacts)


def my_part_section(routing: dict, incidents: list[dict], contacts: list[dict], person: dict | None,
                    rerr: str | None) -> None:
    """Your part of "Who gets what": the incidents that reach you, the rules that send them, who takes
    over when you don't answer, and your corner of the map. Owners and Admins can look as anyone."""
    section("Your part", "what reaches you, and who covers for you", "person")
    if rerr or not contacts:
        st.caption(f"Could not load who gets what: {rerr}" if rerr else "Nobody is in who gets what yet.")
        return
    names = [str(c.get("name")) for c in contacts if c.get("name")]
    if can("configure"):
        mine = str(person.get("name")) if person else ""
        me_label = f"Me ({mine})" if mine else "Me"
        pick = st.selectbox("See it as", [me_label, *[n for n in names if n != mine]], key="part_as",
                            help="Each person sees this part when they sign in. Pick someone to see what they see.")
        if pick != me_label:
            person = next((c for c in contacts if c.get("name") == pick), person)
    if person is None:
        email = f"**{ME['email']}**" if ME else "your sign-in email"
        st.info(f"You are not one of the people in who gets what yet, so no incidents come to you by name. "
                f"{'Click a person on the map below and put' if can('configure') else 'Ask an Owner or Admin to put'} "
                f"{email} as their email to make it you.", icon=":material/link_off:")
        return
    cid, name = str(person.get("id")), str(person.get("name"))
    part = sh.my_part(routing, cid, incidents)
    open_ = lambda incs: [i for i in incs if i.get("status") in sh.OPEN_STATUSES]  # noqa: E731
    owned, backing, heard = open_(part["mine"]), open_(part["backing"]), open_(part["heard"])
    backup = part["backup"]
    stats(("Yours to handle", str(len(owned)), f"open, owned by {name}",
           sh.BAND_COLORS["amber"] if owned else None),
          ("Backing up", str(len(backing)), "you take over if the owner is silent"),
          ("Told about", str(len(heard)), "open, for your information"),
          ("Your backup", str(backup.get("name")) if backup else "Nobody",
           "takes over when you don't answer", None if backup else sh.BAND_COLORS["amber"]))
    def rule_line(i: int, r: dict) -> str:
        return f"{i + 1}. {r.get('name')}"
    lines = []
    if part["owns"]:
        lines.append("**You own:** " + ", ".join(rule_line(i, r) for i, r in part["owns"]))
    if part["told"]:
        lines.append("**You are told about:** " + ", ".join(rule_line(i, r) for i, r in part["told"]))
    if part["covers"]:
        lines.append("**You back up:** " + ", ".join(str(c.get("name")) for c in part["covers"]))
    st.markdown("  \n".join(lines) if lines else "No rule sends anything to you, and you back nobody up.")
    for inc in owned:
        incident_row(inc, "mine", "yours", lambda inc=inc: incident_card(inc, contacts, "mine_"))
    for inc in backing:
        incident_row(inc, "mine", f"owned by {inc.get('owner')}, you are the backup",
                     lambda inc=inc: incident_card(inc, contacts, "mine_"))
    if ROUTING_EDITOR is not None and (part["owns"] or part["told"] or part["covers"]):
        with st.expander("Your part of the map", icon=":material/alt_route:", expanded=not owned and not backing):
            lock = ("Your part only. An Owner or Admin changes who gets what on the whole map."
                    if not can("configure") else "Only your part. Change it on the whole map below.")
            ROUTING_EDITOR(key=f"routing_mine_{cid}", on_save_change=lambda: None,
                           data=sh.routing_editor_data(sh.my_routing(routing, cid), read_only=True,
                                                       lock_reason=lock, focus=cid))


def routing_editor(routing: dict) -> None:
    """Who gets what as a map to drag and connect (sentrai_ui/routing_editor.mjs). Every change stays in the
    browser until Save, which sends the whole routing file here; Owners and Admins only, Auditors look."""
    if ROUTING_EDITOR is None:
        st.caption("This Streamlit is too old for the map editor: run `pip install -r requirements.txt` in "
                   "mvp/dashboard. The tables below show who gets what meanwhile.")
        return
    off = locked("configure")
    data = sh.routing_editor_data(routing, read_only=off, lock_reason=why_locked("configure") or "",
                                  result=st.session_state.get("rt_result"))
    save = ROUTING_EDITOR(key="routing_editor", data=data, on_save_change=lambda: None).get("save")
    if save and not off:
        _save_routing(save)


def _save_routing(event: dict) -> None:
    """Post the editor's routing file to the core, then tell the editor (by the save's id) how it went."""
    summary = str(event.get("summary") or "")[:300]
    try:
        client.save_routing(sh.routing_from_editor(event.get("routing")), st.session_state.operator, summary)
    except CoreError as exc:
        reason = str(exc).split(": ", 1)[-1] if exc.status == 400 else str(exc)  # the core's own words
        st.session_state["rt_result"] = {"id": event.get("id"), "ok": False, "message": reason}
        st.session_state["flash"] = (f"Who gets what not saved: {reason}", WARN_ICON)
    else:
        st.session_state["rt_result"] = {"id": event.get("id"), "ok": True, "message": f"Saved. {summary}"}
        st.session_state["flash"] = (f"Who gets what saved. {summary}", OK_ICON)
    st.rerun(scope="fragment")


def telegram_links(contacts: list[dict]) -> None:
    """Make a one-time code a person sends to the bot, so their alerts reach them in their own chat."""
    if not contacts:
        return
    st.markdown("**Alerts in each person's own Telegram chat**")
    st.caption("Make a code for a person and send it to them. They open a private chat with the SentrAI bot "
               "and send `/link CODE` within 30 minutes. From then on, alerts for them arrive in that chat "
               "with the buttons, and whatever they press is recorded under their name.")
    by_name = {str(c.get("name")): c for c in contacts if c.get("name")}
    a, b, c = st.columns([3, 1.4, 1.2], vertical_alignment="bottom")
    who = a.selectbox("Person", list(by_name), key="tg_person")
    contact = by_name.get(who) or {}
    op = st.session_state.operator
    if b.button("Make link code", icon=":material/key:", key="tg_code", width="stretch", disabled=locked(),
                help=why_locked()):
        made, err = safe(lambda: client.telegram_link_code(str(contact.get("id")), op), {})
        if err:
            st.warning(f"Could not make a code: {err}")
        else:
            st.session_state["tg_made"] = made
    if contact.get("telegram_linked") and c.button("Unlink", icon=":material/link_off:", key="tg_unlink",
                                                   width="stretch", disabled=locked(), help=why_locked()):
        run_action(f"{who} unlinked from Telegram",
                   lambda: client.telegram_unlink(str(contact.get("id")), op))
    made = st.session_state.get("tg_made")
    if made and made.get("name") == who:
        st.success(f"Code for {made.get('name')}: **{made.get('code')}** "
                   f"(works once, until {str(made.get('expires_at') or '')[11:16]}). "
                   f"They send this to the bot in a private chat:")
        st.code(made.get("send") or f"/link {made.get('code')}", language=None)


CHAT_STARTERS = ("What is happening right now?", "Which incident should I deal with first?",
                 "Why did you block the last IP address?")
CHAT_FOLLOW_UPS = CHAT_STARTERS + ("Is anything waiting for my approval?", "What changed in the last hour?",
                                   "Is any machine offline?")


def chat_quick_replies(questions: list[str] | tuple[str, ...], key: str) -> None:
    """Questions to send with one click, shown under Cyanide's message like quick replies."""
    cols = st.container(key=f"quick_{key}").columns(len(questions))
    for col, q in zip(cols, questions):
        if col.button(q, key=f"{key}_{q}", width="stretch"):
            st.session_state["chat_pending"] = q


def chat_follow_ups(messages: list[dict]) -> list[str]:
    """Up to three questions the operator has not asked yet, for under the latest reply."""
    asked = {str(m.get("text") or "").strip().lower() for m in messages if m.get("role") == "operator"}
    return [q for q in CHAT_FOLLOW_UPS if q.lower() not in asked][:3]


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

    with st.container(height=540, border=True, key="chat_log"):
        if not messages:
            with st.chat_message("assistant", avatar=":material/science:"):
                st.caption(f"**{assistant}**")
                st.markdown(f"Hi, I'm {assistant}. Ask me about incidents, why I acted, or what to do next. "
                            "Or pick one of these to start:")
                chat_quick_replies(CHAT_STARTERS, "starter")
        last = max((n for n, m in enumerate(messages) if m.get("role") != "operator"), default=-1)
        for n, m in enumerate(messages):
            chat_message(m, assistant, by_id, follow_ups=chat_follow_ups(messages) if n == last else None)

    prompt = st.chat_input(f"Ask {assistant}…") or st.session_state.pop("chat_pending", None)
    if prompt:
        with st.spinner(f"{assistant} is looking into it…"):
            _, err = safe(lambda: client.chat(st.session_state.operator, prompt, about or None))
        if err:
            st.session_state["flash"] = (f"Chat failed: {err}", WARN_ICON)
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
    answer = None
    options = sc.options()
    with st.container(height=540, border=True, key="chat_log"):
        for i, m in enumerate(sc.messages):
            mine = m["role"] == "user"
            with st.chat_message("user" if mine else "assistant", avatar=":material/person:" if mine else ":material/science:"):
                st.markdown(m["text"].replace("\n", "  \n") if mine else m["text"])
                if options and i == len(sc.messages) - 1:  # the answers sit under the question they answer
                    per_row = 2 if any(len(label) > 26 for _, label in options) else 4  # long labels are never cut off
                    cols = st.columns(min(len(options), per_row))
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
    if not can("configure"):
        sc.state = "review"
        sc.messages.append({"role": "assistant", "text": "Auditors can't change the settings. "
                            "Ask an Owner or Admin to save this setup."})
        return
    bad = [f.prompt for f in cfg.FIELDS.values() if not cfg.valid(f, values.get(f.env, f.default))]
    if bad:
        sc.state = "review"
        sc.messages.append({"role": "assistant", "text": "I can't save yet; these values are not valid: "
                            + "; ".join(bad) + ". Fix them on the Configuration page, or start over."})
        return
    path = cfg.save(values)
    cfg.mark_setup_done("chat")
    try:
        watched = setup_chat.save_log_sources(sc, f"guided setup ({values.get('SENTRAI_OPERATOR') or 'operator'})")
    except OSError as e:
        watched = []
        sc.messages.append({"role": "assistant", "text": f"I couldn't add the log files to the collector's list ({e}). "
                            "Add them on the Collector page instead."})
    for key in [k for k in st.session_state if str(k).startswith("cfg_")]:  # Configuration shows the new values
        del st.session_state[key]
    st.session_state.operator = values.get("SENTRAI_OPERATOR") or st.session_state.operator
    ai, err = safe(client.ai_reload)
    note = f"Saved to {path}. "
    if watched:
        note += f"The collector now watches {', '.join(watched)}. "
    note += ("The core isn't running, so start SentrAI (run.ps1 or run.sh) and every part will use these settings."
             if err else f"I've switched to the new AI settings ({ai.get('chat')}). Restart SentrAI "
                         "(stop, then run) so the other parts pick up the rest.")
    deploy = setup_chat.deploy_command(sc)
    if deploy:
        note += ("\n\nWho can open the dashboard is a firewall setting, which needs admin rights. On a Linux "
                 f"server, run this once from the `mvp` folder to apply it:\n\n```\n{deploy}\n```\n\n"
                 "It keeps everything you saved here. On Windows or a laptop the dashboard stays on this "
                 "computer" + (f"; start run.sh with `--dashboard-port {sc.notes['port']}` (Windows: run.ps1 `-DashboardPort {sc.notes['port']}`)" if sc.notes.get("port", "8501") != "8501" else "") + ".")
    sc.saved(note + "\n\nYou can change anything later here or on the Configuration page.")


def chat_message(m: dict, assistant: str, by_id: dict[str, dict], follow_ups: list[str] | None = None) -> None:
    mine = m.get("role") == "operator"
    who = m.get("operator") or st.session_state.operator if mine else assistant
    with st.chat_message("user" if mine else "assistant", avatar=":material/person:" if mine else ":material/science:"):
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
        if follow_ups:
            chat_quick_replies(follow_ups, f"follow_{m.get('id')}")


def chat_suggestion(mid: Any, n: int, s: dict, inc: dict | None) -> None:
    """A suggested decision. Pressing it calls the same endpoints as the Approvals page."""
    if s.get("kind") == "watch_log":
        watch_suggestion(mid, n, s)
        return
    if s.get("kind") == "quarantine_file":
        quarantine_suggestion(mid, n, s)
        return
    if s.get("kind") == "backup_now":
        backup_suggestion(mid, n, s)
        return
    inc_id, decision = str(s.get("incident")), str(s.get("decision"))
    ok, why_not = sh.suggestion_state(inc, decision)
    label = str(s.get("label") or f"{decision} {inc_id}")
    if not ok:
        st.caption(f":material/lightbulb: Suggested: {label} · {why_not}")
        return
    op = st.session_state.operator
    with st.form(key=f"sugg_{mid}_{n}", border=True):
        st.markdown(f":material/lightbulb: **Suggested: {html.escape(label)}**")
        just = st.text_input("Justification (written to the audit log)", value=str(s.get("reason") or ""),
                             key=f"sugg_just_{mid}_{n}")
        go_ = st.form_submit_button(f"Confirm: {label}", type="primary" if decision != "reject" else "secondary",
                                    disabled=locked(), help=why_locked())
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
        st.markdown(f":material/lightbulb: **Suggested: {html.escape(label)}**")
        if s.get("reason"):
            st.caption(str(s["reason"]))
        if st.button(f"Confirm: {label}", key=f"sugg_{mid}_{n}", type="primary", disabled=locked(), help=why_locked()):
            run_action(label, lambda: client.watch_log(str(s.get("file_id")), st.session_state.operator), rerun=False)
            st.rerun()


def quarantine_suggestion(mid: Any, n: int, s: dict) -> None:
    """A file Cyanide thinks is hostile. Pressing it moves the file into quarantine (it can be restored)."""
    label = str(s.get("label") or "Quarantine file")
    with st.container(border=True):
        st.markdown(f":material/lightbulb: **Suggested: {html.escape(label)}**")
        if s.get("reason"):
            st.caption(str(s["reason"]))
        if st.button(f"Confirm: {label}", key=f"sugg_{mid}_{n}", type="primary", disabled=locked(), help=why_locked()):
            run_action(label, lambda: client.quarantine(str(s.get("finding_id")), st.session_state.operator,
                                                        str(s.get("reason") or "")), rerun=False)
            st.rerun()


def backup_suggestion(mid: Any, n: int, s: dict) -> None:
    """Cyanide thinks a fresh backup is a good idea. Pressing it takes one now."""
    with st.container(border=True):
        st.markdown(":material/lightbulb: **Suggested: Back up now**")
        if s.get("reason"):
            st.caption(str(s["reason"]))
        if st.button("Confirm: Back up now", key=f"sugg_{mid}_{n}", type="primary", disabled=locked(), help=why_locked()):
            with st.spinner("Backing up…"):
                run_action("Backup made", lambda: client.backup_now(st.session_state.operator), rerun=False)
            st.rerun()


@st.fragment(run_every=AUTO)
@st.fragment(run_every=AUTO)
def page_flow() -> None:
    """How an attack is handled, as one map with what each step is doing now. Click a step to open its page."""
    show_flash()
    if header("How it works", "how an attack is handled, step by step · click a step to open it") is None:
        return
    risk, _ = fetch("risk", {})
    incidents, _ = fetch("incidents", [])
    agents, _ = fetch("agents", [])
    blocklist, _ = fetch("blocklist", {})
    exts, _ = fetch("extensions", [])
    records, valid, _ = audit_records()
    settings = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read()
    data = sh.flow_map_data(risk, incidents, agents, blocklist, exts, records, settings, valid)
    with st.container(border=True):
        if FLOW_MAP is None:
            st.caption("This Streamlit is too old to draw the map: run `pip install -r requirements.txt` in "
                       "mvp/dashboard. The same steps as a list:")
            table(sh.pd.DataFrame([{"Step": n["title"], "Now": n["value"], "": n["note"]} for n in data["nodes"]]), "")
            return
        picked = FLOW_MAP(key="flow_map", data=data, on_open_change=lambda: None).get("open")
        if picked in PAGES and page_allowed(picked):
            go(picked)
    st.caption("Nothing on this map changes a setting. Each step's own page shows it in full.")
    with st.container(border=True):
        section("What it may do on its own", "drag an action between the lanes, change a number, then Save",
                "smart_toy")
        limits_map(settings)


def limits_map(settings: dict[str, str]) -> None:
    """The limits on acting without a person, as a map to change (sentrai_ui/limits_map.mjs). Saved to the
    settings file like the Configuration page does; Owners and Admins only, everyone else looks."""
    if LIMITS_MAP is None:
        st.caption("This Streamlit is too old to draw the map. The same settings are under 3. Responder on the "
                   "Configuration page.")
        return
    off = locked("configure")
    data = sh.limits_map_data(settings, read_only=off, lock_reason=why_locked("configure") or "",
                              result=st.session_state.get("lm_result"))
    save = LIMITS_MAP(key="limits_map", data=data, on_save_change=lambda: None).get("save")
    if save and not off and save.get("id") != (st.session_state.get("lm_result") or {}).get("id"):
        try:
            changed = sh.check_limits(save.get("settings"))
        except ValueError as exc:
            st.session_state["lm_result"] = {"id": save.get("id"), "ok": False, "message": f"Not saved: {exc}."}
        else:
            values = {f.env: f.default for f in cfg.FIELDS.values()} | cfg.read() | changed
            path = cfg.save(values)
            st.session_state["lm_result"] = {"id": save.get("id"), "ok": True,
                                             "message": f"Saved to {short_path(path)}. Restart SentrAI (run.sh or "
                                                        "run.ps1) so the core uses the new limits."}
            st.session_state["flash"] = ("What SentrAI may do on its own: saved", OK_ICON)
        st.rerun(scope="fragment")


def page_collector() -> None:
    show_flash()
    if header("Collector", "Step 1 of 3 · reads your logs and turns each line into an event") is None:
        return
    records, _, _ = audit_records()
    agents, _ = fetch("agents", [])
    agents = agents or []
    layer = [a for a in agents if "analyzed" in a]
    watchdog = next((a for a in agents if a.get("name") == "Watchdog"), {})
    collectors = watchdog.get("collectors") or []
    malicious = sh.records_of(records, "event_classified")
    silent = sh.records_of(records, "collector_silent")

    stats(("Events analysed", str(sum(int(a.get("analyzed") or 0) for a in layer)), "by the layer agents"),
          ("Malicious events", str(len(malicious)), "attached to incidents",
           sh.BAND_COLORS["critical"] if malicious else None),
          ("Collectors", str(len(collectors)), "sending heartbeats"),
          ("Silent alerts", str(len(silent)), "a collector stopped reporting",
           sh.BAND_COLORS["amber"] if silent else None))

    left, right = st.columns(2)
    with left, st.container(border=True):
        section("Log sources", "from the settings file", "folder_open")
        logs_dir = Path(os.environ.get("SENTRAI_LAB_LOGS") or cfg.FIELDS["SENTRAI_LAB_LOGS"].default)
        st.caption(f"Folder: {logs_dir}")
        rows = []
        for env in ("SENTRAI_LOG_ACCESS", "SENTRAI_LOG_AUTH", "SENTRAI_LOG_DB", "SENTRAI_LOG_OS"):
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
        table(sh.pd.DataFrame([{"Collector": c.get("collector", "-"), "State": "Silent" if c.get("silent") else "Alive",
                                "Last seen": datetime.fromtimestamp(float(c["last_seen_ts"])).strftime("%H:%M:%S")
                                if c.get("last_seen_ts") else "-"} for c in collectors]),
              "No heartbeat received yet. Start the collector.")
        section("Events per layer agent", "", "hub")
        table(sh.pd.DataFrame([{"Agent": a.get("name"), "Events analysed": a.get("analyzed", 0)} for a in layer]),
              "No agent data.")
    scout_proposals()
    log_discovery()
    threat_panel()
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
            c1.markdown(f"**{html.escape(str(p.get('name')))}** · {code(p.get('path'))} · {html.escape(str(p.get('layer')))}  \n"
                        f"<span style='opacity:.7'>{html.escape(str(p.get('why') or ''))}</span>",
                        unsafe_allow_html=True)
            pid = p.get("id")
            for col, approve, label in ((c2, True, "Watch"), (c3, False, "Dismiss")):
                if col.button(label, key=f"scout_{'yes' if approve else 'no'}_{pid}",
                              icon=":material/visibility:" if approve else ":material/close:", disabled=locked(), help=why_locked()):
                    run_action(f"Collector now watches {p.get('name')}" if approve else f"Dismissed {p.get('name')}",
                               lambda a=approve: client.decide_log_source(pid, st.session_state.operator, a),
                               rerun=False)
                    st.rerun()


def log_discovery() -> None:
    """Process scan: the core lists running programs and their log files; the operator picks what to watch."""
    with st.container(border=True):
        section("Find logs on this computer", "read-only scan of running programs · nothing is watched until you "
                                              "press Watch", "travel_explore")
        if st.button("Scan running programs", icon=":material/radar:", key="scan_system",
                     disabled=locked(), help=why_locked()):
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
        for t in latest.get("threats") or []:
            st.error(f"{SEVERITY_ICON.get(str(t.get('severity')), OTHER_SEVERITY)} Suspicious program: {t.get('label')} · "
                     f"{t.get('name')} (pid {t.get('pid')}, account {t.get('account') or 'unknown'})")
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
            st.caption(f":material/info: {note}")


SEVERITY_ICON = {"critical": ":red[:material/error:]", "high": ":orange[:material/warning:]",
                 "medium": ":orange[:material/info:]"}  # Streamlit markdown icons: the same on every OS
OTHER_SEVERITY = ":gray[:material/help:]"


def threat_panel() -> None:
    """Threat scan: look inside the configured folders for web shells, miners, reverse shells and the like."""
    with st.container(border=True):
        section("Check for threats", "read-only look inside your chosen folders · files move to quarantine only "
                                     "when you press it", "bug_report")
        if st.button("Scan for threats", icon=":material/policy:", key="scan_threats",
                     disabled=locked(), help=why_locked()):
            with st.spinner("Checking files…"):
                run_action("Threat scan finished", lambda: client.scan_threats(st.session_state.operator), rerun=False)
        latest, err = safe(client.latest_threats, None)
        if err or not latest:
            st.caption("Threat scanning is not available on this core.")
            return
        if latest.get("note"):
            st.caption(latest["note"])
        if not latest.get("scanned_at"):
            st.caption("No threat scan yet. Set the folders under threat_scan.paths in the system profile "
                       "(or SENTRAI_THREAT_PATHS); Cyanide can also run one when you ask in Chat.")
        else:
            c = latest.get("counts") or {}
            st.caption(f"Last scan {sh.short_time(latest.get('scanned_at'))}: {latest.get('files_checked', 0)} files in "
                       f"{', '.join(latest.get('roots') or [])} · {c.get('critical', 0)} critical, {c.get('high', 0)} high, "
                       f"{c.get('medium', 0)} worth a look")
            if latest.get("missing"):
                st.warning("Folders not found: " + ", ".join(latest["missing"]))
            found = latest.get("findings") or []
            if not found:
                empty("Nothing suspicious found.", "verified_user", good=True)
            for f in found[:25]:
                threat_row(f)
        held, _ = safe(client.quarantined, [])
        if held:
            with st.expander(f"In quarantine ({len(held)})"):
                for q in held:
                    c1, c2 = st.columns([5, 1])
                    c1.caption(f"{q.get('name')} · from `{q.get('original')}` · {(q.get('finding') or {}).get('label')} · "
                               f"by {q.get('operator')} {sh.short_time(q.get('at'))}")
                    if c2.button("Restore", key=f"restore_{q.get('id')}", icon=":material/undo:", disabled=locked(), help=why_locked()):
                        run_action(f"Restored {q.get('name')}",
                                   lambda qid=q.get("id"): client.restore(qid, st.session_state.operator), rerun=False)
                        st.rerun()


def threat_row(f: dict) -> None:
    where = code(f.get('path')) + (f" → {code(f.get('entry'))}" if f.get("entry") else "") + \
        (f" line {html.escape(str(f.get('line')))}" if f.get("line") else "")
    c1, c2 = st.columns([5, 1])
    c1.markdown(f"{SEVERITY_ICON.get(str(f.get('severity')), OTHER_SEVERITY)} **{html.escape(str(f.get('label')))}** · "
                f"{html.escape(str(f.get('kind', '')).replace('_', ' '))} · {where}", unsafe_allow_html=True)
    if f.get("snippet"):
        c1.code(str(f["snippet"]), language=None)
    if c2.button("Quarantine", key=f"quar_{f.get('id')}", icon=":material/block:", disabled=locked(), help=why_locked()):
        run_action(f"Quarantined {f.get('path')}",
                   lambda fid=f.get("id"): client.quarantine(fid, st.session_state.operator), rerun=False)
        st.rerun()


def scan_suggestion(s: dict) -> None:
    """One place the scan found logs, with a Watch button per file not yet watched."""
    files = s.get("files") or []
    state = ":material/check: already watched" if s.get("already_watched") else sh.plural(len(files), "log file")
    st.markdown(f"**{html.escape(str(s.get('program')))}** · {code(s.get('path'))} · {html.escape(str(s.get('layer')))} · {state}  \n"
                f"<span style='opacity:.7'>{html.escape(', '.join(s.get('reasons') or []))}</span>",
                unsafe_allow_html=True)
    for f in files:
        c1, c2 = st.columns([5, 1])
        c1.caption(f"{f.get('name')} · {int(f.get('size') or 0) / 1024:.1f} KB · changed "
                   f"{sh.short_time(f.get('modified'))}")
        if f.get("watched"):
            c2.caption("watched")
        elif c2.button("Watch", key=f"watch_{f.get('id')}", icon=":material/visibility:", disabled=locked(), help=why_locked()):
            run_action(f"Collector now watches {f.get('name')}",
                       lambda fid=f.get("id"): client.watch_log(fid, st.session_state.operator), rerun=False)
            st.rerun()


@st.fragment(run_every=AUTO)
def page_classifier() -> None:
    if header("Classifier", "Step 2 of 3 · decides which events are attacks: rules first, then AI, then keywords") is None:
        return
    records, _, _ = audit_records()
    agents, _ = fetch("agents", [])
    jev = next((a for a in agents or [] if a.get("name") == "Jev"), {})
    rows = sh.classification_rows(records)
    opened = sh.records_of(records, "incident_opened")

    by_rules = int((rows["Classified by"] == "Rules").sum()) if not rows.empty else 0
    exts, _ = fetch("extensions", [])
    ai_value, ai_note = sh.ai_classifier_state(jev.get("status"),
                                               next((r for r in exts or [] if r.get("name") == "typesafe"), None))
    stats(("Attacks identified", str(len(opened)), "incidents opened", sh.BAND_COLORS["critical"] if opened else None),
          ("Malicious events", str(len(rows)), "classified as an attack"),
          ("Settled by rules", str(by_rules), "certain, no AI needed"),
          ("AI classifier", ai_value, ai_note[:48]))

    with st.container(border=True):
        section("Rules in use", "change them on the Configuration page", "rule")
        preset = cfg.preset_label(os.environ.get(cfg.PRESET_ENV, cfg.DEFAULT_PRESET))
        st.markdown(
            f"- Security preset: **{preset}**\n"
            f"- Brute force: **{os.environ.get('BRUTE_FORCE_COUNT', '5')}** failed logins within "
            f"**{os.environ.get('BRUTE_FORCE_WINDOW_S', '60')} s**\n"
            f"- Bulk exfiltration: **{os.environ.get('EXPORT_ROWS_THRESHOLD', '100')}** rows or more in one export\n"
            "- Signatures: SQL injection, XSS, privilege escalation, port scans, misconfiguration, log tampering")
    with st.container(border=True):
        section("Classifications", "newest first · 40-60% sure goes to a person and is never blocked on its own", "label")
        table(rows, "No malicious classifications yet.", column_config={
            "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
            "Malicious": st.column_config.ProgressColumn("Malicious", min_value=0, max_value=1, format="%.2f")})


@st.fragment(run_every=AUTO)
def page_responder() -> None:
    show_flash()
    if header("Action taker", "Step 3 of 3 · temporary blocks that undo themselves unless a person keeps them") is None:
        return
    records, _, _ = audit_records()
    incidents, _ = fetch("incidents", [])
    blocklist, bl_err = fetch("blocklist", {"ips": [], "users": []})
    containment = sh.build_containment_rows(blocklist, incidents or [])
    history = sh.all_action_rows(incidents or [])

    stats(("Active containment", str(len(containment)), "in force now", sh.BAND_COLORS["amber"] if len(containment) else None),
          ("Blocked IPs", str(len((blocklist or {}).get("ips") or [])), "blocked right now"),
          ("Locked accounts", str(len((blocklist or {}).get("users") or [])), "locked right now"),
          ("Actions taken", str(len(history)), f"each expires after {os.environ.get('HOTPATCH_TTL_HOURS', '2')} h"))

    with st.container(border=True):
        section("Active containment", "blocked or locked right now", "block")
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
    risk = header("Review", "how close SentrAI is to acting on its own, and why")
    if risk is None:
        return
    incidents, inc_err = fetch("incidents", [])
    incidents = incidents or []
    idx = risk.get("risk_index")
    threshold = float(risk.get("threshold") or 80)
    active = [i for i in incidents if i.get("status") in sh.ACTIVE_STATUSES]
    waiting = sh.pending_approvals(incidents)
    penalty = sum(float(i.get("inaction_penalty") or 0) for i in active)
    hist = sh.history_frame(risk.get("history"))
    peak = max(float(hist["risk_index"].max()), float(idx or 0)) if not hist.empty else idx

    # Each machine's own number and band are in the machine list; these add what it doesn't say.
    stats(("Peak so far", f"{peak:.0f}" if peak is not None else "-", "on this computer",
           sh.band_color(sh.band_for(peak)) if peak is not None and peak >= threshold else None),
          ("Waiting on you", str(len(waiting)), f"{len(waiting) - len(active)} contained · {len(active)} open",
           sh.BAND_COLORS["amber"] if waiting else None),
          ("Inaction penalty", f"+{penalty:.0f}", "+5 per hour nobody responds",
           sh.BAND_COLORS["amber"] if penalty else None),
          ("Raw score", f"{float(risk.get('raw_score') or 0):.1f}", "points before scaling to 0-100"))

    g, h = st.columns([5, 7])
    with g, st.container(border=True):
        found = machines()
        online = sum(m["online"] for m in found)
        section("Machines", f"{online} of {len(found)} online · SentrAI acts on its own above the threshold", "dns")
        machine_list(found, panel_mode(risk))
    with h, st.container(border=True):
        section("Risk over time", "dashed line is the threshold", "show_chart")
        if hist.empty:
            empty("No history yet. The core adds a point on every risk change.", "show_chart")
        else:
            st.plotly_chart(sh.history_figure(hist, threshold), width="stretch", config={"displayModeBar": False}, key="history")

    with st.container(border=True):
        section("What adds to the score", "one row per incident", "calculate")
        st.caption("Each incident adds base points × AI confidence × how critical the target is, plus 5 for every "
                   "hour nobody responds. The 0-100 index is 100 × (1 − e^(−raw ÷ 60)), so it slows down near the top.")
        if inc_err:
            st.warning(f"Could not load incidents: {inc_err}")
        table(sh.risk_breakdown(incidents), "All quiet at the gate. No incidents.", column_config={
            "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
            "Inaction penalty": st.column_config.NumberColumn("Inaction penalty", format="+%.0f pts")})


def machine_list(found: list[dict], panel: bool) -> None:
    """One card per machine, like the server list of a game panel. On a central panel each card opens
    that machine's own page (an invisible button stretched over the card, see console.css)."""
    if not panel:
        st.markdown(sh.machine_rows_html(found), unsafe_allow_html=True)
        return
    for i, m in enumerate(found):
        if not m.get("host"):
            st.markdown(sh.machine_rows_html([m]), unsafe_allow_html=True)
            continue
        with st.container(key=f"mrow-{i}"):
            st.markdown(sh.machine_rows_html([m], link=True), unsafe_allow_html=True)
            if st.button(f"Open {m['name']}", key=f"mopen-{i}", width="stretch"):
                open_machine(m["host"])


def panel_address() -> str:
    """Where a new machine should reach this panel: SENTRAI_PANEL_URL (here or on the core), else the
    address this page was opened on, unless that is this computer itself."""
    url = os.environ.get("SENTRAI_PANEL_URL", "").strip()
    if not url:
        info, _ = safe(client.fleet_panel, {})
        url = str((info or {}).get("panel_url") or "")
    if not url:
        page = urlsplit(str(getattr(st.context, "url", "") or ""))
        if page.scheme == "https" and page.hostname not in (None, "localhost", "127.0.0.1", "::1"):
            url = f"https://{page.netloc}"
    return url.rstrip("/") or os.environ.get("SENTRAI_PUBLIC_URL") or st.session_state.core_url


def add_machine(panel: bool) -> None:
    """The join-code form behind the + on the machine list."""
    with st.container(border=True):
        section("Add machine", "a one-time join code, valid for 24 hours", "add_circle")
        if not panel:
            empty("Turn on central panel mode first (see the note above).", "info")
            return
        name = st.text_input("Machine name (optional)", key="join_name", placeholder="web-01",
                             help="Leave empty to use the new machine's own host name")
        url = st.text_input("Panel address the machine will use", key="join_url", value=panel_address(),
                            help="Must be https:// from another machine (install.sh --panel opens port 8443)")
        if st.button("Make join code", icon=":material/key:", type="primary", key="join_make",
                     disabled=locked("configure"), help=why_locked("configure")):
            try:
                st.session_state["join_made"] = client.join_code(st.session_state.operator, name.strip() or None)
            except CoreError as exc:
                st.session_state["flash"] = (f"Could not make a join code: {exc}", WARN_ICON)
                st.rerun(scope="fragment")
        made = st.session_state.get("join_made")
        if made:
            st.markdown(f'Join code <b>{html.escape(str(made["code"]))}</b> · works once, until '
                        f'{html.escape(f"{ts:%d %b %H:%M}" if (ts := sh.parse_ts(made.get("expires_at"))) else "-")}', unsafe_allow_html=True)
            pin = made.get("pin") if url.startswith("https://") else None
            cmds = sh.join_commands(url, made["code"], made.get("name"), pin)
            st.caption("On a Linux server, from a SentrAI checkout:")
            st.code(cmds["linux"], language="bash")
            st.caption("On Windows, from a SentrAI checkout in an Administrator PowerShell:")
            st.code(cmds["windows"], language="powershell")
            if pin:
                st.caption("The --pin is this panel's certificate fingerprint: the machine will talk to this "
                           "panel and nothing pretending to be it.")
            if not url.startswith("https://"):
                st.warning("Other machines refuse a plain http:// panel. Install the panel with "
                           "sudo ./deploy/install.sh --panel to open its HTTPS port for agents.",
                           icon=":material/lock_open:")
            elif not pin:
                st.info("No certificate pin is known (SENTRAI_PANEL_CERT is not set), so the machine checks the "
                        "panel's certificate against the usual authorities.", icon=":material/lock:")


@st.fragment(run_every=AUTO)
def page_machines() -> None:
    show_flash()
    risk = header("Machines", "every computer that reports to this panel, and adding a new one")
    if risk is None:
        return
    found = machines()
    panel = panel_mode(risk)
    online = sum(1 for m in found if m["online"])
    attacked = [m for m in found if m.get("open") or m["band"] in ("red", "critical")]
    stats(("Machines", str(len(found)), "joined this panel" if panel else "this computer and SENTRAI_PEERS"),
          ("Online", str(online), f"{len(found) - online} offline or waiting",
           sh.BAND_COLORS["amber"] if online < len(found) else None),
          ("Need a look", str(len(attacked)), "open incidents or red and above",
           sh.BAND_COLORS["red"] if attacked else None),
          ("Blocks in force", str(sum(m.get("blocked", 0) for m in found)), "each on its own machine"))
    if not panel:
        st.info("This core adds every machine into one score. To run it as a central panel, set "
                "SENTRAI_RISK_SCOPE=host (and SENTRAI_FIREWALL=off) on it and restart the core: each machine is then "
                "scored and blocked on its own.", icon=":material/info:")

    with st.container(border=True):
        title, plus = st.columns([9, 2], vertical_alignment="center")
        with title:
            section("Machine list", "worst first · click a machine for its details · SentrAI acts on a machine "
                    "when its own score passes the threshold", "dns")
        if plus.button("Add machine", icon=":material/add:", key="add_toggle", help="Show the join command for a new machine",
                       width="stretch",
                       type="primary" if st.session_state.get("add_open") else "secondary"):
            st.session_state["add_open"] = not st.session_state.get("add_open")
            st.rerun(scope="fragment")
        if st.session_state.get("add_open"):
            add_machine(panel)
        machine_list(found, panel)

    if panel:
        agents, aerr = fetch("fleet", [])
        with st.container(border=True):
            section("Joined machines", "each has its own key; revoking one never touches the others", "key")
            if aerr:
                st.warning(f"Could not load joined machines: {aerr}")
            table(sh.agent_rows(agents or []), "No machine has joined yet. Make a join code above.")
            if agents:
                st.caption("To stop accepting a machine's key, open the machine and use Revoke on its Agent tab.")


# ------------------------------------------------------------------ one machine's page

def _tab_to_address() -> None:
    """A new tab goes into the address, so a link or the Back button brings the same tab back."""
    slug = MACHINE_TABS.get(st.session_state.get("machine_tab", ""), "")
    if slug:
        st.query_params["tab"] = slug
    else:
        st.query_params.pop("tab", None)


def _show_tab(tab: str) -> None:
    st.session_state.machine_tab = tab
    _tab_to_address()


def machine_note(m: dict, agent: dict | None) -> str:
    """The line under a machine's name: what watches it, since when, and what runs on it."""
    if agent:
        joined = sh.parse_ts(agent.get("joined_at"))
        parts = [f"SentrAI agent {agent.get('agent_id')}",
                 f"joined {joined:%d %b %H:%M}" + (f" by {agent['invited_by']}" if agent.get("invited_by") else "")
                 if joined else ""]
    else:
        parts = ["Known from logs only: no SentrAI agent runs on it"]
    if m.get("services"):
        parts.append(sh.services_text(m["services"]))
    return " · ".join(p for p in parts if p)


@st.fragment(run_every=AUTO)
def page_machine() -> None:
    """One machine's own page, laid out like a server's page in Pterodactyl or Calagopus: a status card
    with its quick actions (their power buttons), then tabs. Its address can be bookmarked or shared."""
    show_flash()
    host = str(st.session_state.get("machine") or "")
    found = machines()
    m = next((x for x in found if x.get("host") == host), None)
    back, _, pick = st.columns([2, 5, 3], vertical_alignment="center")
    if back.button("All machines", icon=":material/arrow_back:", type="tertiary", key="machine_back"):
        go("machines")
    hosts = [x["host"] for x in found if x.get("host")]
    if m is not None and len(hosts) > 1:
        other = pick.selectbox("Switch machine", hosts, index=hosts.index(host), key=f"machine_pick_{host}",
                               label_visibility="collapsed", help="Open another machine on the same tab")
        if other != host:
            open_machine(other, st.session_state.get("machine_tab", "Overview"))
    agents, _ = fetch("fleet", [])
    mine = [a for a in agents or [] if isinstance(a, dict) and a.get("host") == host]
    agent = next((a for a in mine if not a.get("revoked_at")), None)
    risk = header(m["name"] if m else host or "Machine", machine_note(m, agent) if m else "", eyebrow="Machines")
    if risk is None:
        return
    if m is None:
        why = "" if panel_mode(risk) else " Machine pages need central panel mode (SENTRAI_RISK_SCOPE=host)."
        empty(f"No machine called {host or '(none)'} reports to this panel. It may have been revoked, or the "
              f"link is out of date.{why}", "search_off")
        return

    card, actions = st.columns([3, 2], vertical_alignment="center")
    card.markdown(sh.machine_rows_html([m], status=True), unsafe_allow_html=True)
    with actions:
        b1, b2 = st.columns(2)
        why = None if m.get("agent_id") else "Scans and backups run through SentrAI's agent, and this machine has none."
        off = not m.get("agent_id") or locked()
        if b1.button("Scan for threats", icon=":material/policy:", key="job_scan", width="stretch", disabled=off,
                     help=why or why_locked(otherwise="Its agent scans the folders set on that machine")):
            run_action(f"Asked {host} to scan for threats",
                       lambda: client.queue_job(host, "threat_scan", st.session_state.operator))
        if b2.button("Back up now", icon=":material/backup:", key="job_backup", width="stretch", disabled=off,
                     help=why or why_locked(otherwise="Its agent backs up the folders set on that machine")):
            run_action(f"Asked {host} to back up", lambda: client.queue_job(host, "backup", st.session_state.operator))

    incs, ierr = safe(lambda: client.machine_incidents(host), [])
    if ierr:
        st.warning(f"Could not load its incidents: {ierr}")
    incs = incs or []
    tabs = st.tabs(list(MACHINE_TABS), key="machine_tab", on_change=_tab_to_address)
    for tab, show in zip(tabs, (machine_overview, machine_incidents, machine_blocks, machine_services,
                                machine_jobs_tab, machine_agent)):
        if tab.open:
            with tab:
                show(m, incs, agent, mine)


def machine_overview(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    """Its console: the live log of what SentrAI saw and did there, beside its own risk over time."""
    host = m["host"]
    waiting = sh.pending_approvals(incs)
    if waiting:
        lead, btn = st.columns([4, 1], vertical_alignment="center")
        lead.markdown(f'<div class="lead">{icon("pending_actions")}<span>{html.escape(sh.approvals_headline(waiting))}'
                      f'</span></div>', unsafe_allow_html=True)
        btn.button("Open its incidents", key="to_incidents", width="stretch", on_click=_show_tab, args=("Incidents",))
    records, _, _ = audit_records()
    log = sh.build_activity_feed(sh.machine_records(records, host, [i.get("id") for i in incs]), limit=80)
    left, right = st.columns([7, 5])
    with left, st.container(border=True):
        section("Live log", "what SentrAI saw and did on this machine, newest first", "terminal")
        if log:
            st.markdown(sh.console_html(log, f"Live log for {host}"), unsafe_allow_html=True)
        else:
            empty(f"Nothing recorded about {host} yet.", "terminal")
    with right, st.container(border=True):
        section("Risk over time", "this machine's own score · dashed line is the threshold", "show_chart")
        own, err = safe(lambda: client.machine_risk(host), {})
        hist = sh.history_frame((own or {}).get("history"))
        if err or hist.empty:
            empty("No history yet. The panel adds a point whenever its score changes.", "show_chart")
        else:
            st.plotly_chart(sh.history_figure(hist, float((own or {}).get("threshold") or m["threshold"] or 80)),
                            width="stretch", config={"displayModeBar": False}, key="machine_history")


def machine_incidents(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    waiting = sh.pending_approvals(incs)
    with st.container(border=True):
        section("Waiting on you", "approve or reject, keep or roll back", "approval_delegation")
        if not waiting:
            empty(f"Nothing on {m['host']} waits for a decision.", "check_circle", good=True)
        for inc in waiting:
            verb = "Approve or reject" if sh.available_actions(inc)["decide"] else "Keep or roll back"

            def details(inc=inc) -> None:
                incident_summary(inc)
                decision_controls(inc)
                table(sh.action_rows(inc), "No containment actions yet.")
            incident_row(inc, "mach", verb, details)
    with st.container(border=True):
        section("All its incidents", "what adds to its own score, one row per incident", "calculate")
        table(sh.risk_breakdown(incs), f"All quiet on {m['host']}. No incidents.")


def machine_blocks(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    """Its firewall, as a game panel's Network tab: what is blocked there right now, and every action taken."""
    host = m["host"]
    blocks, err = safe(lambda: client.machine_blocklist(host), {"ips": [], "users": []})
    with st.container(border=True):
        section("In force on this machine", "its agent puts each one in place there and takes it out when it ends",
                "block")
        if err:
            st.warning(f"Could not load its blocks: {err}")
        table(sh.build_containment_rows(blocks, incs), f"Nothing blocked on {host} right now.")
    with st.container(border=True):
        section("Every action on this machine", "each one ends on its own unless a person keeps it", "history")
        table(sh.all_action_rows(incs), f"No actions taken on {host} yet.")


def machine_services(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    at = sh.parse_ts(m.get("services_at"))
    with st.container(border=True):
        section("Services", "what listens on it, reported by its agent every minute"
                + (f" · last report {sh.seen_ago(at)}" if at else ""), "lan")
        table(sh.service_rows(m.get("services")),
              "No services reported yet." if m.get("agent_id") else "No agent on this machine reports its services.")


def machine_jobs_tab(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    host = m["host"]
    with st.container(border=True):
        section("Scans and backups", "asked with the buttons above · its agent picks each one up within about "
                "15 seconds and runs it on the folders set on that machine", "policy")
        if not m.get("agent_id"):
            empty("Scans and backups run through SentrAI's agent, and this machine has none.", "info")
            return
        jobs, jerr = safe(lambda: client.machine_jobs(host), [])
        if jerr:
            st.warning(f"Could not load its scans and backups: {jerr}")
        table(sh.job_rows(jobs or []), f"Nothing asked of {host} yet.")
        found_now = sh.job_findings(jobs or [])
        if not found_now.empty:
            st.caption("What its latest threat scan found (critical and high ones also open an incident)")
            table(found_now, "")


def machine_agent(m: dict, incs: list[dict], agent: dict | None, mine: list[dict]) -> None:
    """Its agent and key, with Revoke, as a game panel's Settings tab with its danger zone."""
    host = m["host"]
    old = [a for a in mine if a.get("revoked_at")]
    with st.container(border=True):
        section("Agent", "the SentrAI program on the machine: it sends the logs and puts the blocks in place", "key")
        if agent is None:
            empty(f"No SentrAI agent runs on {host}: the panel only knows it from the logs it was sent. "
                  "To watch and protect it directly, add it with + Add machine on the Machines page.", "info")
        else:
            st.markdown('<div class="detail-grid three">' + "".join(
                f'<div><span>{html.escape(k)}</span><b>{html.escape(v)}</b></div>' for k, v in sh.agent_facts(agent))
                + '</div>', unsafe_allow_html=True)
        if old:
            st.caption("Earlier keys for this machine")
            table(sh.agent_rows(old), "")
    if agent is None:
        return
    with st.container(border=True):
        section("Revoke its key", "it can join again later with a new join code", "block")
        st.caption(f"The panel stops accepting {host}'s key at once: its agent can no longer send logs or pick up "
                   "scans and backups. Blocks it already put in place end on their own.")
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        sure = c1.checkbox("Yes, stop accepting its key", key=f"revoke_sure_{host}")
        if c2.button("Revoke key", icon=":material/block:", key=f"revoke_{host}", width="stretch",
                     disabled=not sure or locked("configure"), help=why_locked("configure")):
            try:
                client.revoke_agent(str(agent["agent_id"]), st.session_state.operator)
            except CoreError as exc:
                st.session_state["flash"] = (f"Could not revoke {host}: {exc}", WARN_ICON)
                st.rerun(scope="fragment")
            _get.clear()  # the machine list must not show it as joined for another second
            st.session_state["flash"] = (f"Revoked {host} ({agent['agent_id']})", OK_ICON)
            go("machines")


@st.fragment(run_every=AUTO)
def page_reports() -> None:
    header("Reports", "a one-page summary for the client, and one evidence report for every incident")
    client_summary()
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
             "Report": "Ready" if i in with_report else "-"} for i in ids]
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
        state = "intact" if valid else "broken" if valid is False else "not checked"
        section("Agent activity", f"latest {len(records)} records · chain {state}", "timeline")
        if err:
            st.warning(f"Could not load audit log: {err}")
        render_feed(sh.build_activity_feed(records, limit=60))
    with right, st.container(border=True):
        section("Agents", f"who does what · records in the latest {len(records)}", "groups")
        table(sh.agent_table(agents, records), "No agents yet.")


def when(value: Any) -> str:
    """Day and time: backups are days apart, so the clock time alone is not enough."""
    ts = sh.parse_ts(value)
    return ts.strftime("%d %b %H:%M") if ts else (str(value) if value else "-")


BACKUP_REASON = {"schedule": "on schedule", "manual": "by hand", "before_restore": "safety copy before a restore"}


def page_backups() -> None:
    show_flash()
    if header("Backups", "copies of your folders and SentrAI's own records, ready to put back") is None:
        return
    data, err = safe(client.backups, None)
    if err or not data:
        st.warning(f"Backups are not available on this core. {err or ''}")
        return
    kept = data.get("backups") or []
    last = next((b for b in kept if b.get("reason") != "before_restore"), None)
    check = (last or {}).get("verified") or {}
    stats(("Last backup", when(last.get("created")) if last else "Never",
           f"{last.get('files', 0)} files · {last.get('bytes', 0) / 1048576:.1f} MB" if last else "take one below",
           sh.BAND_COLORS["amber"] if not last or data.get("overdue") else None),
          ("Next due", "Off" if not data.get("every_hours") else
           ("Now" if data.get("next_due") == "now" else when(data.get("next_due"))),
           f"every {data['every_hours']:g} h" if data.get("every_hours") else "no schedule"),
          ("Kept", f"{len(kept)} of {data.get('keep')}", "oldest removed first"),
          ("Last check", "Intact" if check.get("ok") else "Problem" if check.get("ok") is False else "Not checked",
           when(check.get("at")) if check.get("at") else "press Check on a backup",
           sh.BAND_COLORS["red"] if check.get("ok") is False else None))
    if data.get("last_error"):
        st.error(f"The last backup failed ({when(data['last_error'].get('at'))}): "
                 f"{data['last_error'].get('error')}")
    elif data.get("overdue"):
        st.warning("The last backup is more than two schedule periods old. Is SentrAI's core running?")

    with st.container(border=True):
        section("What is backed up", "change it under backup in the system profile, or SENTRAI_BACKUP_PATHS", "folder_copy")
        folders = data.get("folders") or []
        st.markdown(("Folders: " + ", ".join(code(f) for f in folders) if folders else
                     "No folders chosen yet, so only SentrAI's own data is copied.")
                    + ("  \nSentrAI's own settings, signing key and audit records: always included."
                       if data.get("include_sentrai") else "")
                    + f"  \nStored in {code(data.get('stored_in'))}"
                    + (f", with a second copy in {code(data['copy_to'])}" if data.get("copy_to") else ""),
                    unsafe_allow_html=True)
        if st.button("Back up now", icon=":material/backup:", type="primary", key="backup_now",
                     disabled=locked(), help=why_locked()):
            with st.spinner("Backing up…"):
                run_action("Backup made", lambda: client.backup_now(st.session_state.operator), rerun=False)
            st.rerun()

    with st.container(border=True):
        section("Backups kept", "newest first · a restore always checks the backup first", "inventory_2")
        if not kept:
            empty("No backups yet.", "backup")
        for b in kept:
            backup_row(b)


def backup_row(b: dict) -> None:
    bid = str(b.get("id"))
    v = b.get("verified") or {}
    state = (":green[:material/verified:] intact" if v.get("ok") else
             ":red[:material/error:] problem" if v.get("ok") is False else ":gray[:material/help:] not checked")
    c1, c2 = st.columns([5, 1])
    c1.markdown(f"**{html.escape(bid)}** · {when(b.get('created'))} · "
                f"{html.escape(BACKUP_REASON.get(str(b.get('reason')), str(b.get('reason'))))} by "
                f"{html.escape(str(b.get('by')))} · {b.get('files', 0)} files, {b.get('bytes', 0) / 1048576:.1f} MB · "
                f"{state}", unsafe_allow_html=True)
    if v.get("ok") is False:
        c1.caption("; ".join(v.get("problems") or []))
    if c2.button("Check", key=f"bk_check_{bid}", icon=":material/fact_check:"):
        run_action(f"Backup {bid} is intact", lambda: client.verify_backup(bid, st.session_state.operator),
                   rerun=False)
        st.rerun()
    with st.expander(f"Restore from {bid}"):
        with st.form(key=f"bk_restore_{bid}", border=False):
            where = st.radio("Where to put the files", ["new", "in_place"], horizontal=True, key=f"bk_where_{bid}",
                             format_func=lambda w: "Into a new folder (nothing live changes)" if w == "new"
                             else "Back where they came from (overwrites live files)")
            confirm = st.text_input(f"For 'back where they came from', type {bid} to confirm", key=f"bk_conf_{bid}")
            st.caption("Back in place first takes a safety backup of the current files, so it can be undone. "
                       "SentrAI's own data is only ever restored into a new folder.")
            go_ = st.form_submit_button("Restore", icon=":material/settings_backup_restore:",
                                        disabled=locked("configure"), help=why_locked("configure"))
        if go_:
            in_place = where == "in_place"
            with st.spinner("Restoring…"):
                run_action(f"Restored {bid}" + (" in place" if in_place else " into a new folder"),
                           lambda: client.restore_backup(bid, st.session_state.operator, in_place, confirm.strip()),
                           rerun=False)
            st.rerun()


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
            f'<div class="feed-body"><span class="agent" style="color:{e["color"]}">{icon(e["icon"])} {html.escape(e["agent"])}</span>'
            f' · <span class="feed-type">{html.escape(e["type"])}</span><br>'
            f'<span class="feed-sum">{html.escape(e["summary"])}</span> '
            f'<span class="feed-hash">{html.escape(e["hash"])}</span></div></div>'
        )
    # Focusable, so keyboard users can scroll the feed too.
    st.markdown(f'<div class="feed" tabindex="0" role="region" aria-label="Agent activity">{"".join(rows)}</div>',
                unsafe_allow_html=True)


SUMMARY_EVERY = {"daily": "Every day", "weekly": "Every week", "off": "Off"}
WEEKDAYS = {"mon": "Monday", "tue": "Tuesday", "wed": "Wednesday", "thu": "Thursday", "fri": "Friday",
            "sat": "Saturday", "sun": "Sunday"}


def client_summary() -> None:
    """The one-page client summary: how often it goes out (the client's choice) and today's or this week's page."""
    sched, err = safe(client.summary_schedule)
    if err or not isinstance(sched, dict):
        return  # an older core without the summary
    left, right = st.columns([4, 8])
    with left, st.container(border=True):
        nxt = str(sched.get("next_at") or "")[:16].replace("T", " ")
        section("Client summary", f"next: {nxt}" if nxt else "not scheduled", "event_repeat")
        with st.form("summary_schedule", border=False):
            every = st.radio("Send it", list(SUMMARY_EVERY), format_func=SUMMARY_EVERY.get, horizontal=True,
                             index=list(SUMMARY_EVERY).index(sched.get("every", "daily")))
            c1, c2 = st.columns(2)
            at = c1.text_input("At (local time)", sched.get("at", "08:00"), help="24-hour time, such as 08:00")
            day = c2.selectbox("On (weekly)", list(WEEKDAYS), format_func=WEEKDAYS.get,
                               index=list(WEEKDAYS).index(sched.get("day", "mon")))
            to = st.text_input("Addressed to", sched.get("to", "Client"),
                               help="The client's name, shown on the page. It goes out on the alert channels.")
            if st.form_submit_button("Save", icon=":material/save:", type="primary", width="stretch"):
                run_action("Summary schedule saved", lambda: client.set_summary_schedule(
                    st.session_state.operator, every, at, day, to), rerun=False)
                st.rerun()
        if st.button("Send one now", icon=":material/send:", width="stretch",
                     help="Sends the summary for the chosen period to the alert channels now"):
            run_action("Summary sent to the alert channels", lambda: client.send_summary(st.session_state.operator),
                       rerun=False)
            st.rerun()
    with right, st.container(border=True):
        period = st.segmented_control("Period", ["daily", "weekly"], default="weekly" if sched.get("every") == "weekly"
                                      else "daily", format_func=lambda p: "Last 24 hours" if p == "daily" else "Last 7 days",
                                      key="summary_period") or "daily"
        md, merr = safe(lambda: client.summary_md(period))
        if merr or not md:
            empty(f"The summary could not be made: {merr}", "error")
            return
        d0, d1 = st.columns(2)
        pdf, perr = safe(lambda: client.summary_pdf(period))
        if pdf and not perr:
            d0.download_button("PDF (one page)", pdf, icon=":material/picture_as_pdf:", file_name=f"sentrai-{period}-summary.pdf",
                               mime="application/pdf", type="primary", width="stretch", key=f"dl_sum_pdf_{period}")
        d1.download_button("Markdown", md, icon=":material/download:", file_name=f"sentrai-{period}-summary.md",
                           mime="text/markdown", width="stretch", key=f"dl_sum_md_{period}")
        with st.container(height=420, border=True):
            st.markdown(sh.demote_headings(md))


def report_viewer(inc_id: str) -> None:
    section("Evidence report", inc_id, "verified")
    md, err = safe(lambda: client.report_md(inc_id))
    if err or not md:
        empty("No report for this incident yet.", "hourglass_empty")
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


# ------------------------------------------------------------------ team

def _invite_link(code: str) -> None:
    link = f"{_base_url()}/?invite={code}"
    st.code(link, language=None)
    st.caption(f"Send this link to them yourself. It works once, for {acc.INVITE_HOURS} hours, and only "
               "opens from a computer allowed to reach this console.")


def page_team() -> None:
    """Owners and Admins: who may sign in, with which role. No open sign-up; people join by invite."""
    header("Team", "Who may sign in to this console, and what each role may do")
    if made := st.session_state.pop("team_link", None):
        with st.container(border=True):
            st.markdown(f"**{made[0]}**")
            _invite_link(made[1])
    people = acc.people()
    with st.container(border=True):
        section("People", f"{len(people)} with access", "group")
        table(sh.pd.DataFrame([{
            "Name": p["name"], "Email": p["email"], "Role": acc.ROLE_LABEL[p["role"]],
            "Authenticator": "Yes" if p["authenticator"] else "Not yet",
            "Last sign-in": _when(p["last_sign_in"]) + (f" from {p['last_ip']}" if p["last_ip"] else ""),
        } for p in people]), "No one yet.")
        st.caption("Owner and Admin run SentrAI. An Auditor sees every page and can export reports, "
                   "but changes nothing.")

    others = [p for p in people if p["email"] != ME["email"]]
    if others:
        with st.container(border=True):
            section("Change someone's access", "", "manage_accounts")
            c1, c2 = st.columns([2, 1])
            who = c1.selectbox("Person", [p["email"] for p in others], key="team_who")
            person = next(p for p in others if p["email"] == who)
            roles = [r for r in acc.ROLES if r != "owner" or ROLE == "owner"]
            role = c2.selectbox("Role", roles, format_func=acc.ROLE_LABEL.get, key="team_role",
                                index=roles.index(person["role"]) if person["role"] in roles else 0)
            b1, b2, b3 = st.columns(3)
            try:
                if b1.button("Change role", width="stretch", disabled=role == person["role"]):
                    acc.set_role(ME["email"], who, role)
                    st.session_state.flash = (f"{who} is now {acc.ROLE_LABEL[role]}", OK_ICON)
                    st.rerun()
                if b2.button("Reset sign-in", width="stretch",
                             help="Forgot the password or lost the phone: their old password stops working "
                                  "and a link lets them set both again."):
                    code = acc.reset(ME["email"], who)
                    st.session_state.team_link = (f"Reset link for {who}", code)
                    st.rerun()
                sure = b3.checkbox("I'm sure", key="team_sure")
                if b3.button("Remove", width="stretch", disabled=not sure):
                    acc.remove(ME["email"], who)
                    st.session_state.flash = (f"{who} can no longer sign in", OK_ICON)
                    st.rerun()
            except acc.AccountError as e:
                st.error(str(e))

    with st.container(border=True):
        section("Invite someone", "They set their own password and authenticator", "person_add")
        with st.form("team_invite", clear_on_submit=True):
            c1, c2 = st.columns([2, 1])
            email = c1.text_input("Their email")
            roles = [r for r in acc.ROLES if r != "owner" or ROLE == "owner"]
            role = c2.selectbox("Role", roles, index=roles.index("admin"), format_func=acc.ROLE_LABEL.get)
            if st.form_submit_button("Make invite link", type="primary"):
                try:
                    code = acc.invite(ME["email"], email, role)
                except acc.AccountError as e:
                    st.error(str(e))
                else:
                    st.session_state.team_link = (f"Invite for {email.strip().lower()} as {acc.ROLE_LABEL[role]}", code)
                    st.rerun()
        waiting = acc.pending_invites()
        if waiting:
            st.markdown("**Waiting to be used**")
            for i in waiting:
                c1, c2 = st.columns([4, 1], vertical_alignment="center")
                kind = "reset" if i["reset"] else acc.ROLE_LABEL[i["role"]]
                c1.caption(f"{i['email']} · {kind} · by {i['by']} · until {_when(i['expires'])}")
                if c2.button("Withdraw", key=f"withdraw_{i['email']}", width="stretch"):
                    try:
                        acc.withdraw_invite(ME["email"], i["email"])
                    except acc.AccountError as e:
                        st.error(str(e))
                    else:
                        st.rerun()


if not page_allowed(st.session_state.page):
    st.session_state.page = "config"
{
    "config": page_config, "approvals": page_approvals, "incidents": page_incidents, "staff": page_staff, "chat": page_chat,
    "flow": page_flow, "collector": page_collector, "classifier": page_classifier, "responder": page_responder, "machines": page_machines,
    "review": page_review, "reports": page_reports, "audit": page_audit, "machine": page_machine,
    "backups": page_backups, "team": page_team, "extensions": page_extensions,
    "integrations": page_extensions,  # the page's name before extensions
}[st.session_state.page]()
