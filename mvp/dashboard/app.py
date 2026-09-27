"""CactAI operator dashboard (Streamlit, http://127.0.0.1:8501).

Run from this folder:  .venv\\Scripts\\streamlit run app.py
"""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Any

import streamlit as st

from cactai_ui import shaping as sh
from cactai_ui.api import CoreClient, CoreError

DEFAULT_CORE = os.environ.get("CACTAI_CORE_URL", "http://127.0.0.1:8000")
DEFAULT_OPERATOR = os.environ.get("CACTAI_OPERATOR", "erick")
REFRESH_SECONDS = 2

st.set_page_config(page_title="CactAI · Risk Console", page_icon="🌵", layout="wide",
                   initial_sidebar_state="expanded")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');
html, body, [class*="css"], .stMarkdown, .stText { font-family: 'Inter', 'Segoe UI', sans-serif; }
.stApp { background: radial-gradient(1200px 600px at 10% -10%, rgba(63,181,106,0.10), transparent 60%),
                      radial-gradient(900px 500px at 110% 0%, rgba(208,59,59,0.07), transparent 60%), #0f1210; }
.block-container { padding-top: 1.4rem; padding-bottom: 2rem; max-width: 1500px; }
section[data-testid="stSidebar"] { background: #121613; border-right: 1px solid rgba(255,255,255,0.06); }
.cact-head { display:flex; align-items:center; justify-content:space-between; gap:1rem; flex-wrap:wrap; margin-bottom:.6rem; }
.cact-brand { display:flex; align-items:center; gap:.7rem; }
.cact-logo { font-size:2.6rem; line-height:1; filter: drop-shadow(0 0 12px rgba(63,181,106,.45)); }
.cact-name { font-size:2rem; font-weight:800; letter-spacing:-.02em; color:#f2f4f1; line-height:1; }
.cact-name span { color:#3fb56a; }
.cact-tag { color:#9aa096; font-size:.85rem; margin-top:.25rem; }
.pill { display:inline-flex; align-items:center; gap:.4rem; padding:.28rem .7rem; border-radius:999px;
        font-size:.78rem; font-weight:700; letter-spacing:.04em; border:1px solid rgba(255,255,255,.12); }
.pill .dot { width:.55rem; height:.55rem; border-radius:50%; display:inline-block; }
.cact-card { background: rgba(24,29,25,.82); border:1px solid rgba(255,255,255,.07); border-radius:14px;
             padding: .9rem 1.1rem; }
.kpi-label { color:#9aa096; font-size:.72rem; text-transform:uppercase; letter-spacing:.09em; font-weight:600; }
.kpi-value { color:#f2f4f1; font-size:1.9rem; font-weight:800; line-height:1.15; }
.kpi-sub { color:#80867d; font-size:.75rem; }
.sec-title { color:#f2f4f1; font-weight:700; font-size:1.05rem; margin:.2rem 0 .5rem 0; display:flex; gap:.5rem; align-items:center; }
.sec-title small { color:#80867d; font-weight:500; font-size:.78rem; }
.feed { display:flex; flex-direction:column; gap:.35rem; max-height: 640px; overflow-y:auto; padding-right:.3rem; }
.feed-row { display:grid; grid-template-columns: 4.6rem 7.8rem 1fr; gap:.5rem; align-items:start;
            padding:.4rem .55rem; border-radius:9px; background:rgba(255,255,255,.025); font-size:.82rem; }
.feed-time { color:#80867d; font-family:'JetBrains Mono', monospace; font-size:.75rem; padding-top:.1rem; }
.agent { font-weight:700; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.feed-type { color:#dfe3dc; font-weight:600; }
.feed-sum { color:#9aa096; }
.feed-hash { color:#5f665c; font-family:'JetBrains Mono', monospace; font-size:.7rem; }
.detail-grid { display:grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap:.6rem; margin:.4rem 0 .8rem 0; }
.detail-grid div { background:rgba(255,255,255,.03); border-radius:10px; padding:.5rem .7rem; }
.detail-grid b { display:block; color:#f2f4f1; font-size:1rem; }
.detail-grid span { color:#80867d; font-size:.7rem; text-transform:uppercase; letter-spacing:.08em; }
.reco { border-left:3px solid #3fb56a; background:rgba(63,181,106,.08); padding:.7rem .9rem; border-radius:8px; color:#e8ece5; }
.reco b { color:#3fb56a; font-size:.72rem; letter-spacing:.09em; text-transform:uppercase; display:block; margin-bottom:.2rem; }
.offline { border:1px solid rgba(208,59,59,.5); background:rgba(208,59,59,.1); border-radius:14px; padding:1.2rem 1.4rem; color:#f2d6d6; }
div[data-testid="stForm"] { border:1px solid rgba(255,255,255,.08); border-radius:12px; }
@media (max-width: 900px) { .detail-grid { grid-template-columns: repeat(2, minmax(0,1fr)); } }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ------------------------------------------------------------------ helpers

def pill(text: str, color: str) -> str:
    return (f'<span class="pill" style="color:{color};border-color:{color}55;background:{color}14">'
            f'<span class="dot" style="background:{color}"></span>{html.escape(text)}</span>')


def kpi(label: str, value: str, sub: str = "", color: str = "#f2f4f1") -> None:
    st.markdown(
        f'<div class="cact-card"><div class="kpi-label">{html.escape(label)}</div>'
        f'<div class="kpi-value" style="color:{color}">{html.escape(value)}</div>'
        f'<div class="kpi-sub">{html.escape(sub) or "&nbsp;"}</div></div>',
        unsafe_allow_html=True,
    )


def section(title: str, note: str = "") -> None:
    st.markdown(f'<div class="sec-title">{title} <small>{html.escape(note)}</small></div>',
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


# ------------------------------------------------------------------ sidebar

with st.sidebar:
    st.markdown(
        '<div class="cact-brand"><div class="cact-logo">🌵</div><div>'
        '<div class="cact-name">Cact<span>AI</span></div>'
        '<div class="cact-tag">Proof, not just alerts.</div></div></div>',
        unsafe_allow_html=True,
    )
    st.divider()
    core_url = st.text_input("Core API URL", value=DEFAULT_CORE, key="core_url")
    operator = st.text_input("Operator name", value=DEFAULT_OPERATOR, key="operator").strip() or "operator"
    auto = st.toggle(f"Auto-refresh every {REFRESH_SECONDS} s", value=True, key="auto_refresh")
    st.divider()
    if st.button("🔄 Reset demo", width="stretch", help="POST /demo/reset: clears state for a fresh take"):
        run_action("Demo reset", lambda: CoreClient(core_url).reset_demo(), rerun=False)
        st.session_state.pop("sel_inc", None)
    st.caption("Humans stay in charge. Above the threshold the organization set, CactAI applies a "
               "temporary, reversible fix and records who was warned and when.")
    st.caption("A cactus doesn't chase you. It just makes touching it a bad idea.")

client = CoreClient(core_url)


# ------------------------------------------------------------------ main body

@st.fragment(run_every=REFRESH_SECONDS if auto else None)
def live_console() -> None:
    show_flash()
    risk, err = safe(client.risk)
    now_s = datetime.now().strftime("%H:%M:%S")

    if err or not isinstance(risk, dict):
        st.markdown(
            '<div class="cact-head"><div class="cact-brand"><div class="cact-logo">🌵</div><div>'
            '<div class="cact-name">Cact<span>AI</span> Risk Console</div></div></div>'
            + pill("CORE OFFLINE", sh.BAND_COLORS["critical"]) + "</div>",
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<div class="offline"><b>Core API unreachable</b><br>'
            f'<span style="color:#b9a5a5">{html.escape(err or "unexpected /risk payload")}</span><br><br>'
            f'Retrying every {REFRESH_SECONDS} s. Start the core (or <code>dev/fake_core.py</code>) '
            f'and check the URL in the sidebar. Last attempt {now_s}.</div>',
            unsafe_allow_html=True,
        )
        if not auto:
            st.button("Retry now")
        return

    incidents, inc_err = safe(client.incidents, [])
    audit_payload, audit_err = safe(client.audit, [])
    blocklist, bl_err = safe(client.blocklist, {"ips": [], "users": []})
    records, chain_valid = sh.normalize_audit(audit_payload)
    if chain_valid is None and records:
        chain_valid = sh.verify_chain_links(records)

    idx = risk.get("risk_index")
    band = sh.resolve_band(risk)
    color = sh.band_color(band)
    threshold = float(risk.get("threshold") or 80)

    # ---------- header
    chain_pill = (pill("CHAIN VALID ✅", sh.BAND_COLORS["green"]) if chain_valid
                  else pill("CHAIN BROKEN ❌", sh.BAND_COLORS["critical"]) if chain_valid is False
                  else pill("CHAIN UNKNOWN", sh.UNKNOWN_COLOR))
    st.markdown(
        '<div class="cact-head"><div class="cact-brand"><div class="cact-logo">🌵</div><div>'
        '<div class="cact-name">Cact<span>AI</span> Risk Console</div>'
        '<div class="cact-tag">Accountability-based security · CIA + Non-repudiation & Authentication</div>'
        '</div></div><div style="display:flex;gap:.5rem;flex-wrap:wrap">'
        + pill(sh.BAND_LABELS.get(band, band).upper(), color)
        + chain_pill
        + pill(f"LIVE · {now_s}" if auto else f"PAUSED · {now_s}", "#3fb56a" if auto else sh.UNKNOWN_COLOR)
        + "</div></div>",
        unsafe_allow_html=True,
    )

    # ---------- KPIs
    active = [i for i in incidents if i.get("status") in sh.ACTIVE_STATUSES]
    breached = [i for i in incidents if i.get("sla_breached")]
    containment = sh.build_containment_rows(blocklist, incidents)
    penalty = sum(float(i.get("inaction_penalty") or 0) for i in active)
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        kpi("Risk index", f"{idx if idx is not None else '-'} / 100", f"raw score {risk.get('raw_score', '-')}", color)
    with k2:
        kpi("Open incidents", str(len(active)), f"{len(incidents)} total")
    with k3:
        kpi("Inaction penalty", f"+{penalty:.0f}", "+5 per demo-hour unacknowledged",
            sh.BAND_COLORS["amber"] if penalty else "#f2f4f1")
    with k4:
        kpi("SLA breached", str(len(breached)), "policy SLA 2 h",
            sh.BAND_COLORS["critical"] if breached else "#f2f4f1")
    with k5:
        kpi("Active containment", str(len(containment)), f"threshold {threshold:.0f}")

    st.write("")

    # ---------- gauge + history
    g, h = st.columns([5, 7])
    with g:
        with st.container(border=True):
            section("Risk gauge", f"threshold {threshold:.0f} · white line")
            st.plotly_chart(sh.gauge_figure(idx, threshold, band), width="stretch",
                            config={"displayModeBar": False}, key="gauge")
            st.markdown(f'<div style="text-align:center;margin-top:-.4rem">{pill(sh.BAND_LABELS.get(band, band), color)}</div>',
                        unsafe_allow_html=True)
    with h:
        with st.container(border=True):
            section("Risk over time", "step line · bands green / amber / red / critical")
            hist = sh.history_frame(risk.get("history"))
            if hist.empty:
                st.info("No history yet. The core will append a point on every risk change.")
            else:
                st.plotly_chart(sh.history_figure(hist, threshold), width="stretch",
                                config={"displayModeBar": False}, key="history")

    # ---------- incident queue
    with st.container(border=True):
        section("Incident queue", "open first · penalties tick while nobody acts")
        if inc_err:
            st.warning(f"Could not load incidents: {inc_err}")
        table = sh.build_incident_table(incidents)
        if table.empty:
            st.success("🌵 Quiet desert. No incidents.")
        else:
            st.dataframe(
                table, hide_index=True, width="stretch",
                column_config={
                    "Confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
                    "Inaction penalty": st.column_config.NumberColumn("Inaction penalty", format="+%d pts"),
                    "Points": st.column_config.NumberColumn("Points", format="%.1f"),
                    "SLA breached": st.column_config.CheckboxColumn("SLA breached"),
                },
            )

    # ---------- detail + side panels
    left, right = st.columns([7, 5])
    with left:
        selected = incident_detail(incidents)
    with right:
        with st.container(border=True):
            section("🛡️ Active containment", "enforced via /blocklist")
            if bl_err:
                st.warning(f"Could not load blocklist: {bl_err}")
            if containment.empty:
                st.caption("Nothing contained right now.")
            else:
                st.dataframe(containment, hide_index=True, width="stretch")
        with st.container(border=True):
            badge = ('<span style="color:#0ca30c">Chain valid ✅</span>' if chain_valid
                     else '<span style="color:#d03b3b">Chain BROKEN ❌</span>' if chain_valid is False
                     else '<span style="color:#8a8f98">Chain status unknown</span>')
            section(f"🤖 Agent activity &nbsp;{badge}", f"{len(records)} hash-chained records")
            if audit_err:
                st.warning(f"Could not load audit log: {audit_err}")
            render_feed(sh.build_activity_feed(records))

    if selected:
        with st.container(border=True):
            report_viewer(selected)


def render_feed(feed: list[dict]) -> None:
    if not feed:
        st.caption("No audit records yet.")
        return
    rows = []
    for e in feed:
        rows.append(
            f'<div class="feed-row"><div class="feed-time">{html.escape(e["time"])}<br>'
            f'<span class="feed-hash">#{e["seq"] if e["seq"] is not None else "-"}</span></div>'
            f'<div class="agent" style="color:{e["color"]}">{e["icon"]} {html.escape(e["agent"])}</div>'
            f'<div><span class="feed-type">{html.escape(e["type"])}</span><br>'
            f'<span class="feed-sum">{html.escape(e["summary"])}</span> '
            f'<span class="feed-hash">{html.escape(e["hash"])}</span></div></div>'
        )
    st.markdown(f'<div class="feed">{"".join(rows)}</div>', unsafe_allow_html=True)


def incident_detail(incidents: list[dict]) -> str | None:
    with st.container(border=True):
        section("🔎 Incident detail")
        if not incidents:
            st.caption("Select an incident once one is opened.")
            return None
        by_id = {i.get("id"): i for i in incidents if i.get("id")}
        # Stable newest-first order; remember the choice ourselves so it survives option changes.
        ids = sorted(by_id, key=lambda i: (str(by_id[i].get("opened_at") or ""), i), reverse=True)
        sel = st.session_state.get("sel_inc")
        if sel not in by_id:
            sel = sh.pick_default_incident(incidents)
        inc_id = st.selectbox(
            "Incident", ids, index=ids.index(sel), label_visibility="collapsed",
            format_func=lambda i: f"{i} · {sh.category_label(by_id[i].get('category'))} · {by_id[i].get('status')}",
        )
        st.session_state["sel_inc"] = inc_id
        inc = by_id[inc_id]
        sev_color = {"low": "#0ca30c", "medium": "#fab219", "high": "#ec835a", "critical": "#d03b3b"}.get(
            str(inc.get("severity")), sh.UNKNOWN_COLOR)
        st.markdown(
            f'<div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">'
            f'<span style="font-size:1.25rem;font-weight:800;color:#f2f4f1">{html.escape(inc_id)}</span>'
            f'{pill(str(inc.get("severity", "?")).upper(), sev_color)}'
            f'{pill(sh.status_label(inc.get("status")), "#b9bdb4")}'
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
            st.markdown(f"_{inc['explanation']}_")
        st.markdown(f'<div class="reco"><b>Recommended action</b>{html.escape(str(inc.get("recommended_action") or "-"))}</div>',
                    unsafe_allow_html=True)
        st.write("")

        can = sh.available_actions(inc)
        if can["decide"]:
            if can["ack"] and st.button("👁️ Acknowledge", key=f"ack_{inc_id}",
                                        help="Records that you have seen this alert (POST /ack)"):
                run_action(f"Acknowledged {inc_id}", lambda: client.ack(inc_id, st.session_state.operator))
            with st.form(key=f"decide_{inc_id}", clear_on_submit=True, border=True):
                just = st.text_area("Justification (required to reject, written to the audit log)",
                                    key=f"just_{inc_id}", height=80,
                                    placeholder="e.g. False positive: this IP is our penetration tester")
                c1, c2 = st.columns(2)
                approve = c1.form_submit_button("✅ Approve & Patch", type="primary", width="stretch")
                reject = c2.form_submit_button("⛔ Reject with Justification", width="stretch")
            op = st.session_state.operator
            if approve:
                def _approve() -> None:
                    try:
                        client.ack(inc_id, op)
                    except CoreError:
                        pass
                    client.decision(inc_id, op, "approve", just.strip())
                run_action(f"Approved & patched {inc_id}", _approve)
            elif reject:
                if not just.strip():
                    st.toast("⚠️ Rejecting requires a written justification.", icon="⛔")
                    st.error("Rejecting requires a written justification.")
                else:
                    def _reject() -> None:
                        try:
                            client.ack(inc_id, op)
                        except CoreError:
                            pass
                        client.decision(inc_id, op, "reject", just.strip())
                    run_action(f"Rejected {inc_id}", _reject)
        elif can["contain_controls"]:
            with st.form(key=f"contain_{inc_id}", clear_on_submit=True, border=True):
                just = st.text_area("Justification (written to the audit log)", key=f"cjust_{inc_id}", height=70,
                                    placeholder="e.g. Verified attacker; keep the block")
                c1, c2 = st.columns(2)
                rb = c1.form_submit_button("↩️ Rollback", width="stretch")
                perm = c2.form_submit_button("📌 Make Permanent", type="primary", width="stretch")
            op = st.session_state.operator
            if rb:
                run_action(f"Rolled back {inc_id}",
                           lambda: client.rollback(inc_id, op, just.strip() or "Rolled back by operator from dashboard"))
            elif perm:
                run_action(f"Made permanent {inc_id}",
                           lambda: client.permanent(inc_id, op, just.strip() or "Made permanent by operator from dashboard"))
        else:
            st.caption(f"No operator action available (status: {inc.get('status')}).")

        acts = sh.action_rows(inc)
        if not acts.empty:
            st.markdown("**Containment actions**")
            st.dataframe(acts, hide_index=True, width="stretch")
    return inc_id


def report_viewer(inc_id: str) -> None:
    section("📄 Negligence report", "GET /reports/{id}.md")
    md, err = safe(lambda: client.report_md(inc_id))
    if err or not md:
        st.caption("No report for this incident yet. Scribe generates one when autonomous containment fires.")
        return
    d1, d2 = st.columns(2)
    d1.download_button("⬇️ Download report (.md)", md, file_name=f"{inc_id}-negligence-report.md",
                       mime="text/markdown", width="stretch", key=f"dl_md_{inc_id}")
    rep_json, jerr = safe(lambda: client.report_json(inc_id))
    if rep_json is not None and not jerr:
        d2.download_button("⬇️ Download report (.json)", json.dumps(rep_json, indent=2), file_name=f"{inc_id}-negligence-report.json",
                           mime="application/json", width="stretch", key=f"dl_json_{inc_id}")
    with st.container(height=460, border=True):
        st.markdown(sh.demote_headings(md))


live_console()
