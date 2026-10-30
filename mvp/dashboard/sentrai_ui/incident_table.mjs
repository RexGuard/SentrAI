/* The Incidents page's lists as one table each: a line per incident, its quick buttons at the end of the line.

   One component draws the whole list, so 300 incidents cost one element on the Streamlit side instead of
   300 cards with 8 buttons each. Filtering and "Show more" happen here, without a round trip. A button
   that needs a reason (Reject, Make permanent) opens a small line under its row to type it.

   With pick (Approvals), a tick box starts each row, and with groups the rows sit under a header row per group
   ("198.51.100.7 · 12 waiting") that folds, with a tick box that picks the whole group.

   Python gets three kinds of events, each with a fresh n so the same click is never acted on twice:
     act  {id, a, reason, n}   a quick button was pressed (a is the action, as shaping.quick_action_list names it)
     open {id, n}              a row was clicked: Python draws that incident's card under the table
     pick {ids, on, n}         tick boxes: these incidents are picked (on) or not any more
   A Streamlit component (st.components.v2): no iframe, nothing from the internet, colours from the console. */

/** The rows whose text holds every word of the filter (case-insensitive). */
export function filterRows(rows, query) {
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  if (!words.length) return rows || [];
  return (rows || []).filter((r) => {
    const hay = [r.id, ...(r.cells || [])].join(" ").toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

/** "Showing 25 of 300", or "300 incidents" when they all fit. */
export function countLine(shown, total, filtered) {
  const noun = (n) => `${n} incident${n === 1 ? "" : "s"}`;
  if (filtered !== total) return shown < filtered ? `Showing ${shown} of ${filtered} matching (${total} in all)`
    : `${noun(filtered)} matching (${total} in all)`;
  return shown < total ? `Showing ${shown} of ${total}` : noun(total);
}

// What, Machine, Status, Owner, Open for, Needs: the classes of the cells after the id and the severity.
const CELL_CLASS = ["wrap", "cut", null, "cut", null, "wrap it-needs"];

/** The groups as they are drawn: each with the rows that pass the filter, in the group's order; a group with
    none left is not drawn. Without groups, one unnamed group of every row. */
export function groupRows(rows, groups) {
  if (!groups || !groups.length) return [{ label: "", rows: rows || [] }];
  const byId = new Map((rows || []).map((r) => [r.id, r]));
  return groups.map((g) => ({ label: g.label, rows: (g.ids || []).map((id) => byId.get(id)).filter(Boolean) }))
    .filter((g) => g.rows.length);
}

/** A tick box for a set of ids: "all", "some" or "none" of them picked. */
export function pickState(ids, picked) {
  const n = ids.filter((id) => picked.has(id)).length;
  return n === 0 ? "none" : n === ids.length ? "all" : "some";
}

let seq = 0;
export const nonce = () => `${Date.now().toString(36)}-${(seq += 1)}`;

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid);
  return el;
}
const icon = (name) => h("span", { class: "mi", "aria-hidden": "true" }, name);

const tables = new WeakMap();

export default function mount(component) {
  const { parentElement, data, setTriggerValue } = component;
  let t = tables.get(parentElement);
  if (!t) {
    t = new IncidentTable(parentElement);
    tables.set(parentElement, t);
  }
  t.update(data || {}, setTriggerValue);
}

class IncidentTable {
  constructor(root) {
    this.limit = 0;          // rows shown; grows with Show more, set from page_size on the first draw
    this.query = "";
    this.asking = null;      // {id, a} while a reason line is open
    this.busy = new Set();   // "id:a" pressed and not answered by a new draw yet
    this.folded = new Set(); // group labels folded away
    this.filter = h("input", { class: "it-in", type: "search", placeholder: "Filter: id, address, owner, machine…",
                               "aria-label": "Filter the incidents", oninput: () => {
                                 this.query = this.filter.value; this.draw(); } });
    this.count = h("span", { class: "it-count", "aria-live": "polite" });
    this.body = h("tbody");
    this.head = h("thead");
    this.foot = h("div", { class: "it-foot" });
    this.wrap = h("div", { class: "it" },
      h("div", { class: "it-bar" }, this.filter, this.count),
      h("div", { class: "it-scroll" }, h("table", { class: "it-table" }, this.head, this.body)),
      this.foot);
    root.append(this.wrap);
  }

  update(data, setTrigger) {
    this.data = data;
    this.setTrigger = setTrigger;
    this.busy.clear();  // a new draw from Python answers every press made before it
    if (!this.limit) this.limit = data.page_size || 25;
    if (this.asking && !(data.rows || []).some((r) => r.id === this.asking.id)) this.asking = null;
    this.picked = new Set(data.picked || []);
    this.head.replaceChildren(h("tr", {}, data.pick ? h("th", { scope: "col", class: "it-pick" },
                                  h("span", { class: "it-sr" }, "Pick")) : null,
                                ...(data.columns || []).map((c) => h("th", { scope: "col" }, c)),
                                h("th", { scope: "col", class: "it-act-h" }, h("span", { class: "it-sr" }, "Actions"))));
    this.draw();
  }

  draw() {
    const all = this.data.rows || [];
    const rows = filterRows(all, this.query);
    const groups = groupRows(rows, this.data.groups);
    const total = groups.reduce((n, g) => n + g.rows.length, 0);
    this.filter.hidden = all.length <= 5;
    const cols = (this.data.columns || []).length + 1 + (this.data.pick ? 1 : 0);
    const out = [];
    if (!all.length || !total) {
      out.push(h("tr", { class: "it-empty" }, h("td", { colspan: cols },
        all.length ? "Nothing matches the filter." : this.data.empty || "Nothing here.")));
    }
    let left = this.limit;  // Show more counts incident rows, not group headers
    let shown = 0;
    for (const g of groups) {
      if (left <= 0) break;
      if (g.label) out.push(this.groupRow(g, cols));
      if (g.label && this.folded.has(g.label)) continue;
      for (const r of g.rows.slice(0, left)) {
        out.push(this.row(r));
        if (this.asking && this.asking.id === r.id) out.push(this.reasonRow(r, cols));
      }
      const n = Math.min(left, g.rows.length);
      left -= n;
      shown += n;
    }
    // Folded groups count as shown: their rows are one click away, not behind Show more.
    const hidden = groups.filter((g) => g.label && this.folded.has(g.label)).reduce((n, g) => n + g.rows.length, 0);
    shown = Math.min(total, shown + hidden);
    this.count.textContent = all.length ? countLine(shown, all.length, total) : "";
    this.body.replaceChildren(...out);
    const more = total - shown;
    const size = this.data.page_size || 25;
    this.foot.replaceChildren(...(more > 0 ? [
      h("button", { class: "it-btn", type: "button", onclick: () => { this.limit += size; this.draw(); } },
        icon("expand_more"), `Show ${Math.min(size, more)} more`),
      more > size ? h("button", { class: "it-btn ghost", type: "button",
                                  onclick: () => { this.limit = total; this.draw(); } }, `Show all ${total}`) : null,
    ] : []));
  }

  row(r) {
    const [id, sev, ...rest] = r.cells;
    const selected = r.open && r.id === this.data.selected;
    const tr = h("tr", { class: `it-row${r.open ? " openable" : ""}${selected ? " selected" : ""}`,
                         tabindex: r.open ? "0" : null, "aria-selected": r.open ? String(selected) : null,
                         title: r.open ? "Open this incident to assign, resolve or decide" : null },
      this.data.pick ? h("td", { class: "it-pick" }, this.pickBox([r.id], `Pick ${r.id}`)) : null,
      h("td", { class: "it-id" }, id),
      h("td", {}, h("span", { class: "it-pill", style: `--c:${r.sev}` }, sev)),
      ...rest.map((c, i) => h("td", { class: CELL_CLASS[i] || null, title: CELL_CLASS[i] === "cut" ? c : null }, c)),
      h("td", { class: "it-act" }, h("div", { class: "it-btns" }, ...(r.actions || []).map((b) => this.button(r, b)))));
    if (r.open) {
      const open = () => this.setTrigger("open", { id: r.id, n: nonce() });
      tr.addEventListener("click", (e) => { if (!e.target.closest("button, input")) open(); });
      tr.addEventListener("keydown", (e) => {
        if ((e.key === "Enter" || e.key === " ") && e.target === tr) { e.preventDefault(); open(); }
      });
    }
    return tr;
  }

  /** A group's header row: fold it, see how many wait, and pick all of them with one tick. */
  groupRow(g, cols) {
    const folded = this.folded.has(g.label);
    const fold = h("button", { class: "it-fold", type: "button", "aria-expanded": String(!folded),
                               onclick: () => { if (folded) this.folded.delete(g.label); else this.folded.add(g.label); this.draw(); } },
      icon(folded ? "chevron_right" : "expand_more"), h("b", {}, g.label), h("span", { class: "it-count" }, `${g.rows.length} waiting`));
    const ids = g.rows.map((r) => r.id);
    return h("tr", { class: "it-group" },
      this.data.pick ? h("td", { class: "it-pick" }, this.pickBox(ids, `Pick all ${ids.length} from ${g.label}`)) : null,
      h("td", { colspan: cols - (this.data.pick ? 1 : 0) }, fold));
  }

  pickBox(ids, label) {
    const state = pickState(ids, this.picked);
    const box = h("input", { type: "checkbox", class: "it-check", "aria-label": label, title: label,
                             checked: state === "all" });
    box.indeterminate = state === "some";
    box.addEventListener("change", () => {
      for (const id of ids) { if (box.checked) this.picked.add(id); else this.picked.delete(id); }
      this.draw();  // ticks show at once; Python answers with the bar for the picked ones
      this.setTrigger("pick", { ids, on: box.checked, n: nonce() });
    });
    return box;
  }

  button(r, b) {
    const busy = this.busy.has(`${r.id}:${b.a}`);
    const on = this.asking && this.asking.id === r.id && this.asking.a === b.a;
    return h("button", {
      class: `it-btn${b.primary ? " primary" : ""}${on ? " on" : ""}`, type: "button", title: b.help || null,
      disabled: b.disabled || busy, "aria-expanded": b.reason ? String(!!on) : null,
      onclick: () => {
        if (b.reason) { this.asking = on ? null : { id: r.id, a: b.a }; this.draw(); this.focusReason(); return; }
        this.send(r, b, "");
      },
    }, icon(busy ? "hourglass_top" : b.icon), b.label);
  }

  reasonRow(r, cols) {
    const b = (r.actions || []).find((x) => x.a === this.asking.a);
    if (!b) return null;
    const required = b.reason === "required";
    const input = h("input", { class: "it-in it-reason", type: "text", maxlength: "500",
      placeholder: required ? "Why? Required, written to the audit log" : "Why? Optional, written to the audit log",
      "aria-label": `Why ${b.label.toLowerCase()} ${r.id}` });
    const go = h("button", { class: "it-btn primary", type: "button", disabled: required,
                             onclick: () => this.send(r, b, input.value.trim()) }, icon(b.icon), b.confirm);
    input.addEventListener("input", () => { go.disabled = required && !input.value.trim(); });
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !go.disabled) go.click();
      if (e.key === "Escape") { this.asking = null; this.draw(); }
    });
    const cancel = h("button", { class: "it-btn ghost", type: "button",
                                 onclick: () => { this.asking = null; this.draw(); } }, "Cancel");
    return h("tr", { class: "it-ask" }, h("td", { colspan: cols },
      h("div", { class: "it-ask-in" }, h("b", {}, `${b.label} ${r.id}`), input, go, cancel)));
  }

  focusReason() {
    const el = this.body.querySelector(".it-reason");
    if (el) el.focus();
  }

  send(r, b, reason) {
    this.busy.add(`${r.id}:${b.a}`);
    this.asking = null;
    this.draw();
    this.setTrigger("act", { id: r.id, a: b.a, reason, n: nonce() });
  }
}
