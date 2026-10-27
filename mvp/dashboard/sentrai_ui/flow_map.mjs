/* "How an attack is handled" map: the steps SentrAI takes, left to right, each with what it is doing
   right now. Read-only: click a step (or press Enter on it) to open the page that shows it in full.

   Python (shaping.flow_map_data) sends the steps as nodes on a grid (col, row) and the wires between
   them; a wire whose two ends are both busy draws moving dashes, so an attack in progress shows as
   movement along its path. A Streamlit component (st.components.v2): no iframe, nothing fetched from the
   internet, colours from the console's CSS variables. */

export const COL_W = 224; // one column: a box and the gap after it
export const BOX_W = 184;
export const ROW_H = 152;
export const BOX_H = 132;

const SVG = "http://www.w3.org/2000/svg";
const maps = new WeakMap();

/** Where each box sits on the stage, and how big the stage is. */
export function place(nodes) {
  const rows = nodes.map((n) => Number(n.row) || 0);
  const top = Math.min(0, ...rows);
  const at = {};
  for (const n of nodes) at[n.id] = { x: (Number(n.col) || 0) * COL_W, y: ((Number(n.row) || 0) - top) * ROW_H };
  const width = Math.max(0, ...nodes.map((n) => at[n.id].x)) + BOX_W;
  const height = Math.max(0, ...nodes.map((n) => at[n.id].y)) + BOX_H;
  return { at, width, height };
}

/** A wire from the right side of one box to the left side of the next (or straight down within a column). */
export function wire(a, b) {
  if (Math.abs(a.x - b.x) < 1) {
    const x = a.x + BOX_W / 2;
    const [y1, y2] = a.y < b.y ? [a.y + BOX_H, b.y] : [a.y, b.y + BOX_H];
    return { d: `M ${x} ${y1} L ${x} ${y2}`, mid: { x: x + 6, y: (y1 + y2) / 2 } };
  }
  const x1 = a.x + BOX_W, y1 = a.y + BOX_H / 2, x2 = b.x, y2 = b.y + BOX_H / 2;
  const k = Math.max(28, (x2 - x1) / 2);
  return { d: `M ${x1} ${y1} C ${x1 + k} ${y1}, ${x2 - k} ${y2}, ${x2} ${y2}`, mid: { x: (x1 + x2) / 2, y: (y1 + y2) / 2 } };
}

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

function s(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}

const STATE_WORDS = { ok: "fine", busy: "busy", alert: "needs a look", off: "off", idle: "quiet", unknown: "not reported" };

export default function mount(component) {
  const { parentElement, data, setTriggerValue } = component;
  let map = maps.get(parentElement);
  if (!map) {
    map = new FlowMap(parentElement);
    maps.set(parentElement, map);
  }
  map.update(data || {}, setTriggerValue);
}

class FlowMap {
  constructor(host) {
    this.root = h("div", { class: "fm" });
    this.viewport = h("div", { class: "fm-viewport" });
    this.stage = h("div", { class: "fm-stage" });
    this.svg = s("svg", { class: "fm-wires", "aria-hidden": "true" });
    this.stage.append(this.svg);
    this.viewport.append(this.stage);
    this.legend = h("div", { class: "fm-legend" },
      ...["ok", "busy", "alert", "off"].map((k) => h("span", { class: `fm-key ${k}` }, h("i", {}), STATE_WORDS[k])),
      h("span", { class: "fm-key live" }, h("b", {}), "moving: an attack on that path now"));
    this.root.append(this.viewport, this.legend);
    host.append(this.root);
    if (typeof ResizeObserver !== "undefined") {
      this.resizer = new ResizeObserver(() => this.fit());
      this.resizer.observe(this.viewport);
    }
  }

  update(data, setTrigger) {
    this.setTrigger = setTrigger;
    const sig = JSON.stringify(data);
    if (sig === this.sig) return;
    this.sig = sig;
    this.data = data;
    this.render();
  }

  render() {
    const nodes = Array.isArray(this.data.nodes) ? this.data.nodes : [];
    const edges = Array.isArray(this.data.edges) ? this.data.edges : [];
    const { at, width, height } = place(nodes);
    this.size = { width, height };
    this.stage.style.width = `${width}px`;
    this.stage.style.height = `${height}px`;
    this.svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    this.svg.setAttribute("width", width);
    this.svg.setAttribute("height", height);
    this.svg.replaceChildren(s("defs"));
    const defs = this.svg.firstChild;
    const marker = s("marker", { id: "fm-arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    marker.append(s("path", { d: "M 0 0 L 10 5 L 0 10 z", class: "fm-arrowhead" }));
    defs.append(marker);
    for (const e of edges) {
      if (!at[e.from] || !at[e.to]) continue;
      const { d } = wire(at[e.from], at[e.to]);
      this.svg.append(s("path", { d, class: `fm-wire${e.live ? " live" : ""}`, "marker-end": "url(#fm-arrow)" }));
    }
    for (const el of [...this.stage.querySelectorAll(".fm-node")]) el.remove();
    for (const n of nodes) {
      const state = STATE_WORDS[n.state] ? n.state : "unknown";
      const open = () => this.setTrigger && n.page && this.setTrigger("open", n.page);
      const el = h("div", {
        class: `fm-node ${state}`, role: "button", tabindex: "0", "data-id": n.id,
        "aria-label": `${n.title}: ${n.value}, ${n.note}. ${STATE_WORDS[state]}. Opens its page.`,
        onclick: open, onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } },
      },
      h("div", { class: "fm-head" }, h("span", { class: "mi", "aria-hidden": "true" }, n.icon || "circle"),
        h("span", { class: "fm-title" }, n.title), h("i", { class: "fm-dot", title: STATE_WORDS[state] })),
      h("div", { class: "fm-value" }, String(n.value ?? "-")),
      h("div", { class: "fm-note" }, n.note || ""),
      h("div", { class: "fm-what" }, n.what || ""));
      el.style.left = `${at[n.id].x}px`;
      el.style.top = `${at[n.id].y}px`;
      el.title = n.what || "";
      this.stage.append(el);
    }
    this.fit();
  }

  /** Shrink the whole map to the width there is (never below 60 %: then it scrolls sideways instead). */
  fit() {
    if (!this.size) return;
    const room = this.viewport.clientWidth || this.size.width;
    const k = Math.max(0.6, Math.min(1, room / this.size.width));
    this.stage.style.transform = `scale(${k})`;
    this.viewport.style.height = `${Math.ceil(this.size.height * k) + 4}px`;
  }
}
