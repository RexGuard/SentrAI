/* "How an attack is handled" map: the steps SentrAI takes, left to right, each with what it is doing
   right now. Read-only: click a step (or press Enter on it) to open the page that shows it in full.
   A box keeps its face short (title, state dot, a live count or an On/Off badge, one note); the step
   explained in full shows in a tip on hover or keyboard focus, so nothing is cut off with "...".

   Python (shaping.flow_map_data) sends the steps as nodes on a grid (col, row) and the wires between
   them; a wire whose two ends are both busy draws moving dashes, so an attack in progress shows as
   movement along its path. A Streamlit component (st.components.v2): no iframe, nothing fetched from the
   internet, colours from the console's CSS variables. */

export const COL_W = 176; // one column: a box and the gap after it; six fit a 1440 px screen unshrunk
export const BOX_W = 156;
export const ROW_H = 160;
export const BOX_H = 140;
export const MIN_SCALE = 0.85; // below this the text would drop under 12 px: scroll sideways instead

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

/** Where the hover tip goes: under a box in the top rows, over the boxes lower down, kept inside the stage. */
export function tipAt(box, stageWidth, tipWidth = TIP_W) {
  const x = Math.max(0, Math.min(stageWidth - tipWidth, box.x + BOX_W / 2 - tipWidth / 2));
  return box.y < ROW_H ? { x, y: box.y + BOX_H + 6, below: true } : { x, y: box.y - 6, below: false };
}
export const TIP_W = 236;

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
    for (const el of [...this.stage.querySelectorAll(".fm-node, .fm-tip")]) el.remove();
    this.tip = h("div", { class: "fm-tip", "aria-hidden": "true" });
    this.tip.style.width = `${TIP_W}px`;
    for (const n of nodes) {
      const state = STATE_WORDS[n.state] ? n.state : "unknown";
      const open = () => this.setTrigger && n.page && this.setTrigger("open", n.page);
      const hasValue = n.value !== null && n.value !== undefined && n.value !== "";
      const said = [hasValue ? `${n.value}${n.unit ? ` ${n.unit}` : ""}` : "", n.badge || "", n.note || ""].filter(Boolean).join(", ");
      const show = () => this.showTip(n, at[n.id], width);
      const hide = () => this.tip.classList.remove("on");
      const el = h("div", {
        class: `fm-node ${state}${hasValue ? "" : " no-value"}`, role: "button", tabindex: "0", "data-id": n.id,
        "aria-label": `${n.title}: ${said}. ${STATE_WORDS[state]}. ${n.what || ""} Opens its page.`,
        onclick: open, onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); open(); } },
        onmouseenter: show, onmouseleave: hide, onfocus: show, onblur: hide,
      },
      h("div", { class: "fm-head" }, h("span", { class: "mi", "aria-hidden": "true" }, n.icon || "circle"),
        h("span", { class: "fm-title" }, n.title),
        n.badge ? h("span", { class: `fm-badge ${n.badge === "On" ? "on" : "off"}` }, n.badge) : null,
        h("i", { class: "fm-dot", title: STATE_WORDS[state] })),
      hasValue ? h("div", { class: "fm-value" }, String(n.value), n.unit ? h("small", {}, ` ${n.unit}`) : null) : null,
      h("div", { class: "fm-note" }, n.note || ""),
      h("div", { class: "fm-more", "aria-hidden": "true" }, "View details", h("span", { class: "mi" }, "arrow_forward")));
      el.style.left = `${at[n.id].x}px`;
      el.style.top = `${at[n.id].y}px`;
      this.stage.append(el);
    }
    this.stage.append(this.tip);
    this.fit();
  }

  showTip(n, box, stageWidth) {
    if (!n.what) return;
    const p = tipAt(box, stageWidth);
    this.tip.textContent = n.what;
    this.tip.style.left = `${p.x}px`;
    this.tip.style.top = `${p.y}px`;
    this.tip.classList.toggle("above", !p.below);
    this.tip.classList.add("on");
  }

  /** Shrink the whole map to the width there is (never below MIN_SCALE: then it scrolls sideways instead). */
  fit() {
    if (!this.size) return;
    const room = this.viewport.clientWidth || this.size.width;
    const k = Math.max(MIN_SCALE, Math.min(1, room / this.size.width));
    this.stage.style.transform = `scale(${k})`;
    this.viewport.style.height = `${Math.ceil(this.size.height * k) + 4}px`;
  }
}
