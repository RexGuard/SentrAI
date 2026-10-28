/* The pipeline overview as a canvas: every step SentrAI takes, every machine it watches and every extension
   it uses is a block on one open surface, like a whiteboard. Drag the background to move around, Ctrl + scroll
   (or the buttons) to zoom, drag a block anywhere, click one for its live numbers and its settings, draw a
   wire from the handle on a block's right edge to another block, take a block off the canvas or add one back
   from "+ Add" (a hidden step, a machine, an extension, a note, or a new machine: that opens the join form
   above the canvas). Where things sit is saved as you go (overview-canvas.json next to the settings file);
   the live numbers keep updating under all of it without touching what you are doing.

   Python (shaping.flow_canvas_data) sends every block that can be on the canvas with what it is doing right
   now, the wires between them, and the saved layout. The component keeps the layout and your typing in the
   browser; Save in a block's panel hands the changed settings to Python, which checks them and writes the
   settings file. Read-only for Auditors: they can look around, but move and change nothing.

   A Streamlit component (st.components.v2): no iframe, nothing fetched from the internet, colours from the
   console's CSS variables. The model functions at the top touch no DOM; tests/canvas.test.mjs runs them in Node. */

export const COL_W = 176; // the grid the steps start on: a column is a box and the gap after it
export const BOX_W = 156;
export const ROW_H = 160;
export const BOX_H = 140;
export const SMALL_H = 112; // a machine or an extension block
export const NOTE_W = 200;
export const GAP = 16;
export const ZOOM = { min: 0.3, max: 2 };
export const MAX_NOTE = 2000;
export const MIN_H = 420; // the canvas never gets shorter than this, even in a small window
export const BOTTOM_GAP = 12; // room left under the canvas at the bottom of the window

const str = (v) => (v === undefined || v === null ? "" : String(v));
export const clone = (x) => JSON.parse(JSON.stringify(x));
export const kindOf = (id) => str(id).split(":")[0];
export const isNote = (id) => kindOf(id) === "note";
const pair = (v) => Array.isArray(v) && v.length === 2 && v.every((n) => Number.isFinite(Number(n)));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const wkey = (w) => `${w.from}>${w.to}`;
const r = (n) => Math.round(n * 10) / 10;

// ------------------------------------------------------------------ the model

/** The grid position shaping.flow_map_data gives a step (a column and a row), in pixels. */
export function gridPos(block) {
  return { x: Math.round((Number(block.col) || 0) * COL_W), y: Math.round((Number(block.row) || 0) * ROW_H) };
}

export const FALLBACK = { step: { w: BOX_W, h: BOX_H }, machine: { w: BOX_W, h: SMALL_H }, ext: { w: BOX_W, h: SMALL_H },
  note: { w: NOTE_W, h: 72 } };
export const fallbackSize = (id) => FALLBACK[kindOf(id)] || FALLBACK.step;

/** Move a block that would cover another one down until it covers nothing. `others`: the ids placed already. */
export function clearSpot(pos, id, size, others) {
  const p = pos[id];
  const sz = size(id);
  const m = 12;
  const boxes = others.filter((k) => k !== id && pos[k]).map((k) => {
    const q = pos[k];
    const z = size(k);
    return { x0: q.x - m, y0: q.y - m, x1: q.x + z.w + m, y1: q.y + z.h + m };
  });
  for (let i = 0; i <= boxes.length; i += 1) {
    const hit = boxes.find((b) => p.x < b.x1 && p.x + sz.w > b.x0 && p.y < b.y1 && p.y + sz.h > b.y0);
    if (!hit) break;
    p.y = hit.y1;
  }
  return p;
}

/** Where the blocks go before anyone moves them: the steps on their grid, the machines in a column left of
    "Logs come in", each extension under the step it plugs into, notes to the right of everything. */
export function defaultLayout(blocks, ids, size = fallbackSize) {
  const by = new Map((blocks || []).map((b) => [b.id, b]));
  const pos = {};
  const steps = ids.filter((id) => kindOf(id) === "step" && by.has(id));
  for (const id of steps) pos[id] = gridPos(by.get(id));
  const logs = pos["step:logs"] || { x: 0, y: ROW_H };
  const machines = ids.filter((id) => kindOf(id) === "machine" && by.has(id));
  const total = machines.reduce((t, id) => t + size(id).h, 0) + GAP * Math.max(0, machines.length - 1);
  let y = Math.round(logs.y + BOX_H / 2 - total / 2);
  for (const id of machines) {
    pos[id] = { x: logs.x - COL_W - 24, y };
    y += size(id).h + GAP;
  }
  const placed = [...steps, ...machines];
  const right = () => (placed.length ? Math.max(...placed.map((k) => pos[k].x + size(k).w)) + 40 : 0);
  for (const id of ids.filter((k) => kindOf(k) === "ext" && by.has(k))) {
    const step = by.get(id).step ? `step:${by.get(id).step}` : "";
    pos[id] = pos[step] ? { x: pos[step].x, y: pos[step].y + size(step).h + 40 } : { x: right(), y: logs.y };
    clearSpot(pos, id, size, placed);
    placed.push(id);
  }
  for (const id of ids.filter(isNote)) {
    pos[id] = { x: right(), y: 0 };
    clearSpot(pos, id, size, placed);
    placed.push(id);
  }
  return pos;
}

/** The blocks on the canvas that Python still knows (a machine that left stays in the layout, unseen, until it is back). */
export function visibleIds(data, st) {
  const known = new Set((data.blocks || []).map((b) => b.id));
  return st.shown.filter((id) => known.has(id) || (isNote(id) && id in st.notes));
}

/** A position for every block on the canvas that has none yet (new, or just joined): its default spot, moved
    down past anything already there. */
export function placeMissing(data, st, size = fallbackSize) {
  const missing = visibleIds(data, st).filter((id) => !st.pos[id]);
  if (!missing.length) return st.pos;
  const def = defaultLayout(data.blocks, st.shown, size);
  for (const id of missing) {
    st.pos[id] = def[id] ? { ...def[id] } : { x: 0, y: 0 };
    clearSpot(st.pos, id, size, st.shown.filter((o) => o !== id && st.pos[o]));
  }
  return st.pos;
}

const dedupe = (ws) => {
  const seen = new Set();
  return ws.filter((w) => w.from && w.to && w.from !== w.to && !seen.has(wkey(w)) && seen.add(wkey(w)));
};
const pairs = (v) => (Array.isArray(v) ? v : []).filter((w) => Array.isArray(w) && w.length === 2)
  .map((w) => ({ from: str(w[0]), to: str(w[1]) }));

/** The saved layout (Python's cleaned doc) as the working state: which blocks show, where, the notes, and the
    wires drawn or taken away by hand. Blocks that are on by default show unless the doc hides them. */
export function applyDoc(data, doc, size = fallbackSize) {
  const d = doc && typeof doc === "object" ? doc : {};
  const known = new Set((data.blocks || []).map((b) => b.id));
  const defaults = (data.defaults || []).filter((id) => known.has(id));
  const notes = {};
  for (const [id, text] of Object.entries(d.notes || {})) if (isNote(id) && typeof text === "string") notes[id] = text.slice(0, MAX_NOTE);
  const hidden = (Array.isArray(d.hidden) ? d.hidden : []).map(str).filter(Boolean);
  const shown = defaults.filter((id) => !hidden.includes(id));
  for (const id of (Array.isArray(d.added) ? d.added : []).map(str)) {
    if (!shown.includes(id) && (isNote(id) ? id in notes : known.has(id))) shown.push(id);
  }
  for (const id of Object.keys(notes)) if (!shown.includes(id)) shown.push(id);
  const pos = {};
  for (const [id, p] of Object.entries(d.pos || {})) {
    if (shown.includes(id) && pair(p)) pos[id] = { x: Math.round(Number(p[0])), y: Math.round(Number(p[1])) };
  }
  const wires = d.wires && typeof d.wires === "object" ? d.wires : {};
  const st = { shown, hidden: hidden.filter((id) => !shown.includes(id)), notes, pos,
    addedWires: dedupe(pairs(wires.added)), removedWires: dedupe(pairs(wires.removed)) };
  placeMissing(data, st, size);
  return st;
}

/** The working state as the file Python keeps: what is hidden of the default blocks, what was added, the notes,
    where everything sits, and the wires drawn or taken away by hand. */
export function toDoc(st, defaults) {
  const def = new Set(defaults || []);
  const notes = {};
  for (const id of st.shown) if (isNote(id) && id in st.notes) notes[id] = st.notes[id];
  const pos = {};
  for (const id of st.shown) if (st.pos[id]) pos[id] = [Math.round(st.pos[id].x), Math.round(st.pos[id].y)];
  return { version: 1, hidden: [...st.hidden], added: st.shown.filter((id) => !def.has(id)), notes, pos,
    wires: { added: st.addedWires.map((w) => [w.from, w.to]), removed: st.removedWires.map((w) => [w.from, w.to]) } };
}

export const signature = (st, defaults) => JSON.stringify(toDoc(st, defaults));

/** Every wire to draw: the default ones between blocks that are both on the canvas (minus those taken away),
    then the ones drawn by hand. A wire whose two ends are both busy is live: it moves. */
export function wiresOf(data, st) {
  const visible = new Set(visibleIds(data, st));
  const by = new Map((data.blocks || []).map((b) => [b.id, b]));
  const busy = (id) => by.has(id) && ["busy", "alert"].includes(by.get(id).state);
  const removed = new Set(st.removedWires.map(wkey));
  const seen = new Set();
  const out = [];
  for (const w of data.wires || []) {
    const k = wkey(w);
    if (!visible.has(w.from) || !visible.has(w.to) || removed.has(k) || seen.has(k)) continue;
    seen.add(k);
    out.push({ from: w.from, to: w.to, live: !!w.live, user: false });
  }
  for (const w of st.addedWires) {
    const k = wkey(w);
    if (!visible.has(w.from) || !visible.has(w.to) || seen.has(k)) continue;
    seen.add(k);
    out.push({ from: w.from, to: w.to, live: busy(w.from) && busy(w.to), user: true });
  }
  return out;
}

export const isDefaultWire = (data, from, to) => (data.wires || []).some((w) => w.from === from && w.to === to);

/** Draw a wire by hand. Words for what happened, or "" when nothing changed. */
export function addWire(data, st, from, to) {
  if (!from || !to || from === to) return "";
  if (wiresOf(data, st).some((w) => w.from === from && w.to === to)) return "";
  if (isDefaultWire(data, from, to)) st.removedWires = st.removedWires.filter((w) => !(w.from === from && w.to === to));
  else st.addedWires.push({ from, to });
  return "Connected.";
}

export function removeWire(data, st, from, to) {
  const before = wiresOf(data, st).length;
  st.addedWires = st.addedWires.filter((w) => !(w.from === from && w.to === to));
  if (isDefaultWire(data, from, to) && !st.removedWires.some((w) => w.from === from && w.to === to)) st.removedWires.push({ from, to });
  return wiresOf(data, st).length < before ? "Wire removed." : "";
}

/** Take a block off the canvas. A block that is on by default is remembered as hidden; a note is gone for good. */
export function hideBlock(data, st, id) {
  if (!st.shown.includes(id)) return "";
  st.shown = st.shown.filter((x) => x !== id);
  if ((data.defaults || []).includes(id) && !st.hidden.includes(id)) st.hidden.push(id);
  if (isNote(id)) delete st.notes[id];
  return isNote(id) ? "Note deleted." : "Taken off the canvas. It is under + Add if you want it back.";
}

/** Put a block on the canvas, at `near` (the middle of the view) or its default spot. */
export function showBlock(data, st, id, near, size = fallbackSize) {
  if (st.shown.includes(id)) return "";
  st.hidden = st.hidden.filter((x) => x !== id);
  st.shown.push(id);
  if (near) {
    const sz = size(id);
    st.pos[id] = { x: Math.round(near.x - sz.w / 2), y: Math.round(near.y - sz.h / 2) };
    clearSpot(st.pos, id, size, st.shown.filter((o) => o !== id && st.pos[o]));
  } else placeMissing(data, st, size);
  return "Added to the canvas.";
}

export function addNote(data, st, text, near, size = fallbackSize) {
  let n = 1;
  while (`note:${n}` in st.notes || st.shown.includes(`note:${n}`)) n += 1;
  const id = `note:${n}`;
  st.notes[id] = str(text).slice(0, MAX_NOTE);
  showBlock(data, st, id, near, size);
  return id;
}

/** What "+ Add" offers: every block Python knows that is not on the canvas, by kind. */
export function catalogue(data, st) {
  const visible = new Set(visibleIds(data, st));
  return [["step", "Steps"], ["machine", "Machines"], ["ext", "Extensions"]].map(([kind, title]) => ({
    kind, title, items: (data.blocks || []).filter((b) => kindOf(b.id) === kind && !visible.has(b.id))
      .map((b) => ({ id: b.id, title: b.title, icon: b.icon || "circle", note: b.note || "" })) }));
}

/** A wire from block a to block b ({x, y, w, h}): out of a's right side into b's left side when b is to the
    right, mirrored when it is to the left, otherwise down (or up) out of the nearer long side. */
export function wirePath(a, b) {
  let p0;
  let p3;
  let dx = 0;
  let dy = 0;
  if (b.x >= a.x + a.w - 8) {
    p0 = { x: a.x + a.w, y: a.y + a.h / 2 };
    p3 = { x: b.x, y: b.y + b.h / 2 };
    dx = 1;
  } else if (b.x + b.w <= a.x + 8) {
    p0 = { x: a.x, y: a.y + a.h / 2 };
    p3 = { x: b.x + b.w, y: b.y + b.h / 2 };
    dx = -1;
  } else if (b.y + b.h / 2 >= a.y + a.h / 2) {
    p0 = { x: a.x + a.w / 2, y: a.y + a.h };
    p3 = { x: b.x + b.w / 2, y: b.y };
    dy = 1;
  } else {
    p0 = { x: a.x + a.w / 2, y: a.y };
    p3 = { x: b.x + b.w / 2, y: b.y + b.h };
    dy = -1;
  }
  const k = Math.max(28, (dx ? Math.abs(p3.x - p0.x) : Math.abs(p3.y - p0.y)) / 2);
  const p1 = { x: p0.x + k * dx, y: p0.y + k * dy };
  const p2 = { x: p3.x - k * dx, y: p3.y - k * dy };
  const d = `M ${r(p0.x)} ${r(p0.y)} C ${r(p1.x)} ${r(p1.y)}, ${r(p2.x)} ${r(p2.y)}, ${r(p3.x)} ${r(p3.y)}`;
  const mid = { x: (p0.x + 3 * p1.x + 3 * p2.x + p3.x) / 8, y: (p0.y + 3 * p1.y + 3 * p2.y + p3.y) / 8 };
  return { d, mid, end: p3, dx, dy };
}

/** The arrowhead at a wire's end, pointing the way the wire arrives. */
export function arrowHead(w) {
  const e = w.end;
  const bx = e.x - 8 * w.dx;
  const by = e.y - 8 * w.dy;
  return `M${r(e.x)},${r(e.y)} L${r(bx - 4.5 * w.dy)},${r(by + 4.5 * w.dx)} L${r(bx + 4.5 * w.dy)},${r(by - 4.5 * w.dx)} Z`;
}

/** How tall the canvas is: from where it starts on the page down to the bottom of the window, so it fills the
    page under the header (the menu stays where it is). `top` is the canvas's distance from the top of the page. */
export function fillHeight(top, windowH, min = MIN_H) {
  return Math.max(min, Math.round(windowH - Math.max(0, top) - BOTTOM_GAP));
}

/** Where the hover tip goes (viewport coordinates): under the block when there is room, else over it, kept inside. */
export function tipAt(box, room, tip) {
  const x = Math.max(4, Math.min(room.w - tip.w - 4, box.x + box.w / 2 - tip.w / 2));
  const below = box.y + box.h + 6 + tip.h <= room.h || box.y - 6 - tip.h < 0;
  return { x: Math.round(x), y: Math.round(below ? box.y + box.h + 6 : box.y - 6 - tip.h), below };
}

/** What is wrong with the values typed in a block's settings, in words. Python checks everything again on Save. */
export function settingProblems(fields, values) {
  const out = [];
  for (const f of fields || []) {
    if (!(f.env in values) || f.kind === "set") continue;
    const v = str(values[f.env]).trim();
    if (f.choices && f.choices.length) {
      if (!f.choices.includes(v)) out.push(`${f.label} must be one of: ${f.choices.join(", ")}.`);
    } else if (f.kind === "int") {
      if (!/^[+-]?\d+$/.test(v)) out.push(`${f.label} must be a whole number.`);
    } else if (f.kind === "float") {
      if (v === "" || !Number.isFinite(Number(v))) out.push(`${f.label} must be a number.`);
    }
  }
  return out;
}

/** Only the settings that differ from what is saved, trimmed. */
export function settingChanges(fields, values) {
  const out = {};
  for (const f of fields || []) {
    if (f.env in values && str(values[f.env]).trim() !== str(f.value).trim()) out[f.env] = str(values[f.env]).trim();
  }
  return out;
}

export const STATE_WORDS = { ok: "fine", busy: "busy", alert: "needs a look", off: "off", idle: "quiet", unknown: "not reported" };
export const stateOf = (b) => (STATE_WORDS[b && b.state] ? b.state : "unknown");

/** One block in words, for screen readers: its numbers, its state and what it does. */
export function faceText(b) {
  const hasValue = b.value !== null && b.value !== undefined && b.value !== "";
  const said = [hasValue ? `${b.value}${b.unit ? ` ${b.unit}` : ""}` : "", b.badge || "", b.note || ""].filter(Boolean).join(", ");
  return `${b.title}${said ? `: ${said}` : ""}. ${STATE_WORDS[stateOf(b)]}.${b.what ? ` ${b.what}` : ""}`;
}

// ------------------------------------------------------------------ the canvas (DOM)

const SVG = "http://www.w3.org/2000/svg";
const canvases = new WeakMap();

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid !== null && kid !== undefined && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const kids = (...xs) => xs.flat().filter((x) => x !== null && x !== undefined && x !== false);

function s(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}

const icon = (name) => h("span", { class: "mi", "aria-hidden": "true" }, name);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const isTyping = (el) => !!el && (el.tagName === "TEXTAREA" || el.tagName === "SELECT"
  || (el.tagName === "INPUT" && !["checkbox", "radio", "button"].includes(el.type)));
const PAGE_WORDS = { collector: "Collector", classifier: "Classifier", review: "Review", approvals: "Approvals", guardrails: "Automation guardrails",
  responder: "Action taker", extensions: "Extensions", incidents: "Incidents", audit: "Audit trail", machine: "its page", machines: "Machines" };

export default function mount(component) {
  const { parentElement, data, setTriggerValue } = component;
  let canvas = canvases.get(parentElement);
  if (!canvas) {
    canvas = new Canvas(parentElement);
    canvases.set(parentElement, canvas);
  }
  canvas.update(data || {}, setTriggerValue);
}

class Canvas {
  constructor(host) {
    this.host = host;
    this.data = { blocks: [], defaults: [], wires: [] };
    this.st = null;
    this.base = null;
    this.version = null;
    this.view = { x: 0, y: 0, k: 1 };
    this.sel = null; // {kind: "block", id} or {kind: "wire", from, to}
    this.hover = null;
    this.undo = [];
    this.redo = [];
    this.drag = null;
    this.queued = null;
    this.pending = new Map(); // id -> {kind, timer, ...}: what waits for Python's answer
    this.draft = null; // {id, values}: settings typed in the panel, not saved yet
    this.error = "";
    this.message = "";
    this.nodeEls = new Map();
    this.wireEls = new Map();
    this.panelFor = null;
    this.build();
  }

  // ---------------------------------------------------------------- skeleton

  build() {
    const tool = (act, label, ico, opts = {}) => h("button", {
      type: "button", class: `fc-btn${opts.cls ? ` ${opts.cls}` : ""}${opts.iconOnly ? " icon" : ""}`, "data-act": act,
      "aria-label": opts.iconOnly ? label : null, title: opts.title || (opts.iconOnly ? label : null),
      "aria-haspopup": opts.menu ? "true" : null, "aria-expanded": opts.menu ? "false" : null,
    }, ico ? icon(ico) : null, opts.iconOnly ? null : h("span", {}, label), opts.menu ? icon("expand_more") : null);
    this.btn = {
      add: tool("add", "Add", "add", { title: "Add a block to the canvas", menu: true }),
      undo: tool("undo", "Undo", "undo", { iconOnly: true, title: "Undo (Ctrl+Z)" }),
      redo: tool("redo", "Redo", "redo", { iconOnly: true, title: "Redo (Ctrl+Shift+Z)" }),
      tidy: tool("tidy", "Tidy up", "account_tree", { title: "Put every block back in its usual place" }),
      zoomOut: tool("zoom-out", "Zoom out", "remove", { iconOnly: true }),
      zoomIn: tool("zoom-in", "Zoom in", "add", { iconOnly: true }),
      fit: tool("fit", "Fit everything in view", "fit_screen", { iconOnly: true }),
      full: tool("full", "Full screen", "arrows_outward", { iconOnly: true }),
      help: tool("help", "How to use the canvas", "help", { iconOnly: true }),
    };
    this.zoomLabel = h("span", { class: "fc-zoom", "aria-hidden": "true" }, "100%");
    this.statusEl = h("span", { class: "fc-status", role: "status" });
    this.menu = h("div", { class: "fc-menu", role: "menu", hidden: true, "aria-label": "Blocks to add" });
    const bar = h("div", { class: "fc-bar", role: "group", "aria-label": "Canvas tools" },
      h("div", { class: "fc-group edit fc-addwrap" }, this.btn.add, this.menu),
      h("div", { class: "fc-group edit" }, this.btn.undo, this.btn.redo),
      h("div", { class: "fc-group" }, this.btn.tidy, this.btn.zoomOut, this.zoomLabel, this.btn.zoomIn, this.btn.fit, this.btn.full),
      h("div", { class: "fc-spacer" }), this.statusEl, h("div", { class: "fc-group" }, this.btn.help));
    bar.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-act]");
      if (b && !b.disabled) this.act(b.dataset.act);
    });
    this.menu.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-add]");
      if (b) this.addFromMenu(b.dataset.add);
    });

    this.notice = h("div", { class: "fc-notice", hidden: true });
    this.wires = s("svg", { class: "fc-wires", "aria-hidden": "true", width: 1, height: 1 });
    this.ghost = s("svg", { class: "fc-wires fc-ghost", "aria-hidden": "true", width: 1, height: 1 });
    this.nodesEl = h("div", { class: "fc-nodes" });
    this.wireX = h("button", { type: "button", class: "fc-wire-x", hidden: true }, icon("close"), h("span", {}, "Remove"));
    this.wireX.addEventListener("click", () => this.removeSelectedWire());
    this.world = h("div", { class: "fc-world" }, this.wires, this.nodesEl, this.ghost, this.wireX);
    this.tip = h("div", { class: "fc-tip", role: "tooltip", hidden: true });
    this.viewport = h("div", { class: "fc-viewport", tabindex: "-1" }, this.world, this.tip);
    this.legend = h("div", { class: "fc-legend" },
      ...["ok", "busy", "alert", "off"].map((k) => h("span", { class: `fc-key ${k}` }, h("i", {}), STATE_WORDS[k])),
      h("span", { class: "fc-key live" }, h("b", {}), "moving: an attack on that path now"),
      h("span", { class: "fc-key user" }, h("b", {}), "dashed: drawn by hand"));
    this.panel = h("section", { class: "fc-panel", "aria-label": "Details" });
    this.live = h("div", { class: "fc-sr", "aria-live": "polite" });
    // The canvas is the page: the panel and the legend float over it, like a drawing app's.
    this.body = h("div", { class: "fc-body" }, h("div", { class: "fc-canvas" }, this.viewport, this.legend, this.panel));
    this.root = h("div", { class: "fc" }, bar, this.notice, this.body, this.live);
    this.host.appendChild(this.root);

    const vp = this.viewport;
    vp.addEventListener("pointerdown", (e) => this.down(e));
    vp.addEventListener("pointermove", (e) => this.move(e));
    vp.addEventListener("pointerup", (e) => this.up(e));
    vp.addEventListener("pointercancel", (e) => this.up(e, true));
    vp.addEventListener("wheel", (e) => this.wheel(e), { passive: false });
    vp.addEventListener("pointerover", (e) => this.hoverAt(e));
    vp.addEventListener("pointerleave", () => this.setHover(null));
    vp.addEventListener("dblclick", (e) => this.dblclick(e));
    this.nodesEl.addEventListener("focusin", (e) => this.hoverAt(e));
    this.nodesEl.addEventListener("focusout", () => this.setHover(null));
    this.nodesEl.addEventListener("keydown", (e) => this.nodeKey(e));
    this.root.addEventListener("keydown", (e) => this.key(e));
    this.root.addEventListener("fullscreenchange", () => this.fullChanged());
    document.addEventListener("fullscreenchange", () => this.fullChanged());
    this.root.addEventListener("focusout", (e) => {
      if (!this.menu.hidden && !(e.relatedTarget && this.root.contains(e.relatedTarget))) this.closeMenu();
    });
    window.addEventListener("resize", () => this.fillPage());
    requestAnimationFrame(() => this.fillPage());
    if (typeof ResizeObserver !== "undefined") {
      this.resizer = new ResizeObserver(() => {
        this.drawWires();
        if (this.needsFit && this.viewport.clientWidth) this.fit();
      });
      this.resizer.observe(this.viewport);
    }
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => this.st && this.drawWires());
  }

  // ---------------------------------------------------------------- data from Python

  update(data, setTrigger) {
    if (setTrigger) this.setTrigger = setTrigger;
    this.data = { blocks: [], defaults: [], wires: [], ...(data || {}) };
    this.readOnly = !!this.data.read_only;
    this.root.classList.toggle("ro", this.readOnly);
    for (const res of this.data.results || []) this.settle(res);
    if (!this.st) {
      this.adopt();
      return;
    }
    if (this.drag) {
      this.queued = true;
      return;
    }
    if (this.data.version !== this.version && !this.dirty() && !this.pendingOf("layout")) {
      // The saved layout changed: our own save landing (nothing moves, undo history stays), or someone
      // else moved things, in which case their layout is taken over.
      const fresh = applyDoc(this.data, this.data.doc, (k) => this.size(k));
      if (signature(fresh, this.data.defaults) === signature(this.st, this.data.defaults)) {
        this.version = this.data.version;
        this.base = fresh;
        this.syncDefaults();
        this.render();
      } else this.adopt();
    } else {
      this.syncDefaults();
      this.render();
    }
  }

  /** Take the saved layout from Python as the working copy (first run, and after a save landed). */
  adopt() {
    const keep = this.sel;
    this.st = applyDoc(this.data, this.data.doc, (k) => this.size(k));
    this.base = clone(this.st);
    this.version = this.data.version;
    this.undo = [];
    this.redo = [];
    this.sel = keep && keep.kind === "block" && this.st.shown.includes(keep.id) ? keep : keep && keep.kind === "wire" ? keep : null;
    this.render();
    if (!this.fitted) {
      this.fitted = true;
      requestAnimationFrame(() => this.fit());
    }
  }

  /** A machine that just joined (or an extension that was just installed) shows up on its own. */
  syncDefaults() {
    const before = this.st.shown.length;
    for (const id of this.data.defaults || []) {
      if (!this.st.shown.includes(id) && !this.st.hidden.includes(id)) this.st.shown.push(id);
    }
    placeMissing(this.data, this.st, (k) => this.size(k));
    if (this.st.shown.length !== before) this.scheduleSave();
  }

  settle(res) {
    const p = this.pending.get(res.id);
    if (!p) return;
    clearTimeout(p.timer);
    this.pending.delete(res.id);
    if (p.kind === "layout") {
      if (res.ok) {
        this.base = p.state;
        this.error = "";
      } else this.error = res.message || "The layout was not saved.";
    } else if (p.kind === "settings") {
      if (res.ok && this.draft && this.draft.id === p.block) this.draft = null;
      this.message = { ok: !!res.ok, text: res.message || (res.ok ? "Saved." : "Not saved."), block: p.block };
      this.panelFor = null; // redraw the form with the saved values
    } else {
      this.message = { ok: !!res.ok, text: res.message || "", block: p.block };
      this.panelFor = null;
    }
    this.say(res.message || (res.ok ? "Saved." : "Not saved."));
  }

  pendingOf(kind) {
    return [...this.pending.values()].some((p) => p.kind === kind);
  }

  dirty() {
    return !!this.st && signature(this.st, this.data.defaults) !== signature(this.base, this.data.defaults);
  }

  block(id) {
    return (this.data.blocks || []).find((b) => b.id === id) || null;
  }

  size(id) {
    const el = this.nodeEls.get(id);
    return el && el.offsetWidth ? { w: el.offsetWidth, h: el.offsetHeight } : fallbackSize(id);
  }

  // ---------------------------------------------------------------- changes, history, saving

  snapshot() {
    return { st: clone(this.st), sel: this.sel && { ...this.sel } };
  }

  restore(snap) {
    this.st = snap.st;
    this.sel = snap.sel;
    placeMissing(this.data, this.st, (k) => this.size(k));
    this.render();
    this.scheduleSave();
  }

  /** One change as one undo step: `fn` returns words for screen readers, or false when nothing changed. */
  change(fn) {
    if (this.readOnly) return false;
    const snap = this.snapshot();
    const said = fn(this.st);
    if (said === false || signature(this.st, this.data.defaults) === signature(snap.st, this.data.defaults)) {
      this.render();
      return false;
    }
    this.undo.push(snap);
    if (this.undo.length > 200) this.undo.shift();
    this.redo = [];
    this.render();
    this.scheduleSave();
    if (typeof said === "string" && said) this.say(said);
    return true;
  }

  undoLast() {
    if (!this.undo.length || this.readOnly) return;
    this.redo.push(this.snapshot());
    this.restore(this.undo.pop());
    this.say("Undone.");
  }

  redoLast() {
    if (!this.redo.length || this.readOnly) return;
    this.undo.push(this.snapshot());
    this.restore(this.redo.pop());
    this.say("Redone.");
  }

  /** The layout saves itself a moment after the last change, like a whiteboard would. */
  scheduleSave() {
    if (this.readOnly) return;
    clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(() => this.saveLayout(), 600);
    this.renderChrome();
  }

  saveLayout() {
    if (this.readOnly || !this.st || !this.dirty() || !this.setTrigger) return;
    if (this.pendingOf("layout")) {
      this.scheduleSave(); // one save at a time; the next one picks up everything since
      return;
    }
    const id = `layout-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    const state = clone(this.st);
    this.pending.set(id, { kind: "layout", state, timer: setTimeout(() => this.timedOut(id), 20000) });
    this.setTrigger("save_layout", { id, doc: toDoc(state, this.data.defaults) });
    this.renderChrome();
  }

  timedOut(id) {
    const p = this.pending.get(id);
    if (!p) return;
    this.pending.delete(id);
    this.error = "No answer from the console. Check that it is still running, then try again.";
    this.panelFor = null;
    this.render();
  }

  saveSettings() {
    const d = this.draft;
    const b = d && this.block(d.id);
    if (!b || this.readOnly || !this.setTrigger) return;
    const changes = settingChanges(b.settings, d.values);
    if (!Object.keys(changes).length || settingProblems(b.settings, d.values).length) return;
    const id = `settings-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    this.pending.set(id, { kind: "settings", block: b.id, timer: setTimeout(() => this.timedOut(id), 20000) });
    this.message = "";
    this.setTrigger("save_settings", { id, block: b.id, title: b.title, changes });
    this.panelFor = null;
    this.render();
  }

  toggle(b, on) {
    if (this.readOnly || !this.setTrigger || !b.switch || b.switch.managed) return;
    const name = b.id.startsWith("ext:") ? b.id.slice(4) : b.switch.name;
    const id = `toggle-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;
    this.pending.set(id, { kind: "toggle", block: b.id, timer: setTimeout(() => this.timedOut(id), 20000) });
    this.message = "";
    this.setTrigger("toggle", { id, block: b.id, name, title: b.switch.title || b.title, on: !!on });
    this.panelFor = null;
    this.render();
  }

  open(b) {
    if (!this.setTrigger || !b) return;
    this.setTrigger("open", { page: b.page || "", host: b.host || "", id: b.id });
  }

  // ---------------------------------------------------------------- toolbar and the add menu

  act(what) {
    if (what === "zoom-in") return this.zoomBy(1.2);
    if (what === "zoom-out") return this.zoomBy(1 / 1.2);
    if (what === "fit") return this.fit();
    if (what === "full") return this.toggleFull();
    if (what === "undo") return this.undoLast();
    if (what === "redo") return this.redoLast();
    if (what === "add") return this.menu.hidden ? this.openMenu() : this.closeMenu();
    if (what === "help") {
      this.showHelp = !(this.showHelp && !this.sel);
      this.sel = null;
      this.panelFor = null;
      return this.render();
    }
    if (this.readOnly) return undefined;
    if (what === "tidy") {
      this.change((st) => {
        const def = defaultLayout(this.data.blocks, st.shown, (k) => this.size(k));
        for (const id of visibleIds(this.data, st)) if (def[id]) st.pos[id] = def[id];
        return "Every block is back in its usual place.";
      });
      return requestAnimationFrame(() => this.fit());
    }
    return undefined;
  }

  openMenu() {
    if (this.readOnly) return;
    const groups = catalogue(this.data, this.st);
    const item = (add, title, ico, note) => h("button", { type: "button", class: "fc-item", role: "menuitem", "data-add": add },
      icon(ico), h("span", { class: "fc-item-main" }, h("span", { class: "fc-item-title" }, title), note ? h("span", { class: "fc-item-note" }, note) : null));
    const parts = [];
    for (const g of groups) {
      const items = g.items.map((x) => item(x.id, x.title, x.icon, x.note));
      if (g.kind === "machine" && this.data.panel) items.push(item("machine:+", "New machine", "key", "make a join code: the form opens above the canvas"));
      if (!items.length) continue;
      parts.push(h("div", { class: "fc-menu-title" }, g.title), ...items);
    }
    parts.push(h("div", { class: "fc-menu-title" }, "Other"), item("note:+", "Note", "sticky_note_2", "a few words for whoever looks at this next"));
    this.menu.replaceChildren(...parts);
    this.menu.hidden = false;
    this.btn.add.setAttribute("aria-expanded", "true");
    const first = this.menu.querySelector("button");
    if (first) first.focus();
  }

  closeMenu() {
    this.menu.hidden = true;
    this.btn.add.setAttribute("aria-expanded", "false");
  }

  addFromMenu(what) {
    this.closeMenu();
    if (this.readOnly) return;
    if (what === "machine:+") {
      if (this.setTrigger) this.setTrigger("add_machine", { id: `machine-${Date.now().toString(36)}` });
      this.say("The join form opens above the canvas.");
      return;
    }
    const near = this.centre();
    if (what === "note:+") {
      let id;
      this.change((st) => {
        id = addNote(this.data, st, "New note", near, (k) => this.size(k));
        this.sel = { kind: "block", id };
        return "Note added. Type its text in the panel.";
      });
      this.reveal(id);
      this.focusField("fc-f-note", true);
      return;
    }
    this.change((st) => {
      const said = showBlock(this.data, st, what, near, (k) => this.size(k));
      if (!said) return false;
      this.sel = { kind: "block", id: what };
      return said;
    });
    this.reveal(what);
    this.nodeEls.get(what)?.focus({ preventScroll: true });
  }

  /** The middle of the view, in canvas coordinates. */
  centre() {
    const rect = this.viewport.getBoundingClientRect();
    return { x: (rect.width / 2 - this.view.x) / this.view.k, y: (rect.height / 2 - this.view.y) / this.view.k };
  }

  /** Stretch the canvas from where it starts down to the bottom of the window. Measured from the top of the page
      (not of the view), so scrolling does not change it. */
  fillPage() {
    const scroller = document.querySelector('[data-testid="stMain"]') || document.scrollingElement;
    const top = this.body.getBoundingClientRect().top + (scroller ? scroller.scrollTop : 0);
    const height = fillHeight(top, window.innerHeight);
    if (this.body.style.getPropertyValue("--fc-h") !== `${height}px`) {
      this.body.style.setProperty("--fc-h", `${height}px`);
      requestAnimationFrame(() => this.drawWires());
    }
  }

  toggleFull() {
    const on = this.root.classList.contains("fs");
    if (on) {
      if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(() => {});
      this.root.classList.remove("fs");
    } else if (this.root.requestFullscreen) {
      this.root.requestFullscreen().then(() => this.root.classList.add("fs")).catch(() => this.root.classList.add("fs"));
    } else this.root.classList.add("fs");
    requestAnimationFrame(() => this.fit());
  }

  fullChanged() {
    const full = !!document.fullscreenElement && (document.fullscreenElement === this.root || document.fullscreenElement.contains(this.host));
    this.root.classList.toggle("fs", full);
    this.btn.full.replaceChildren(icon(full ? "close" : "arrows_outward"));
    this.btn.full.setAttribute("aria-label", full ? "Leave full screen" : "Full screen");
    this.btn.full.title = full ? "Leave full screen" : "Full screen";
    requestAnimationFrame(() => this.fit());
  }

  // ---------------------------------------------------------------- drawing

  render() {
    if (!this.st) return;
    this.renderNodes();
    this.placeNodes();
    this.drawWires();
    this.renderPanel();
    this.renderChrome();
  }

  renderNodes() {
    const ids = visibleIds(this.data, this.st);
    for (const [id, el] of this.nodeEls) {
      if (!ids.includes(id)) {
        el.remove();
        this.nodeEls.delete(id);
      }
    }
    for (const id of ids) {
      let el = this.nodeEls.get(id);
      if (!el) {
        el = h("div", { class: `fc-node ${kindOf(id)}`, "data-id": id, tabindex: "0", role: "button" });
        this.nodesEl.appendChild(el);
        this.nodeEls.set(id, el);
        if (this.resizer) this.resizer.observe(el);
      }
      const selected = !!this.sel && this.sel.kind === "block" && this.sel.id === id;
      el.classList.toggle("sel", selected);
      el.setAttribute("aria-pressed", selected ? "true" : "false");
      if (isNote(id)) this.fillNote(el, id);
      else this.fillBlock(el, this.block(id));
    }
  }

  fillBlock(el, b) {
    const state = stateOf(b);
    const hasValue = b.value !== null && b.value !== undefined && b.value !== "";
    const sig = JSON.stringify([b.title, b.icon, b.badge, b.value, b.unit, b.note, state, this.readOnly]);
    el.setAttribute("aria-label", `${faceText(b)} Press Enter for details.`);
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    for (const k of Object.keys(STATE_WORDS)) el.classList.remove(k);
    el.classList.add(state);
    el.classList.toggle("no-value", !hasValue);
    el.replaceChildren(...kids(
      h("div", { class: "fc-head" }, icon(b.icon || "circle"), h("span", { class: "fc-title" }, b.title),
        b.badge ? h("span", { class: `fc-badge ${b.badge === "On" ? "on" : "off"}` }, b.badge) : null,
        h("i", { class: "fc-dot", title: STATE_WORDS[state] })),
      hasValue ? h("div", { class: "fc-value" }, String(b.value), b.unit ? h("small", {}, ` ${b.unit}`) : null) : null,
      h("div", { class: "fc-note" }, b.note || ""),
      this.readOnly ? null : h("span", { class: "fc-port", "data-port": "out", title: "Drag onto another block to connect them" })));
  }

  fillNote(el, id) {
    const text = this.st.notes[id] || "";
    const sig = JSON.stringify([text, this.readOnly]);
    el.setAttribute("aria-label", `Note: ${text || "empty"}. Press Enter to edit it.`);
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.replaceChildren(...kids(h("div", { class: "fc-head" }, icon("sticky_note_2"), h("span", { class: "fc-title" }, "Note")),
      h("div", { class: "fc-text" }, text || "Empty note"),
      this.readOnly ? null : h("span", { class: "fc-port", "data-port": "out", title: "Drag onto another block to connect them" })));
  }

  placeNodes() {
    for (const [id, el] of this.nodeEls) {
      const p = this.st.pos[id];
      if (!p) continue;
      el.style.left = `${p.x}px`;
      el.style.top = `${p.y}px`;
    }
  }

  box(id) {
    const p = this.st.pos[id];
    if (!p) return null;
    const sz = this.size(id);
    return { x: p.x, y: p.y, w: sz.w, h: sz.h };
  }

  drawWires() {
    if (!this.st) return;
    const focus = this.sel && this.sel.kind === "block" ? this.sel.id : this.hover;
    const selWire = this.sel && this.sel.kind === "wire" ? `${this.sel.from}>${this.sel.to}` : null;
    const frag = document.createDocumentFragment();
    let selGeom = null;
    for (const w of wiresOf(this.data, this.st)) {
      const a = this.box(w.from);
      const b = this.box(w.to);
      if (!a || !b) continue;
      const g = wirePath(a, b);
      const k = `${w.from}>${w.to}`;
      const hot = focus && (w.from === focus || w.to === focus);
      const cls = `w${w.live ? " live" : ""}${w.user ? " user" : ""}${k === selWire ? " sel" : ""}${hot ? " hot" : ""}${(focus || selWire) && !hot && k !== selWire ? " dim" : ""}`;
      const grp = s("g", { class: cls });
      grp.append(s("path", { class: "line", d: g.d }), s("path", { class: "head", d: arrowHead(g) }));
      if (!this.readOnly) grp.append(s("path", { class: "hit", d: g.d, "data-wire": k }));
      frag.append(grp);
      if (k === selWire) selGeom = g;
    }
    this.wires.replaceChildren(frag);
    if (selGeom && !this.readOnly) {
      this.wireX.hidden = false;
      this.wireX.style.left = `${selGeom.mid.x}px`;
      this.wireX.style.top = `${selGeom.mid.y}px`;
      this.wireX.setAttribute("aria-label", `Remove the wire from ${this.titleOf(this.sel.from)} to ${this.titleOf(this.sel.to)}`);
    } else this.wireX.hidden = true;
  }

  titleOf(id) {
    const b = this.block(id);
    return b ? b.title : isNote(id) ? "the note" : id;
  }

  renderChrome() {
    const ro = this.readOnly;
    for (const b of [this.btn.add, this.btn.tidy]) b.disabled = ro;
    this.btn.undo.disabled = ro || !this.undo.length;
    this.btn.redo.disabled = ro || !this.redo.length;
    let status;
    if (ro) status = "Read only";
    else if (this.pendingOf("layout")) status = "Saving the layout…";
    else if (this.dirty()) status = this.error ? "Layout not saved" : "Saving soon…";
    else status = "Layout saved";
    if (this.statusEl.textContent !== status) this.statusEl.textContent = status;
    this.statusEl.classList.toggle("dirty", !ro && this.dirty());
    this.statusEl.classList.toggle("bad", !ro && !!this.error);
    this.zoomLabel.textContent = `${Math.round(this.view.k * 100)}%`;
    const notes = [];
    if (ro) notes.push(["lock", this.data.lock_reason || "You can look around, but not change anything here.", ""]);
    if (this.error && !ro) notes.push(["error", `Could not save the layout: ${this.error} Your changes stay here until the page is reloaded.`, "bad"]);
    this.notice.hidden = !notes.length;
    this.notice.replaceChildren(...notes.map(([ico, text, cls]) => h("div", { class: `fc-note-row ${cls}`, role: cls === "bad" ? "alert" : null },
      icon(ico), h("span", {}, text))));
  }

  // ---------------------------------------------------------------- the panel

  /** The panel for what is selected. Its form is drawn once per selection and kept while you type; only the
      live numbers in it change under a refresh. */
  renderPanel() {
    const sel = this.sel;
    const want = sel ? JSON.stringify([sel, this.readOnly, !!this.pendingOf("settings"), !!this.pendingOf("toggle"), this.message, this.confirmOff])
      : this.showHelp ? `help-${visibleIds(this.data, this.st).length}` : "none";
    if (sel && sel.kind === "block" && !this.st.shown.includes(sel.id)) this.sel = null;
    if (this.panelFor === want && sel && sel.kind === "block") {
      this.refreshLive(sel.id);
      return;
    }
    this.panelFor = want;
    const had = this.host.activeElement && this.panel.contains(this.host.activeElement) ? this.host.activeElement.id : "";
    let body;
    if (this.sel && this.sel.kind === "block") body = isNote(this.sel.id) ? this.notePanel(this.sel.id) : this.blockPanel(this.block(this.sel.id));
    else if (this.sel && this.sel.kind === "wire") body = this.wirePanel(this.sel);
    if (!body) {
      this.sel = null;
      body = this.showHelp ? this.homePanel() : null;
    }
    if (this.sel) this.showHelp = false;
    const open = !!body;
    this.root.classList.toggle("panel-open", open);
    this.btn.help.setAttribute("aria-pressed", this.showHelp ? "true" : "false");
    const close = h("button", { type: "button", class: "fc-btn icon small fc-close", "aria-label": "Close the panel", title: "Close (Esc)",
      onclick: () => {
        this.showHelp = false;
        this.select(null);
        this.render();
      } }, icon("close"));
    this.panel.replaceChildren(...(open ? [close, ...kids(body)] : []));
    if (this.readOnly) for (const el of this.panel.querySelectorAll("input, select, textarea, button.danger, button.edit")) el.disabled = true;
    const back = had && this.panel.querySelector(`#${had}`);
    if (back && !back.disabled) back.focus({ preventScroll: true });
  }

  homePanel() {
    const n = visibleIds(this.data, this.st).length;
    const tips = this.readOnly ? [h("p", { class: "fc-help" }, "Click a block to see what it is doing and how it is set up.")] : [
      h("p", { class: "fc-ptitle sub" }, "How to change it"),
      h("ul", { class: "fc-tips" },
        h("li", {}, "Drag any block where you like; the layout saves itself."),
        h("li", {}, "Click a block: its live numbers, its settings and a button to its page."),
        h("li", {}, h("b", {}, "+ Add"), " puts a step, machine, extension or note on the canvas; a new machine opens the join form."),
        h("li", {}, "Drag the handle on a block's right edge onto another block to connect them. Click a wire to remove it."),
        h("li", {}, "Keyboard: Tab to a block, Enter opens it, arrows move it, Delete takes it off, Ctrl+Z undoes."))];
    tips.push(h("p", { class: "fc-ptitle sub" }, "Moving around"),
      h("ul", { class: "fc-tips" },
        h("li", {}, "Drag the background to move around; Ctrl + scroll (or the buttons) zooms."),
        h("li", {}, "Fit puts everything in view; Full screen hides the menu too.")));
    return [h("p", { class: "fc-ptitle" }, "Pipeline overview"),
      h("p", { class: "fc-help" }, `${n} ${n === 1 ? "block" : "blocks"} on the canvas: what SentrAI does from the first log line to the record of it, `
        + "the machines it watches and the extensions it uses, each with what it is doing right now."), ...tips];
  }

  blockPanel(b) {
    if (!b) return null;
    const ro = this.readOnly;
    const state = stateOf(b);
    const out = [h("p", { class: "fc-ptitle" }, icon(b.icon || "circle"), h("span", {}, b.title),
      h("span", { class: `fc-state ${state}` }, h("i", {}), STATE_WORDS[state]))];
    if (b.what) out.push(h("p", { class: "fc-help" }, b.what));
    this.liveEl = h("div", { class: "fc-live" });
    this.fillLive(this.liveEl, b);
    out.push(this.liveEl);
    if (b.switch) {
      const on = !!b.switch.on;
      const busy = [...this.pending.values()].some((p) => p.kind === "toggle" && p.block === b.id);
      const name = b.switch.title || b.title;
      const asking = this.confirmOff === b.id && on;
      out.push(h("div", { class: "fc-switch" },
        h("span", { class: "fc-switch-word" }, on ? `${name} is on.` : `${name} is off.`),
        asking ? null : h("button", { type: "button", class: `fc-btn small edit${on ? "" : " primary"}`, disabled: ro || busy || !!b.switch.managed,
          title: b.switch.managed ? "The server's SENTRAI_EXTENSIONS decides which extensions are on." : null,
          onclick: () => {
            if (on) {
              this.confirmOff = b.id;
              this.panelFor = null;
              this.render();
            } else this.toggle(b, true);
          } }, icon(on ? "remove" : "add"), h("span", {}, busy ? "Working…" : on ? "Turn off" : "Turn on"))));
      if (asking) {
        out.push(h("div", { class: "fc-confirm" },
          h("p", { class: "fc-help" }, h("b", {}, `Turn ${name} off?`), ` ${b.switch.off_note || "Its settings are kept, so turning it on again restores it."}`),
          h("div", { class: "fc-row" },
            h("button", { type: "button", class: "fc-btn small primary edit", disabled: ro || busy, onclick: () => {
              this.confirmOff = null;
              this.toggle(b, false);
            } }, icon("remove"), h("span", {}, `Turn ${name} off`)),
            h("button", { type: "button", class: "fc-btn small edit", onclick: () => {
              this.confirmOff = null;
              this.panelFor = null;
              this.render();
            } }, h("span", {}, "Keep it on")))));
      }
      if (b.switch.managed) out.push(h("p", { class: "fc-help" }, "The server's SENTRAI_EXTENSIONS setting decides which extensions are on. Change it where SentrAI is started."));
    }
    if (b.settings && b.settings.length) out.push(...this.settingsForm(b));
    if (this.message && this.message.block === b.id && this.message.text) {
      out.push(h("div", { class: `fc-note-row${this.message.ok ? "" : " bad"}`, role: this.message.ok ? "status" : "alert" },
        icon(this.message.ok ? "check_circle" : "error"), h("span", {}, this.message.text)));
    }
    const row = h("div", { class: "fc-row end" });
    if (b.page) {
      row.append(h("button", { type: "button", class: "fc-btn", onclick: () => this.open(b) },
        h("span", {}, `Open ${b.host ? b.title : PAGE_WORDS[b.page] || b.page}`), icon("arrow_forward")));
    }
    if (!ro) row.append(h("button", { type: "button", class: "fc-btn danger", onclick: () => this.hideSelected() }, icon("visibility_off"), h("span", {}, "Take off the canvas")));
    out.push(row);
    return out;
  }

  /** The live part of a block's panel: the big number, the note and the facts; redrawn on every refresh. */
  fillLive(el, b) {
    const hasValue = b.value !== null && b.value !== undefined && b.value !== "";
    const sig = JSON.stringify([b.value, b.unit, b.note, b.badge, b.facts]);
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    const facts = (b.facts || []).filter((f) => Array.isArray(f) && f.length === 2 && str(f[1]));
    el.replaceChildren(...kids(
      hasValue ? h("div", { class: "fc-big" }, String(b.value), b.unit ? h("small", {}, ` ${b.unit}`) : null) : null,
      b.note ? h("div", { class: "fc-note" }, b.note) : null,
      facts.length ? h("dl", { class: "fc-facts" }, ...facts.map(([k, v]) => [h("dt", {}, str(k)), h("dd", {}, str(v))])) : null));
  }

  refreshLive(id) {
    const b = this.block(id);
    if (b && this.liveEl && this.panel.contains(this.liveEl)) this.fillLive(this.liveEl, b);
    if (b && this.formEl && this.panel.contains(this.formEl)) this.refreshForm(b);
  }

  settingsForm(b) {
    const ro = this.readOnly;
    if (!this.draft || this.draft.id !== b.id) this.draft = { id: b.id, values: {} };
    const values = this.draft.values;
    const fields = [];
    for (const f of b.settings) {
      const id = `fc-f-${f.env}`;
      const current = f.env in values ? values[f.env] : str(f.value);
      let input;
      if (f.kind === "set") {
        const chosen = current.split(",").map((x) => x.trim()).filter(Boolean);
        const grid = h("div", { class: "fc-check-grid" });
        for (const [v, words] of f.choices || []) {
          const boxId = `${id}-${v}`;
          const cb = h("input", { type: "checkbox", id: boxId, value: v, disabled: ro });
          cb.checked = chosen.includes(v);
          cb.addEventListener("change", () => this.typed(b, f.env, [...grid.querySelectorAll("input:checked")].map((x) => x.value).join(",")));
          grid.append(h("label", { class: "fc-check", for: boxId }, cb, h("span", {}, words)));
        }
        input = h("fieldset", { class: "fc-checks", id }, h("legend", {}, f.label), grid);
        fields.push(input);
        continue;
      }
      if (f.choices && f.choices.length) {
        input = h("select", { id, disabled: ro }, f.choices.map((v) => h("option", { value: v }, v)));
        input.value = current;
        input.addEventListener("change", () => this.typed(b, f.env, input.value));
      } else {
        input = h("input", { id, type: f.kind === "int" || f.kind === "float" ? "number" : "text", step: f.kind === "int" ? "1" : f.kind === "float" ? "any" : null,
          inputmode: f.kind === "int" ? "numeric" : f.kind === "float" ? "decimal" : null, autocomplete: "off", spellcheck: "false", disabled: ro, maxlength: 2000 });
        input.value = current;
        input.addEventListener("input", () => this.typed(b, f.env, input.value));
      }
      input.dataset.env = f.env;
      fields.push(h("div", { class: "fc-field" }, h("label", { for: id }, f.label), input, h("span", { class: "fc-env" }, f.env)));
    }
    this.problemsEl = h("ul", { class: "fc-problems", hidden: true });
    this.saveBtn = h("button", { type: "button", class: "fc-btn primary small edit", onclick: () => this.saveSettings() }, icon("save"), h("span", {}, "Save settings"));
    this.resetBtn = h("button", { type: "button", class: "fc-btn small edit", onclick: () => {
      this.draft = null;
      this.panelFor = null;
      this.render();
    } }, icon("undo"), h("span", {}, "Reset"));
    this.formEl = h("div", { class: "fc-form" },
      h("p", { class: "fc-ptitle sub" }, icon("tune"), h("span", {}, "Settings")),
      ro ? h("p", { class: "fc-help" }, "The settings this step follows. An Owner or Admin can change them.") : null,
      ...fields, this.problemsEl,
      ro ? null : h("div", { class: "fc-row" }, this.saveBtn, this.resetBtn));
    this.refreshForm(b);
    return [this.formEl];
  }

  typed(b, env, value) {
    if (this.readOnly) return;
    if (!this.draft || this.draft.id !== b.id) this.draft = { id: b.id, values: {} };
    this.draft.values[env] = value;
    this.message = "";
    this.refreshForm(b);
  }

  /** The form's buttons and problems follow the draft; the inputs are left alone (someone is typing in them).
      A value saved elsewhere meanwhile shows in any field that is not being changed here. */
  refreshForm(b) {
    const values = this.draft && this.draft.id === b.id ? this.draft.values : {};
    for (const f of b.settings || []) {
      if (f.env in values) continue;
      const el = this.formEl.querySelector(`[data-env="${f.env}"]`);
      if (el && el !== this.host.activeElement && el.value !== str(f.value)) el.value = str(f.value);
    }
    const changes = settingChanges(b.settings, values);
    const problems = settingProblems(b.settings, values);
    const saving = [...this.pending.values()].some((p) => p.kind === "settings" && p.block === b.id);
    if (this.saveBtn) {
      this.saveBtn.disabled = this.readOnly || saving || !Object.keys(changes).length || problems.length > 0;
      this.saveBtn.querySelector("span:last-child").textContent = saving ? "Saving…" : "Save settings";
    }
    if (this.resetBtn) this.resetBtn.disabled = this.readOnly || !Object.keys(values).length || saving;
    this.problemsEl.hidden = !problems.length;
    this.problemsEl.replaceChildren(...problems.map((p) => h("li", {}, icon("error"), h("span", {}, p))));
    this.formEl.classList.toggle("dirty", Object.keys(changes).length > 0);
  }

  notePanel(id) {
    const ro = this.readOnly;
    const text = h("textarea", { id: "fc-f-note", rows: 5, maxlength: MAX_NOTE, disabled: ro, placeholder: "What should whoever looks at this next know?" });
    text.value = this.st.notes[id] || "";
    text.addEventListener("input", () => {
      if (this.noteTyping !== id) {
        this.undo.push(this.snapshot());
        this.redo = [];
        this.noteTyping = id;
      }
      this.st.notes[id] = text.value.slice(0, MAX_NOTE);
      this.renderNodes();
      this.drawWires();
      this.scheduleSave();
    });
    text.addEventListener("blur", () => { this.noteTyping = null; });
    return [h("p", { class: "fc-ptitle" }, icon("sticky_note_2"), h("span", {}, "Note")),
      h("div", { class: "fc-field" }, h("label", { for: "fc-f-note" }, "Text"), text),
      ro ? null : h("div", { class: "fc-row end" }, h("button", { type: "button", class: "fc-btn danger", onclick: () => this.hideSelected() }, icon("delete"), h("span", {}, "Delete note")))];
  }

  wirePanel(sel) {
    const w = wiresOf(this.data, this.st).find((x) => x.from === sel.from && x.to === sel.to);
    if (!w) return null;
    return [h("p", { class: "fc-ptitle" }, icon("link"), h("span", {}, `${this.titleOf(w.from)} → ${this.titleOf(w.to)}`)),
      h("p", { class: "fc-help" }, w.user ? "A wire drawn by hand: it shows how you think of it and changes nothing SentrAI does."
        : w.live ? "An attack is on this path right now: both ends are busy." : "What happens next in the pipeline."),
      this.readOnly ? null : h("div", { class: "fc-row end" }, h("button", { type: "button", class: "fc-btn danger", onclick: () => this.removeSelectedWire() }, icon("link_off"), h("span", {}, "Remove this wire")))];
  }

  focusField(id, selectAll) {
    requestAnimationFrame(() => {
      const el = this.panel.querySelector(`#${id}`);
      if (!el) return;
      el.focus({ preventScroll: true });
      if (selectAll && el.select) el.select();
    });
  }

  // ---------------------------------------------------------------- editing actions

  hideSelected() {
    if (!this.sel || this.sel.kind !== "block" || this.readOnly) return;
    const id = this.sel.id;
    this.change((st) => {
      const said = hideBlock(this.data, st, id);
      if (!said) return false;
      this.sel = null;
      if (this.draft && this.draft.id === id) this.draft = null;
      return said;
    });
    this.viewport.focus({ preventScroll: true });
  }

  removeSelectedWire() {
    if (this.readOnly || !this.sel || this.sel.kind !== "wire") return;
    const { from, to } = this.sel;
    this.change((st) => {
      this.sel = null;
      return removeWire(this.data, st, from, to) || false;
    });
  }

  select(sel, focus = false) {
    const changed = !same(sel, this.sel);
    this.sel = sel;
    if (changed) {
      this.message = "";
      this.confirmOff = null;
      this.render();
    }
    if (focus && sel && sel.kind === "block") this.nodeEls.get(sel.id)?.focus({ preventScroll: true });
  }

  /** Pan so a block is in view. */
  reveal(id) {
    const b = this.box(id);
    if (!b) return;
    const rect = this.viewport.getBoundingClientRect();
    const k = this.view.k;
    const x = b.x * k + this.view.x;
    const y = b.y * k + this.view.y;
    if (x < 16 || y < 16 || x + b.w * k > rect.width - 16 || y + b.h * k > rect.height - 16) {
      this.view.x = rect.width / 2 - (b.x + b.w / 2) * k;
      this.view.y = rect.height / 2 - (b.y + b.h / 2) * k;
      this.applyView();
    }
  }

  // ---------------------------------------------------------------- view: pan and zoom

  applyView() {
    const { x, y, k } = this.view;
    this.world.style.transform = `translate(${x}px, ${y}px) scale(${k})`;
    this.viewport.style.backgroundSize = `${24 * k}px ${24 * k}px`;
    this.viewport.style.backgroundPosition = `${x}px ${y}px`;
    this.zoomLabel.textContent = `${Math.round(k * 100)}%`;
    this.hideTip();
  }

  bounds() {
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const id of this.nodeEls.keys()) {
      const b = this.box(id);
      if (!b) continue;
      x0 = Math.min(x0, b.x);
      y0 = Math.min(y0, b.y);
      x1 = Math.max(x1, b.x + b.w);
      y1 = Math.max(y1, b.y + b.h);
    }
    if (!Number.isFinite(x0)) return { x0: 0, y0: 0, x1: 400, y1: 300 };
    return { x0, y0, x1, y1 };
  }

  fit() {
    const b = this.bounds();
    const rect = this.viewport.getBoundingClientRect();
    this.needsFit = !rect.width;
    if (!rect.width) return;
    const pad = 28;
    const k = clamp(Math.min((rect.width - 2 * pad) / (b.x1 - b.x0), (rect.height - 2 * pad) / (b.y1 - b.y0)), ZOOM.min, 1);
    this.view = { k, x: (rect.width - (b.x1 - b.x0) * k) / 2 - b.x0 * k, y: (rect.height - (b.y1 - b.y0) * k) / 2 - b.y0 * k };
    this.applyView();
  }

  zoomBy(f, cx, cy) {
    const rect = this.viewport.getBoundingClientRect();
    const px = cx === undefined ? rect.width / 2 : cx - rect.left;
    const py = cy === undefined ? rect.height / 2 : cy - rect.top;
    const k = clamp(this.view.k * f, ZOOM.min, ZOOM.max);
    const wx = (px - this.view.x) / this.view.k;
    const wy = (py - this.view.y) / this.view.k;
    this.view = { k, x: px - wx * k, y: py - wy * k };
    this.applyView();
  }

  wheel(e) {
    if (!(e.ctrlKey || e.metaKey)) return; // a plain scroll keeps scrolling the page
    e.preventDefault();
    this.zoomBy(Math.exp(-e.deltaY * 0.0018), e.clientX, e.clientY);
  }

  toWorld(e) {
    const rect = this.viewport.getBoundingClientRect();
    return { x: (e.clientX - rect.left - this.view.x) / this.view.k, y: (e.clientY - rect.top - this.view.y) / this.view.k };
  }

  // ---------------------------------------------------------------- pointer: drag, connect, pan

  down(e) {
    if (e.button !== 0 || !this.st) return;
    if (!this.menu.hidden) this.closeMenu();
    if (e.target.closest(".fc-wire-x")) return;
    const port = e.target.closest("[data-port]");
    const nodeEl = e.target.closest(".fc-node");
    const hit = e.target.closest("[data-wire]");
    const at = this.toWorld(e);
    this.hideTip();
    if (port && nodeEl && !this.readOnly) {
      this.drag = { type: "link", from: nodeEl.dataset.id, at, start: at, target: null };
      this.root.classList.add("linking");
    } else if (nodeEl) {
      const id = nodeEl.dataset.id;
      this.drag = { type: "node", id, start: at, orig: { ...this.st.pos[id] }, moved: false, snap: this.snapshot() };
    } else if (hit) {
      const [from, to] = hit.dataset.wire.split(">");
      this.select({ kind: "wire", from, to });
      e.preventDefault();
      return;
    } else {
      this.drag = { type: "pan", sx: e.clientX, sy: e.clientY, ox: this.view.x, oy: this.view.y, moved: false };
    }
    this.viewport.setPointerCapture(e.pointerId);
    e.preventDefault();
  }

  move(e) {
    const g = this.drag;
    if (!g) return;
    if (g.type === "pan") {
      const dx = e.clientX - g.sx;
      const dy = e.clientY - g.sy;
      if (Math.abs(dx) + Math.abs(dy) > 3) g.moved = true;
      this.view.x = g.ox + dx;
      this.view.y = g.oy + dy;
      this.applyView();
      this.root.classList.toggle("panning", g.moved);
      return;
    }
    const at = this.toWorld(e);
    if (g.type === "node") {
      const dx = at.x - g.start.x;
      const dy = at.y - g.start.y;
      if (!g.moved && Math.abs(dx) + Math.abs(dy) < 4 / this.view.k) return;
      if (this.readOnly) return;
      g.moved = true;
      this.root.classList.add("dragging");
      this.nodeEls.get(g.id)?.classList.add("lifted");
      this.st.pos[g.id] = { x: Math.round(g.orig.x + dx), y: Math.round(g.orig.y + dy) };
      this.placeNodes();
      this.drawWires();
      return;
    }
    g.at = at;
    const target = this.blockAt(at, g.from);
    if (target !== g.target) {
      if (g.target) this.nodeEls.get(g.target)?.classList.remove("drop");
      if (target) this.nodeEls.get(target)?.classList.add("drop");
      g.target = target;
    }
    const a = this.box(g.from);
    const b = target ? this.box(target) : { x: at.x, y: at.y, w: 0, h: 0 };
    if (!a) return;
    const geo = wirePath(a, b);
    this.ghost.replaceChildren(s("g", { class: "w user hot" }, s("path", { class: "line", d: geo.d }), s("path", { class: "head", d: arrowHead(geo) })));
  }

  up(e, cancelled = false) {
    const g = this.drag;
    if (!g) return;
    this.drag = null;
    if (this.viewport.hasPointerCapture && e.pointerId >= 0 && this.viewport.hasPointerCapture(e.pointerId)) this.viewport.releasePointerCapture(e.pointerId);
    this.root.classList.remove("dragging", "panning", "linking");
    if (g.type === "pan") {
      if (!g.moved && !cancelled) this.select(null);
    } else if (g.type === "node") {
      this.nodeEls.get(g.id)?.classList.remove("lifted");
      if (g.moved && !cancelled) {
        if (signature(this.st, this.data.defaults) !== signature(g.snap.st, this.data.defaults)) {
          this.undo.push(g.snap);
          this.redo = [];
          this.scheduleSave();
        }
        this.render();
      } else if (cancelled) {
        this.st = g.snap.st;
        this.render();
      } else this.select({ kind: "block", id: g.id }, true);
    } else {
      this.ghost.replaceChildren();
      if (g.target) this.nodeEls.get(g.target)?.classList.remove("drop");
      if (!cancelled && g.target) {
        const { from, target } = g;
        if (!this.change((st) => addWire(this.data, st, from, target) || false)) this.say("That wire is already there.");
      }
    }
    if (this.queued) {
      this.queued = false;
      this.update(this.data);
    }
  }

  dblclick(e) {
    const nodeEl = e.target.closest(".fc-node");
    if (!nodeEl) return;
    const id = nodeEl.dataset.id;
    if (isNote(id)) {
      this.select({ kind: "block", id });
      this.focusField("fc-f-note", false);
    } else this.open(this.block(id));
  }

  blockAt(at, except) {
    for (const id of visibleIds(this.data, this.st)) {
      if (id === except) continue;
      const b = this.box(id);
      if (b && at.x >= b.x - 10 && at.x <= b.x + b.w + 10 && at.y >= b.y - 10 && at.y <= b.y + b.h + 10) return id;
    }
    return null;
  }

  hoverAt(e) {
    if (this.drag) return;
    const nodeEl = e.target.closest(".fc-node");
    this.setHover(nodeEl ? nodeEl.dataset.id : null);
  }

  setHover(id) {
    if (this.hover === id) return;
    this.hover = id;
    if (!this.sel) this.drawWires();
    if (id) this.showTip(id);
    else this.hideTip();
  }

  showTip(id) {
    const b = this.block(id);
    if (!b || !b.what) return this.hideTip();
    const el = this.nodeEls.get(id);
    if (!el) return this.hideTip();
    this.tip.textContent = b.what;
    this.tip.hidden = false;
    const vp = this.viewport.getBoundingClientRect();
    const nr = el.getBoundingClientRect();
    const box = { x: nr.left - vp.left, y: nr.top - vp.top, w: nr.width, h: nr.height };
    const at = tipAt(box, { w: vp.width, h: vp.height }, { w: this.tip.offsetWidth, h: this.tip.offsetHeight });
    this.tip.style.left = `${at.x}px`;
    this.tip.style.top = `${at.y}px`;
    return undefined;
  }

  hideTip() {
    this.tip.hidden = true;
  }

  // ---------------------------------------------------------------- keyboard

  nodeKey(e) {
    const el = e.target.closest(".fc-node");
    if (!el || e.target !== el) return;
    const id = el.dataset.id;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      this.select({ kind: "block", id }, true);
      if (isNote(id)) this.focusField("fc-f-note", false);
      return;
    }
    if ((e.key === "Delete" || e.key === "Backspace") && !this.readOnly) {
      e.preventDefault();
      this.sel = { kind: "block", id };
      this.hideSelected();
      return;
    }
    const step = e.shiftKey ? 48 : 12;
    const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
    if (!delta || this.readOnly || !this.st.pos[id]) return;
    e.preventDefault();
    if (this.nudging !== id) {
      this.undo.push(this.snapshot());
      this.redo = [];
      this.nudging = id;
    }
    this.st.pos[id] = { x: this.st.pos[id].x + delta[0], y: this.st.pos[id].y + delta[1] };
    this.placeNodes();
    this.drawWires();
    this.scheduleSave();
    this.reveal(id);
    el.focus({ preventScroll: true });
  }

  key(e) {
    const mod = e.ctrlKey || e.metaKey;
    const typing = isTyping(e.target);
    if (mod && e.key.toLowerCase() === "s" && this.draft) {
      e.preventDefault();
      this.saveSettings();
    } else if (mod && !typing && e.key.toLowerCase() === "z") {
      e.preventDefault();
      if (e.shiftKey) this.redoLast();
      else this.undoLast();
    } else if (mod && !typing && e.key.toLowerCase() === "y") {
      e.preventDefault();
      this.redoLast();
    } else if (e.key === "Escape") {
      if (!this.menu.hidden) {
        this.closeMenu();
        this.btn.add.focus();
      } else if (this.drag) {
        this.up({ pointerId: -1 }, true);
        this.ghost.replaceChildren();
      } else if ((this.sel || this.showHelp) && !typing) {
        this.showHelp = false;
        this.select(null);
        this.render();
      }
    } else if ((e.key === "Delete" || e.key === "Backspace") && !typing && this.sel && this.sel.kind === "wire") {
      e.preventDefault();
      this.removeSelectedWire();
    } else if (!this.menu.hidden && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
      const items = [...this.menu.querySelectorAll("button")];
      const i = items.indexOf(this.host.activeElement);
      const next = items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length];
      if (next) {
        e.preventDefault();
        next.focus();
      }
    }
  }

  say(text) {
    this.live.textContent = "";
    requestAnimationFrame(() => { this.live.textContent = text; });
  }
}
