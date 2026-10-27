/* "What it may do on its own" map ("How it works" page). An attack SentrAI could act on goes left to right
   through three gates: is it sure enough, is the danger high enough, is it still under the hourly limit.
   Past all three, each kind of action is either done on its own (top lane) or waits for a person
   (bottom lane); drag an action between the lanes, or press it to move it. Anything that fails a gate
   waits for a person too. A block undoes itself after a while, and some addresses and accounts are never
   touched at all.

   Changes stay here until Save, which hands the settings to Python; Python checks and writes them to
   the settings file. Read-only for anyone who may not change settings. A Streamlit component
   (st.components.v2): no iframe, nothing from the internet, colours from the console's CSS variables. */

export const FIELDS = ["NEEDLE_MIN_CONFIDENCE", "RISK_THRESHOLD", "MAX_AUTO_ACTIONS_PER_HOUR", "HOTPATCH_TTL_HOURS",
  "MAX_TTL_HOURS", "PROTECTED_IPS", "PROTECTED_USERS"];

/** The settings as the map edits them: the allowed actions as a list, everything else as text. */
export function fromSettings(settings, actions) {
  const known = (actions || []).map((a) => a[0]);
  const auto = String(settings.AUTO_ACTIONS || "").split(",").map((x) => x.trim()).filter((x) => known.includes(x));
  const out = { auto: known.filter((a) => auto.includes(a)) };
  for (const f of FIELDS) out[f] = String(settings[f] ?? "");
  return out;
}

/** Back to the settings file's shape: AUTO_ACTIONS in the order the actions are listed. */
export function toSettings(draft, actions) {
  const out = { AUTO_ACTIONS: (actions || []).map((a) => a[0]).filter((a) => draft.auto.includes(a)).join(",") };
  for (const f of FIELDS) out[f] = String(draft[f] ?? "").trim();
  return out;
}

/** What is wrong with a draft, in words a person can act on. Empty when it can be saved. */
export function problems(d) {
  const out = [];
  const num = (v) => (String(v).trim() === "" ? NaN : Number(v));
  const c = num(d.NEEDLE_MIN_CONFIDENCE);
  if (!(c >= 0 && c <= 1)) out.push("How sure it must be is a number from 0 to 1 (0.6 means 60 %).");
  const r = num(d.RISK_THRESHOLD);
  if (!(Number.isInteger(r) && r >= 0 && r <= 100)) out.push("The danger level is a whole number from 0 to 100.");
  const n = num(d.MAX_AUTO_ACTIONS_PER_HOUR);
  if (!(Number.isInteger(n) && n >= 0)) out.push("Actions in one hour is a whole number, 0 or more.");
  const t = num(d.HOTPATCH_TTL_HOURS), m = num(d.MAX_TTL_HOURS);
  if (!(t > 0)) out.push("A block must last more than 0 hours.");
  if (!(m > 0)) out.push("The longest block must be more than 0 hours.");
  if (t > 0 && m > 0 && t > m) out.push("A block cannot last longer than the longest block allowed.");
  return out;
}

export const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

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

const maps = new WeakMap();

export default function mount(component) {
  const { parentElement, data, setTriggerValue } = component;
  let map = maps.get(parentElement);
  if (!map) {
    map = new LimitsMap(parentElement);
    maps.set(parentElement, map);
  }
  map.update(data || {}, setTriggerValue);
}

class LimitsMap {
  constructor(host) {
    this.root = h("div", { class: "lm" });
    host.append(this.root);
    this.draft = null;
    this.version = null;
    this.pending = null;
    this.message = "";
  }

  update(data, setTrigger) {
    this.setTrigger = setTrigger;
    this.data = data;
    const result = data.result;
    if (this.pending && result && result.id === this.pending) {
      this.pending = null;
      this.message = result.message || "";
      this.bad = !result.ok;
      if (result.ok) this.adopt();
    } else if (!this.draft || (data.version !== this.version && !this.dirty())) {
      this.adopt();
    }
    this.render();
  }

  adopt() {
    this.base = fromSettings(this.data.settings || {}, this.data.actions);
    this.draft = JSON.parse(JSON.stringify(this.base));
    this.version = this.data.version;
  }

  dirty() {
    return !!this.draft && !same(this.draft, this.base);
  }

  ro() {
    return !!this.data.read_only;
  }

  change(fn) {
    if (this.ro()) return;
    fn(this.draft);
    this.message = "";
    this.render();
  }

  move(action, toAuto) {
    this.change((d) => {
      d.auto = d.auto.filter((a) => a !== action);
      if (toAuto) d.auto.push(action);
    });
  }

  field(key, label, opts = {}) {
    const input = h("input", { class: "lm-in", type: opts.type || "number", inputmode: opts.inputmode || "decimal",
      value: this.draft[key], disabled: this.ro(), "aria-label": label, step: opts.step, min: opts.min, max: opts.max,
      placeholder: opts.placeholder });
    input.addEventListener("change", () => this.change((d) => { d[key] = input.value; }));
    return h("label", { class: `lm-field${opts.wide ? " wide" : ""}` }, h("span", {}, label), input);
  }

  gate(ico, title, body, no) {
    return h("div", { class: "lm-box gate" }, h("div", { class: "lm-head" }, icon(ico), h("b", {}, title)), body,
      h("div", { class: "lm-no" }, icon("arrow_downward"), no));
  }

  lane(toAuto, title, sub) {
    const actions = (this.data.actions || []).filter(([a]) => this.draft.auto.includes(a) === toAuto);
    const chips = actions.map(([a, words]) => h("button", {
      type: "button", class: `lm-chip${toAuto ? " auto" : ""}`, draggable: this.ro() ? "false" : "true", disabled: this.ro(),
      title: this.ro() ? "" : toAuto ? "Press or drag down to make it wait for a person" : "Press or drag up to let it run on its own",
      "aria-label": `${words}: ${toAuto ? "done on its own" : "waits for a person"}. Press to move it.`,
      onclick: () => this.move(a, !toAuto),
      ondragstart: (ev) => { ev.dataTransfer.setData("text/plain", a); ev.dataTransfer.effectAllowed = "move"; },
    }, icon(toAuto ? "check" : "person"), words));
    const zone = h("div", { class: `lm-lane${toAuto ? " auto" : " ask"}` },
      h("div", { class: "lm-head" }, icon(toAuto ? "smart_toy" : "person"), h("b", {}, title), h("span", { class: "lm-sub" }, sub)),
      h("div", { class: "lm-chips" }, chips.length ? chips : h("span", { class: "lm-empty" }, toAuto ? "Nothing: every action waits for a person." : "Nothing: every action runs on its own.")));
    zone.addEventListener("dragover", (ev) => { if (!this.ro()) { ev.preventDefault(); zone.classList.add("over"); } });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (ev) => {
      ev.preventDefault();
      zone.classList.remove("over");
      const a = ev.dataTransfer.getData("text/plain");
      if (a) this.move(a, toAuto);
    });
    return zone;
  }

  render() {
    const d = this.draft;
    const errs = problems(d);
    const dirty = this.dirty();
    const ro = this.ro();
    const arrow = () => h("div", { class: "lm-arrow", "aria-hidden": "true" }, icon("arrow_forward"));
    const pct = Math.round(Number(d.NEEDLE_MIN_CONFIDENCE) * 100);

    const flow = h("div", { class: "lm-flow" },
      h("div", { class: "lm-box start" }, h("div", { class: "lm-head" }, icon("crisis_alert"), h("b", {}, "An attack is found")),
        h("div", { class: "lm-sub" }, "and there is something SentrAI could do about it")),
      arrow(),
      this.gate("fact_check", "Sure enough?", this.field("NEEDLE_MIN_CONFIDENCE", "At least this sure (0 to 1)", { step: "0.05", min: 0, max: 1 }),
        Number.isFinite(pct) ? `Less than ${pct} % sure: asks a person` : "Not sure enough: asks a person"),
      arrow(),
      this.gate("speed", "Dangerous enough?", this.field("RISK_THRESHOLD", "Danger level from (0 to 100)", { step: "1", min: 0, max: 100, inputmode: "numeric" }),
        "Lower: tells people, blocks nothing"),
      arrow(),
      this.gate("schedule", "Under the hourly limit?", this.field("MAX_AUTO_ACTIONS_PER_HOUR", "At most this many an hour", { step: "1", min: 0, inputmode: "numeric" }),
        "Past it: asks a person"),
      arrow(),
      h("div", { class: "lm-lanes" },
        this.lane(true, "Does it on its own", "then tells people"),
        this.lane(false, "Asks a person first", "approve or reject")),
      arrow(),
      h("div", { class: "lm-box gate" }, h("div", { class: "lm-head" }, icon("history"), h("b", {}, "Undoes itself")),
        this.field("HOTPATCH_TTL_HOURS", "After this many hours", { step: "0.5", min: 0 }),
        this.field("MAX_TTL_HOURS", "Never longer than (hours)", { step: "1", min: 0 }),
        h("div", { class: "lm-no" }, icon("arrow_downward"), "unless a person keeps it")));

    const fence = h("div", { class: "lm-fence" },
      h("div", { class: "lm-head" }, icon("lock"), h("b", {}, "Never touched, whatever happens"),
        h("span", { class: "lm-sub" }, "checked before every action, on its own or approved")),
      h("div", { class: "lm-fence-fields" },
        this.field("PROTECTED_IPS", "Addresses and networks (comma-separated)", { type: "text", inputmode: "text", wide: true, placeholder: "e.g. 10.0.0.0/8, 203.0.113.7" }),
        this.field("PROTECTED_USERS", "Accounts (admin and service accounts always are)", { type: "text", inputmode: "text", wide: true, placeholder: "e.g. ceo, backup-svc" })));

    let status = ro ? "Read only" : this.pending ? "Saving…" : dirty && errs.length ? "Fix the problems below to save" : dirty ? "Unsaved changes" : "All changes saved";
    const save = h("button", { type: "button", class: "lm-btn primary", disabled: ro || !dirty || !!this.pending || errs.length > 0,
      onclick: () => {
        this.pending = `save-${Date.now()}`;
        this.setTrigger && this.setTrigger("save", { id: this.pending, settings: toSettings(this.draft, this.data.actions) });
        this.render();
      } }, icon("save"), "Save changes");
    const discard = h("button", { type: "button", class: "lm-btn", disabled: ro || !dirty || !!this.pending,
      onclick: () => { this.draft = JSON.parse(JSON.stringify(this.base)); this.message = ""; this.render(); } }, icon("undo"), "Discard");
    const bar = h("div", { class: "lm-bar" }, h("span", { class: `lm-status${dirty && !ro ? " dirty" : ""}` }, status),
      h("span", { class: "lm-spacer" }), discard, save);

    const notes = [];
    if (ro) notes.push(h("div", { class: "lm-note" }, icon("lock"), this.data.lock_reason || "You can look, but not change anything here."));
    if (!ro && errs.length) notes.push(h("ul", { class: "lm-problems" }, errs.map((e) => h("li", {}, icon("error"), e))));
    if (this.message) notes.push(h("div", { class: `lm-note${this.bad ? " bad" : ""}`, role: this.bad ? "alert" : "status" },
      icon(this.bad ? "error" : "check_circle"), this.message));

    // Redrawing replaces the inputs: keep the keyboard where it was (by the field's label).
    const shadow = this.root.getRootNode();
    const had = shadow && shadow.activeElement ? shadow.activeElement.getAttribute("aria-label") : null;
    this.root.classList.toggle("ro", ro);
    this.root.replaceChildren(bar, ...notes, flow, fence);
    if (had) {
      const again = [...this.root.querySelectorAll("[aria-label]")].find((el) => el.getAttribute("aria-label") === had);
      if (again) again.focus();
    }
  }
}
