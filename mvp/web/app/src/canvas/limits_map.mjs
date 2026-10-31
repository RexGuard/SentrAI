/* Automation guardrails: what SentrAI may do without a person, as a policy that reads top to bottom.

     1. When it may act      at least this sure, this dangerous, under the hourly limit
     2. Done on its own      the kinds of action it may take without asking, and how long a block lasts
     3. Asks a person first  every other kind of action
     4. Never touched        addresses, networks and accounts no action ever touches

   Drag an action between 2 and 3 by its handle, or press it to move it. The "never touched" lists are tag
   inputs: Enter or a comma turns what you typed into a checked tag, × takes one away.

   Lives on its own page, which does not refresh itself, so nothing redraws under your typing. Changes stay
   here until Save, which hands the settings to Python; Python checks and writes them to the settings file.
   Read-only for anyone who may not change settings. A Streamlit component (st.components.v2): no iframe,
   nothing from the internet, colours from the console's CSS variables. */

export const FIELDS = ["CONFIDENCE_PCT", "RISK_THRESHOLD", "MAX_AUTO_ACTIONS_PER_HOUR", "HOTPATCH_TTL_HOURS",
  "MAX_TTL_HOURS", "PROTECTED_IPS", "PROTECTED_USERS"];

const blank = (v) => String(v ?? "").trim() === "";

/** 0.6 in the settings file is 60 here: the page speaks in percent, like the rest of the console. */
export function toPercent(v) {
  const n = Number(String(v ?? "").trim());
  return blank(v) || !Number.isFinite(n) ? String(v ?? "") : String(Math.round(n * 1000) / 10);
}

export function fromPercent(v) {
  const n = Number(String(v ?? "").trim());
  return blank(v) || !Number.isFinite(n) ? String(v ?? "").trim() : String(Math.round(n * 10) / 1000);
}

/** The settings as the page edits them: the allowed actions as a list, the confidence in percent, the rest as text. */
export function fromSettings(settings, actions) {
  const known = (actions || []).map((a) => a[0]);
  const auto = String(settings.AUTO_ACTIONS || "").split(",").map((x) => x.trim()).filter((x) => known.includes(x));
  const out = { auto: known.filter((a) => auto.includes(a)) };
  for (const f of FIELDS) out[f] = f === "CONFIDENCE_PCT" ? toPercent(settings.NEEDLE_MIN_CONFIDENCE) : String(settings[f] ?? "");
  return out;
}

/** Back to the settings file's shape: AUTO_ACTIONS in the order the actions are listed, confidence 0 to 1. */
export function toSettings(draft, actions) {
  const out = { AUTO_ACTIONS: (actions || []).map((a) => a[0]).filter((a) => draft.auto.includes(a)).join(",") };
  for (const f of FIELDS) {
    if (f === "CONFIDENCE_PCT") out.NEEDLE_MIN_CONFIDENCE = fromPercent(draft[f]);
    else out[f] = String(draft[f] ?? "").trim();
  }
  return out;
}

/** A comma list as tags, and back: blanks and repeats dropped. */
export const tagsOf = (text) => [...new Set(String(text || "").split(",").map((x) => x.trim()).filter(Boolean))];
export const joinTags = (tags) => tags.join(",");

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HOST = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;

function ipv6(text) {
  if (!/^[0-9A-Fa-f:.]+$/.test(text)) return false;
  const halves = text.split("::");
  if (halves.length > 2) return false;
  const groups = (s) => (s === "" ? [] : s.split(":"));
  let parts = [...groups(halves[0]), ...(halves.length === 2 ? groups(halves[1]) : [])];
  let count = parts.length;
  if (parts.length && IPV4.test(parts[parts.length - 1])) { // ::ffff:192.0.2.1
    parts = parts.slice(0, -1);
    count = parts.length + 2;
  }
  if (!parts.every((p) => /^[0-9A-Fa-f]{1,4}$/.test(p))) return false;
  return halves.length === 2 ? count <= 7 : count === 8;
}

/** One "never touched" entry the core can use: an IPv4 or IPv6 address, a network (10.0.0.0/8) or a host
    name such as localhost. shaping.protected_address_ok checks the same again on Save. */
export function addressOk(text) {
  const t = String(text || "").trim();
  const [addr, bits, more] = t.split("/");
  if (more !== undefined || addr === "") return false;
  if (bits !== undefined) {
    if (!/^\d{1,3}$/.test(bits)) return false;
    if (IPV4.test(addr)) return Number(bits) <= 32;
    return ipv6(addr) && Number(bits) <= 128;
  }
  return IPV4.test(addr) || ipv6(addr) || (HOST.test(addr) && !/^[\d.]+$/.test(addr));
}

export const accountOk = (text) => !blank(text) && !/\s/.test(String(text).trim());

/** What is wrong with a draft, in words a person can act on. Empty when it can be saved. */
export function problems(d) {
  const out = [];
  const num = (v) => (blank(v) ? NaN : Number(v));
  const c = num(d.CONFIDENCE_PCT);
  if (!(c >= 0 && c <= 100)) out.push("How sure it must be is a percentage from 0 to 100.");
  const r = num(d.RISK_THRESHOLD);
  if (!(Number.isInteger(r) && r >= 0 && r <= 100)) out.push("The danger score is a whole number from 0 to 100.");
  const n = num(d.MAX_AUTO_ACTIONS_PER_HOUR);
  if (!(Number.isInteger(n) && n >= 0)) out.push("Actions in one hour is a whole number, 0 or more.");
  const t = num(d.HOTPATCH_TTL_HOURS), m = num(d.MAX_TTL_HOURS);
  if (!(t > 0)) out.push("A block must last more than 0 hours.");
  if (!(m > 0)) out.push("The longest block must be more than 0 hours.");
  if (t > 0 && m > 0 && t > m) out.push("A block cannot last longer than the longest block allowed.");
  const badIp = tagsOf(d.PROTECTED_IPS).find((x) => !addressOk(x));
  if (badIp) out.push(`${badIp} is not an address, a network or a host name.`);
  return out;
}

/** The policy in one paragraph, from the draft as it stands: what the page says, the way a person would. */
export function summary(d, actions) {
  const words = Object.fromEntries(actions || []);
  const list = (xs) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);
  const allowed = d.auto.map((a) => words[a] || a);
  const rest = (actions || []).some(([a]) => !d.auto.includes(a));
  if (!allowed.length) return "SentrAI does nothing on its own: every action waits for a person to approve it.";
  const v = (k) => (blank(d[k]) ? "?" : String(d[k]).trim());
  return `SentrAI acts on its own when it is at least ${v("CONFIDENCE_PCT")} % sure, the danger score is ` +
    `${v("RISK_THRESHOLD")} or more, and it has acted fewer than ${v("MAX_AUTO_ACTIONS_PER_HOUR")} times this hour. ` +
    `Then it may ${list(allowed)}${rest ? "; anything else asks a person first" : ""}. ` +
    `Each block undoes itself after ${v("HOTPATCH_TTL_HOURS")} h unless a person keeps it.`;
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
    map = new Guardrails(parentElement);
    maps.set(parentElement, map);
  }
  map.update(data || {}, setTriggerValue);
}

class Guardrails {
  constructor(host) {
    this.root = h("div", { class: "lm" });
    host.append(this.root);
    this.draft = null;
    this.version = null;
    this.pending = null;
    this.message = "";
    this.typing = {}; // half-typed tag text, kept across redraws
    this.tagError = {};
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

  number(key, label, opts = {}) {
    const id = `lm-${key}`;
    const input = h("input", { class: "lm-in", type: "number", inputmode: opts.inputmode || "decimal", id,
      value: this.draft[key], disabled: this.ro(), step: opts.step, min: opts.min, max: opts.max,
      "aria-describedby": opts.help ? `${id}-help` : null });
    input.addEventListener("change", () => this.change((d) => { d[key] = input.value; }));
    return h("div", { class: "lm-num" },
      h("label", { for: id, class: "lm-label" }, label),
      h("div", { class: "lm-in-wrap" }, input, opts.unit ? h("span", { class: "lm-affix", "aria-hidden": "true" }, opts.unit) : null),
      opts.help ? h("div", { class: "lm-help", id: `${id}-help` }, opts.help) : null);
  }

  /** A tag input: what you type turns into a checked tag on Enter, a comma or leaving the box. */
  tags(key, label, ok, why, placeholder) {
    const ro = this.ro();
    const tags = tagsOf(this.draft[key]);
    const id = `lm-${key}`;
    const input = h("input", { class: "lm-tag-in", id, type: "text", disabled: ro, value: this.typing[key] || "",
      placeholder: tags.length ? "Add another" : placeholder, autocomplete: "off", spellcheck: "false",
      "aria-describedby": `${id}-help`, "aria-invalid": this.tagError[key] ? "true" : "false" });
    const commit = () => {
      const typed = tagsOf(input.value);
      if (!typed.length) { this.typing[key] = ""; this.tagError[key] = ""; return; }
      const bad = typed.filter((x) => !ok(x));
      const good = typed.filter((x) => ok(x));
      this.typing[key] = bad.join(", ");
      this.tagError[key] = bad.length ? why(bad[0]) : "";
      if (good.length) this.change((d) => { d[key] = joinTags(tagsOf([d[key], ...good].join(","))); });
      else this.render();
    };
    input.addEventListener("input", () => {
      this.typing[key] = input.value;
      if (input.value.includes(",")) commit();
    });
    input.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") { ev.preventDefault(); commit(); }
      else if (ev.key === "Backspace" && !input.value && tags.length) {
        this.change((d) => { d[key] = joinTags(tags.slice(0, -1)); });
      }
    });
    input.addEventListener("blur", (ev) => {
      // Leaving for a button in this map (Save, ×) must not redraw it away before its click lands.
      if (input.value.trim() && !(ev.relatedTarget && this.root.contains(ev.relatedTarget))) commit();
    });
    const chips = tags.map((t) => h("span", { class: `lm-tag${ok(t) ? "" : " bad"}` }, t,
      ro ? null : h("button", { type: "button", class: "lm-tag-x", "aria-label": `Remove ${t}`,
        onclick: () => this.change((d) => { d[key] = joinTags(tagsOf(d[key]).filter((x) => x !== t)); }) }, icon("close"))));
    const box = h("div", { class: `lm-tags${ro ? " ro" : ""}` }, ...chips, input);
    box.addEventListener("click", (ev) => { if (ev.target === box) input.focus(); });
    return h("div", { class: "lm-tag-field" },
      h("label", { for: id, class: "lm-label" }, label), box,
      h("div", { class: `lm-help${this.tagError[key] ? " bad" : ""}`, id: `${id}-help`, role: this.tagError[key] ? "alert" : null },
        this.tagError[key] || (ro ? "" : "Press Enter or type a comma to add one; × removes it.")));
  }

  lane(toAuto) {
    const ro = this.ro();
    const actions = (this.data.actions || []).filter(([a]) => this.draft.auto.includes(a) === toAuto);
    const chips = actions.map(([a, words]) => h("button", {
      type: "button", class: `lm-chip${toAuto ? " auto" : ""}`, draggable: ro ? "false" : "true", disabled: ro,
      title: ro ? "" : toAuto ? "Drag to Asks a person first, or press to move it there" : "Drag to Done on its own, or press to move it there",
      "aria-label": `${words}: ${toAuto ? "done on its own" : "asks a person first"}. Press to move it.`,
      onclick: () => this.move(a, !toAuto),
      ondragstart: (ev) => { ev.dataTransfer.setData("text/plain", a); ev.dataTransfer.effectAllowed = "move"; },
    }, ro ? null : h("span", { class: "mi lm-grip", "aria-hidden": "true" }, "drag_indicator"),
      icon(toAuto ? "check" : "person"), words));
    const zone = h("div", { class: "lm-chips" }, chips.length ? chips : h("span", { class: "lm-empty" },
      toAuto ? "Nothing: every action asks a person first." : "Nothing: every action is done on its own."));
    zone.addEventListener("dragover", (ev) => { if (!ro) { ev.preventDefault(); zone.classList.add("over"); } });
    zone.addEventListener("dragleave", () => zone.classList.remove("over"));
    zone.addEventListener("drop", (ev) => {
      ev.preventDefault();
      zone.classList.remove("over");
      const a = ev.dataTransfer.getData("text/plain");
      if (a) this.move(a, toAuto);
    });
    return zone;
  }

  part(n, ico, title, sub, cls, ...body) {
    return h("section", { class: `lm-part ${cls}`, "aria-labelledby": `lm-part-${n}` },
      h("div", { class: "lm-head" }, h("span", { class: "lm-n", "aria-hidden": "true" }, String(n)), icon(ico),
        h("h3", { id: `lm-part-${n}` }, title), sub ? h("span", { class: "lm-sub" }, sub) : null),
      ...body);
  }

  render() {
    const d = this.draft;
    const actions = this.data.actions || [];
    const errs = problems(d);
    const dirty = this.dirty();
    const ro = this.ro();
    const pct = blank(d.CONFIDENCE_PCT) ? NaN : Number(d.CONFIDENCE_PCT);

    const when = this.part(1, "fact_check", "When it may act on its own", "all three must hold, or a person decides", "when",
      h("div", { class: "lm-nums" },
        this.number("CONFIDENCE_PCT", "It is at least this sure", { step: "5", min: 0, max: 100, unit: "%",
          help: Number.isFinite(pct) ? `Less than ${pct} % sure: asks a person` : "Less sure: asks a person" }),
        this.number("RISK_THRESHOLD", "The danger score is at least", { step: "1", min: 0, max: 100, inputmode: "numeric",
          unit: "of 100", help: "Lower: tells people, blocks nothing" }),
        this.number("MAX_AUTO_ACTIONS_PER_HOUR", "It has acted fewer times this hour than", { step: "1", min: 0,
          inputmode: "numeric", unit: "an hour", help: "Past it: every action asks a person" })));

    const own = this.part(2, "smart_toy", "Done on its own", "then it tells people", "own",
      this.lane(true),
      h("div", { class: "lm-nums two" },
        this.number("HOTPATCH_TTL_HOURS", "Each block undoes itself after", { step: "0.5", min: 0, unit: "hours",
          help: "unless a person keeps it" }),
        this.number("MAX_TTL_HOURS", "No block lasts longer than", { step: "1", min: 0, unit: "hours",
          help: "even one a person keeps" })));

    const ask = this.part(3, "person", "Asks a person first", "approve or reject, on Approvals", "ask", this.lane(false));

    const never = this.part(4, "lock", "Never touched, whatever happens", "checked before every action, on its own or approved", "never",
      h("div", { class: "lm-tag-grid" },
        this.tags("PROTECTED_IPS", "Addresses and networks", addressOk,
          (x) => `${x} is not an address, a network (10.0.0.0/8) or a host name.`, "e.g. 10.0.0.0/8 or 203.0.113.7"),
        this.tags("PROTECTED_USERS", "Accounts (admin and service accounts always are)", accountOk,
          (x) => `"${x}" has a space in it: one account per tag.`, "e.g. ceo or backup-svc")));

    const status = ro ? "Read only" : this.pending ? "Saving…" : dirty && errs.length ? "Fix the problems below to save" : dirty ? "Unsaved changes" : "All changes saved";
    const save = h("button", { type: "button", class: "lm-btn primary", disabled: ro || !dirty || !!this.pending || errs.length > 0,
      onclick: () => {
        this.pending = `save-${Date.now()}`;
        this.setTrigger && this.setTrigger("save", { id: this.pending, settings: toSettings(this.draft, actions) });
        this.render();
      } }, icon("save"), "Save changes");
    const discard = h("button", { type: "button", class: "lm-btn", disabled: ro || !dirty || !!this.pending,
      onclick: () => { this.draft = JSON.parse(JSON.stringify(this.base)); this.typing = {}; this.tagError = {}; this.message = ""; this.render(); } },
      icon("undo"), "Discard");
    const bar = h("div", { class: "lm-bar" }, h("span", { class: `lm-status${dirty && !ro ? " dirty" : ""}` }, status),
      h("span", { class: "lm-spacer" }), discard, save);

    const notes = [];
    if (ro) notes.push(h("div", { class: "lm-note" }, icon("lock"), this.data.lock_reason || "You can look, but not change anything here."));
    if (!ro && errs.length) notes.push(h("ul", { class: "lm-problems" }, errs.map((e) => h("li", {}, icon("error"), e))));
    if (this.message) notes.push(h("div", { class: `lm-note${this.bad ? " bad" : ""}`, role: this.bad ? "alert" : "status" },
      icon(this.bad ? "error" : "check_circle"), this.message));

    const policy = h("div", { class: "lm-summary" }, icon("policy"), h("p", {}, summary(d, actions)));

    // Redrawing replaces the inputs: keep the keyboard where it was (by the element's id or label), caret too.
    const shadow = this.root.getRootNode();
    const active = shadow && shadow.activeElement;
    const had = active ? active.id || active.getAttribute("aria-label") : null;
    const caret = active && active.type === "text" ? active.selectionStart : null;
    this.root.classList.toggle("ro", ro);
    this.root.replaceChildren(policy, bar, ...notes, when, h("div", { class: "lm-lanes" }, own, ask), never);
    if (had) {
      const again = [...this.root.querySelectorAll("[id], [aria-label]")]
        .find((el) => el.id === had || el.getAttribute("aria-label") === had);
      if (again) {
        again.focus();
        if (caret !== null && again.setSelectionRange) {
          const at = Math.min(caret, again.value.length);
          again.setSelectionRange(at, at);
        }
      }
    }
  }
}
