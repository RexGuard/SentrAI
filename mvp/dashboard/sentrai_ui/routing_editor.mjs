/* "Who gets what" editor (Incidents page): the routing rules as a map you change by dragging.

   A new incident takes the first rule that matches, checked from the top down. The rule's owner gets
   the incident and every reminder (solid line), the people it tells hear about it once (dashed), and
   when someone does not answer, their backup takes over (dotted). Drag a rule's "owner" or "tells"
   handle onto a person, a person's "backup" handle onto whoever takes over, or any handle onto empty
   space for a new person there. Click anything to change it in the panel beside the map; every change
   can also be made there with the keyboard.

   A Streamlit component (st.components.v2), so no iframe, no build step and nothing fetched from the
   internet. Everything edits a working copy: Save hands the whole routing file to Python, which posts it
   to the core (POST /routing), where it is checked again before it is written. Colours come from the
   console's CSS variables (theme.py), which reach into the component's shadow root.

   The model functions at the top touch no DOM; tests/routing_editor.test.mjs runs them in Node. */

export const MAX_TEXT = 120; // the core's limits (routing.py)
export const MAX_PEOPLE = 200;
export const MAX_RULES = 100;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

const str = (v) => (v === undefined || v === null ? "" : String(v));
const list = (v) => (Array.isArray(v) ? v : v === undefined || v === null || v === "" ? [] : [v])
  .map(str).filter((x) => x.trim());
const numberOr = (v, d) => (v === "" || v === null || v === undefined || !Number.isFinite(Number(v)) ? d : Number(v));
export const clone = (x) => JSON.parse(JSON.stringify(x));
export const pkey = (cid) => `p:${cid}`;
let newKeys = 0;
const newKey = () => `n${++newKeys}`;
/** After bringing back a working copy, new rules must not reuse its keys. */
export function reserveKeys(doc) {
  for (const r of doc.rules) {
    const m = /^n(\d+)$/.exec(r.key);
    if (m) newKeys = Math.max(newKeys, Number(m[1]));
  }
}

// ------------------------------------------------------------------ the model

const MATCH_ORDER = ["category", "severity", "host", "layer"];
const matchRank = (k) => (MATCH_ORDER.includes(k) ? MATCH_ORDER.indexOf(k) : MATCH_ORDER.length);

/** A rule's conditions without empty ones, always in the same key order (types, severity, machines, ...),
    so unticking and ticking a box again leaves the rule as it was. */
export function cleanMatch(match) {
  const out = {};
  const keys = Object.keys(match || {}).sort((a, b) => matchRank(a) - matchRank(b) || (a < b ? -1 : a > b ? 1 : 0));
  for (const k of keys) {
    const values = list(match[k]).map((x) => x.trim()).filter(Boolean);
    if (values.length) out[k] = values;
  }
  return out;
}

/** The same conditions, whatever order their values were ticked in. */
export const sameMatch = (a, b) => JSON.stringify(sortedMatch(a)) === JSON.stringify(sortedMatch(b));
const sortedMatch = (m) => Object.fromEntries(Object.entries(cleanMatch(m)).map(([k, v]) => [k, [...new Set(v)].sort()]));

/** What the saved file would say, with the order of conditions and of "tells" ignored (it changes nothing):
    the editor compares these to know whether anything is left to save. */
export function signature(doc, pos) {
  const r = toRouting(doc, pos);
  for (const x of r.rules) {
    x.match = sortedMatch(x.match);
    x.notify = [...x.notify].sort();
  }
  return JSON.stringify(r);
}

/** GET /routing (contacts as a list, as Python sends them) as the editor's working copy. Rules get a key
    (r0, r1, ...) so a rule keeps its place on the map while it is renamed or moved. */
export function fromRouting(routing) {
  const r = routing || {};
  const contacts = [];
  const seen = new Set();
  for (const c of r.contacts || []) {
    const id = str(c && c.id);
    if (!id || seen.has(id)) continue;
    seen.add(id);
    contacts.push({ id, name: str(c.name), role: str(c.role), email: str(c.email), telegram: str(c.telegram),
                    backup: str(c.backup) });
  }
  const rules = (r.rules || []).map((x, i) => ({ key: `r${i}`, name: str(x && x.name), match: cleanMatch(x && x.match),
                                                owner: str(x && x.owner), notify: list(x && x.notify) }));
  const f = r.follow_up || {};
  return { contacts, rules, follow_up: { escalate_after_reminders: numberOr(f.escalate_after_reminders, 2),
                                         max_escalations: numberOr(f.max_escalations, 3),
                                         resolve_within_hours: numberOr(f.resolve_within_hours, 24) } };
}

/** The working copy as the file POST /routing takes, with where everything sits on the map. */
export function toRouting(doc, pos) {
  const at = (p) => (p ? [Math.round(p.x), Math.round(p.y)] : null);
  const out = {
    contacts: doc.contacts.map((c) => ({ id: c.id, name: c.name.trim(), role: c.role, email: c.email.trim(),
                                         telegram: c.telegram.trim(), backup: c.backup })),
    rules: doc.rules.map((r) => ({ name: r.name.trim(), match: cleanMatch(r.match), owner: r.owner,
                                   notify: r.notify.filter((x) => x !== r.owner) })),
    follow_up: { ...doc.follow_up },
  };
  if (pos) {
    out.layout = { incident: at(pos.incident), rules: doc.rules.map((r) => at(pos[r.key])),
                   contacts: Object.fromEntries(doc.contacts.map((c) => [c.id, at(pos[pkey(c.id)])])) };
  }
  return out;
}

export const findPerson = (doc, cid) => doc.contacts.find((c) => c.id === cid);
export const nameOf = (doc, cid) => {
  const c = findPerson(doc, cid);
  return c ? c.name.trim() || "someone with no name" : "nobody";
};
export const ruleName = (doc, i) => (doc.rules[i] && doc.rules[i].name.trim()) || `rule ${i + 1}`;
export const isCatchAll = (rule) => !Object.keys(cleanMatch(rule.match)).length;

/** A rule's match in plain words: "Malware found or Log tampering · critical severity". With `short`, a long
    list of types reads "Malware found, Log tampering and 2 more", for the box on the map. */
export function ruleWhen(match, labels, short = false) {
  const parts = [];
  for (const [key, values] of Object.entries(cleanMatch(match))) {
    const names = key === "category" ? values.map((v) => (labels && labels.get(v)) || v.replace(/_/g, " ")) : values;
    if (key === "category" && short && names.length > 3) parts.push(`${names.slice(0, 2).join(", ")} and ${names.length - 2} more`);
    else if (key === "category") parts.push(names.join(" or "));
    else if (key === "severity") parts.push(`${values.join(" or ")} severity`);
    else if (key === "host") parts.push(`on ${values.join(" or ")}`);
    else parts.push(`${key} ${values.join(" or ")}`);
  }
  return parts.join(" · ");
}

/** A short id from the name (lee, lee-2, ...) that nobody has yet, nor any id in `reserved`. */
export function newContactId(doc, name, reserved = []) {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30) || "person";
  const ids = new Set([...doc.contacts.map((c) => c.id), ...reserved]);
  let id = base;
  for (let n = 2; ids.has(id); n += 1) id = `${base}-${n}`;
  return id;
}

function freeName(taken, base) {
  const low = new Set(taken.map((x) => x.trim().toLowerCase()));
  let name = base;
  for (let n = 2; low.has(name.toLowerCase()); n += 1) name = `${base} ${n}`;
  return name;
}

/** A new person called `name` (or "New person 2"...). `reserved`: ids not to reuse, such as those of people
    removed since the last save, whose Telegram chat link the core keeps under that id. */
export function addPerson(doc, name, reserved = []) {
  const fresh = freeName(doc.contacts.map((c) => c.name), name || "New person");
  const id = newContactId(doc, fresh, reserved);
  doc.contacts.push({ id, name: fresh, role: "", email: "", telegram: "", backup: "" });
  return id;
}

/** Take someone out. Whoever they backed up gets their backup instead, they drop off every "tells" list,
    and rules they owned wait for a new owner (Save stays off until they have one). */
export function removePerson(doc, cid) {
  const gone = findPerson(doc, cid);
  if (!gone) return { error: "That person is not in the routing any more.", notes: [] };
  if (doc.contacts.length === 1) return { error: "Keep at least one person: incidents need someone to go to.", notes: [] };
  doc.contacts = doc.contacts.filter((c) => c.id !== cid);
  const notes = [];
  const next = findPerson(doc, gone.backup) ? gone.backup : "";
  for (const c of doc.contacts) {
    if (c.backup !== cid) continue;
    c.backup = next !== c.id ? next : "";
    notes.push(`${nameOf(doc, c.id)}'s backup is now ${c.backup ? nameOf(doc, c.backup) : "nobody"}`);
  }
  doc.rules.forEach((r, i) => {
    if (r.notify.includes(cid)) {
      r.notify = r.notify.filter((x) => x !== cid);
      notes.push(`${ruleName(doc, i)} no longer tells ${gone.name.trim()}`);
    }
    if (r.owner === cid) {
      r.owner = "";
      notes.push(`${ruleName(doc, i)} needs a new owner`);
    }
  });
  return { error: "", notes };
}

/** A new rule at position `at` with no conditions yet (so it catches everything until it gets some). */
export function addRule(doc, at, owner) {
  const rule = { key: newKey(), name: freeName(doc.rules.map((r) => r.name), "New rule"), match: {},
                 owner: findPerson(doc, owner) ? owner : (doc.contacts[0] || {}).id || "", notify: [] };
  doc.rules.splice(Math.max(0, Math.min(at, doc.rules.length)), 0, rule);
  return rule;
}

/** Where a new rule goes: just above a final catch-all, so that one keeps catching the rest. */
export const newRuleIndex = (doc) => (doc.rules.length && isCatchAll(doc.rules[doc.rules.length - 1])
  ? doc.rules.length - 1 : doc.rules.length);

/** Draw a line: kind "owner" or "tell" from rule index `from`, or "backup" from contact `from`, to person `to`.
    Returns what changed in words, or "" when nothing did. */
export function connect(doc, kind, from, to) {
  if (!findPerson(doc, to)) return "";
  if (kind === "backup") {
    const c = findPerson(doc, from);
    if (!c || from === to || c.backup === to) return "";
    c.backup = to;
    return `${nameOf(doc, to)} now backs up ${nameOf(doc, from)}.`;
  }
  const r = doc.rules[from];
  if (!r) return "";
  if (kind === "owner") {
    if (r.owner === to) return "";
    r.owner = to;
    r.notify = r.notify.filter((x) => x !== to);
    return `${nameOf(doc, to)} now owns ${ruleName(doc, from)}.`;
  }
  if (r.owner === to || r.notify.includes(to)) return "";
  r.notify.push(to);
  return `${ruleName(doc, from)} now also tells ${nameOf(doc, to)}.`;
}

export function disconnect(doc, kind, from, to) {
  if (kind === "backup") {
    const c = findPerson(doc, from);
    if (!c || !c.backup) return "";
    c.backup = "";
    return `${nameOf(doc, from)} has no backup now.`;
  }
  const r = doc.rules[from];
  if (!r) return "";
  if (kind === "owner") {
    if (r.owner !== to) return "";
    r.owner = "";
    return `${ruleName(doc, from)} has no owner now. Connect someone before saving.`;
  }
  if (!r.notify.includes(to)) return "";
  r.notify = r.notify.filter((x) => x !== to);
  return `${ruleName(doc, from)} no longer tells ${nameOf(doc, to)}.`;
}

/** Give a person a settings role; whoever had it before loses it (one person per role, as in the settings). */
export function setRole(doc, cid, role) {
  for (const c of doc.contacts) if (role && c.id !== cid && c.role === role) c.role = "";
  const c = findPerson(doc, cid);
  if (c) c.role = role;
}

/** Everything that would stop the core from taking this file ("error"), and things worth a second look
    ("warning"). Each names the rule or person it is about, so the map can point at it. */
export function problems(doc) {
  const out = [];
  const add = (level, text, kind = "", key = "") => out.push({ level, text, kind, key });
  const ids = new Set(doc.contacts.map((c) => c.id));
  if (!doc.contacts.length) add("error", "Add at least one person.");
  if (doc.contacts.length > MAX_PEOPLE) add("error", `At most ${MAX_PEOPLE} people.`);
  if (doc.rules.length > MAX_RULES) add("error", `At most ${MAX_RULES} rules.`);
  const names = new Map();
  for (const c of doc.contacts) {
    const name = c.name.trim();
    const who = name || "Someone";
    const at = pkey(c.id);
    if (!name) add("error", "A person has no name.", "person", at);
    else if (names.has(name.toLowerCase())) add("error", `Two people are called ${name}. Give each a different name.`, "person", at);
    names.set(name.toLowerCase(), c.id);
    for (const [field, label] of [["name", "name"], ["email", "email"], ["telegram", "Telegram"], ["role", "role"]]) {
      if (c[field].trim().length > MAX_TEXT) add("error", `${who}'s ${label} is longer than ${MAX_TEXT} characters.`, "person", at);
    }
    if (c.email.trim() && !EMAIL.test(c.email.trim())) add("error", `${who}'s email doesn't look like an email address.`, "person", at);
    if (c.backup && c.backup === c.id) add("error", `${who} can't be their own backup.`, "person", at);
    else if (c.backup && !ids.has(c.backup)) add("error", `${who}'s backup is not one of the people any more.`, "person", at);
  }
  doc.rules.forEach((r, i) => {
    const label = `Rule ${i + 1}${r.name.trim() ? ` (${r.name.trim()})` : ""}`;
    if (!r.name.trim()) add("error", `Rule ${i + 1} has no name.`, "rule", r.key);
    if (r.name.trim().length > MAX_TEXT) add("error", `${label}: the name is longer than ${MAX_TEXT} characters.`, "rule", r.key);
    if (!ids.has(r.owner)) add("error", `${label} has no owner. Drag its owner handle onto a person.`, "rule", r.key);
    for (const v of (r.match.host || [])) {
      if (v.length > MAX_TEXT) add("error", `${label}: a machine name is longer than ${MAX_TEXT} characters.`, "rule", r.key);
    }
  });
  const fu = doc.follow_up;
  const whole = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  if (!whole(fu.escalate_after_reminders, 1, 20)) add("error", "Follow-up: reminders before the backup takes over must be a whole number from 1 to 20.", "follow", "");
  if (!whole(fu.max_escalations, 0, 20)) add("error", "Follow-up: hand-overs must be a whole number from 0 to 20.", "follow", "");
  if (!(Number.isFinite(fu.resolve_within_hours) && fu.resolve_within_hours >= 0 && fu.resolve_within_hours <= 720)) {
    add("error", "Follow-up: hours must be a number from 0 to 720.", "follow", "");
  }
  const first = doc.rules.findIndex(isCatchAll);
  if (first >= 0 && first < doc.rules.length - 1) {
    const below = doc.rules.length - 1 - first;
    add("warning", `${below === 1 ? "The rule" : `The ${below} rules`} below ${ruleName(doc, first)} never run${below === 1 ? "s" : ""}: `
        + "it has no conditions, so it catches every incident first. Give it some, or drag it to the bottom.", "rule", doc.rules[first].key);
  }
  if (doc.contacts.length && (!doc.rules.length || !isCatchAll(doc.rules[doc.rules.length - 1]))) {
    add("warning", `Incidents that no rule matches go to ${nameOf(doc, doc.contacts[0].id)} (the first person). `
        + "To choose someone else, end with a rule that has no conditions.", "", "");
  }
  for (const loop of backupLoops(doc)) {
    const who = loop.map((cid) => nameOf(doc, cid));
    const text = who.length === 2 ? `${who[0]} and ${who[1]} back each other up` : `${who.slice(0, -1).join(", ")} and ${who.at(-1)} back each other up in a circle`;
    add("warning", `${text}: an incident nobody answers goes round them until the hand-over limit.`, "person", pkey(loop[0]));
  }
  return out;
}

/** Circles of backups (Lee -> Ika -> Lee), each once. */
export function backupLoops(doc) {
  const backup = new Map(doc.contacts.map((c) => [c.id, c.backup]));
  const loops = [];
  const done = new Set();
  for (const c of doc.contacts) {
    const path = [];
    let cur = c.id;
    while (cur && backup.has(cur) && !path.includes(cur) && !done.has(cur)) {
      path.push(cur);
      cur = backup.get(cur);
    }
    if (cur && path.includes(cur) && path.length - path.indexOf(cur) > 1) loops.push(path.slice(path.indexOf(cur)));
    path.forEach((x) => done.add(x));
  }
  return loops;
}

/** People top to bottom: each rule's owner followed by their chain of backups, then the rest. */
export function peopleOrder(doc) {
  const byId = new Map(doc.contacts.map((c) => [c.id, c]));
  const seen = new Set();
  const out = [];
  const visit = (cid) => {
    while (cid && byId.has(cid) && !seen.has(cid)) {
      seen.add(cid);
      out.push(cid);
      cid = byId.get(cid).backup;
    }
  };
  doc.rules.forEach((r) => visit(r.owner));
  doc.rules.forEach((r) => r.notify.forEach(visit));
  doc.contacts.forEach((c) => visit(c.id));
  return out;
}

const GRID = { gapY: 20, peopleGapY: 26, incidentGap: 64, peopleGap: 132 };

/** A tidy map: the incident on the left, the rules in their order, then the people in one column, both
    columns centred on each other. `size(key)` gives a drawn node's {w, h}. */
export function layoutAll(doc, size) {
  const pos = {};
  const inc = size("incident");
  const rulesX = inc.w + GRID.incidentGap;
  const ruleW = Math.max(0, ...doc.rules.map((r) => size(r.key).w));
  const order = peopleOrder(doc);
  const rulesH = doc.rules.reduce((t, r) => t + size(r.key).h, 0) + GRID.gapY * Math.max(0, doc.rules.length - 1);
  const peopleH = order.reduce((t, cid) => t + size(pkey(cid)).h, 0) + GRID.peopleGapY * Math.max(0, order.length - 1);
  const tall = Math.max(rulesH, peopleH, inc.h);
  let y = (tall - rulesH) / 2;
  for (const r of doc.rules) {
    pos[r.key] = { x: rulesX, y };
    y += size(r.key).h + GRID.gapY;
  }
  y = (tall - peopleH) / 2;
  const peopleX = rulesX + (ruleW || 220) + GRID.peopleGap;
  for (const cid of order) {
    pos[pkey(cid)] = { x: peopleX, y };
    y += size(pkey(cid)).h + GRID.peopleGapY;
  }
  pos.incident = { x: 0, y: (tall - inc.h) / 2 };
  return pos;
}

/** Positions for nodes that have none yet (new, or added to the file by hand): rules below the lowest
    rule, people below the lowest person. */
export function placeMissing(doc, pos, size) {
  const column = (keys, fallbackX) => {
    const placed = keys.filter((k) => pos[k]);
    const bottom = Math.max(-Infinity, ...placed.map((k) => pos[k].y + size(k).h));
    const x = placed.length ? pos[placed[placed.length - 1]].x : fallbackX;
    let y = Number.isFinite(bottom) ? bottom + GRID.gapY : 0;
    for (const k of keys) {
      if (pos[k]) continue;
      pos[k] = { x, y };
      y += size(k).h + GRID.gapY;
    }
  };
  const ruleKeys = doc.rules.map((r) => r.key);
  const firstRule = ruleKeys.find((k) => pos[k]);
  const rulesX = firstRule ? pos[firstRule].x : size("incident").w + GRID.incidentGap;
  column(ruleKeys, rulesX);
  const ruleW = Math.max(220, ...ruleKeys.map((k) => size(k).w));
  column(peopleOrder(doc).map(pkey), rulesX + ruleW + GRID.peopleGap);
  if (!pos.incident) {
    const ys = ruleKeys.map((k) => pos[k].y + size(k).h / 2);
    const mid = ys.length ? (Math.min(...ys) + Math.max(...ys)) / 2 : 0;
    pos.incident = { x: rulesX - GRID.incidentGap - size("incident").w, y: mid - size("incident").h / 2 };
  }
  return pos;
}

const centre = (pos, size, key) => pos[key].y + size(key).h / 2;

/** True when the rules' order on the map (top to bottom) is their order in the file. */
export function rulesFollowY(doc, pos, size) {
  for (let i = 1; i < doc.rules.length; i += 1) {
    if (centre(pos, size, doc.rules[i].key) < centre(pos, size, doc.rules[i - 1].key)) return false;
  }
  return true;
}

/** Put the rules in the order they sit on the map, top to bottom. True when that changed the order. */
export function sortRulesByY(doc, pos, size) {
  const ranked = doc.rules.map((r, i) => ({ r, i, c: pos[r.key] ? centre(pos, size, r.key) : Infinity }));
  ranked.sort((a, b) => a.c - b.c || a.i - b.i);
  const changed = ranked.some((x, j) => x.i !== j);
  if (changed) doc.rules = ranked.map((x) => x.r);
  return changed;
}

/** Stack the rules in their file order from the top one down, each keeping its own left edge. */
export function restackRules(doc, pos, size) {
  if (!doc.rules.length) return;
  let y = Math.min(...doc.rules.map((r) => (pos[r.key] ? pos[r.key].y : Infinity)));
  if (!Number.isFinite(y)) y = 0;
  const x0 = (doc.rules.map((r) => pos[r.key]).find(Boolean) || { x: 0 }).x;
  for (const r of doc.rules) {
    pos[r.key] = { x: pos[r.key] ? pos[r.key].x : x0, y };
    y += size(r.key).h + GRID.gapY;
  }
}

export const CONTACT_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/; // the core's (routing.py)

/** People added since the last save take their id from the name they ended up with (lee-tan, not the
    new-person they started as), never the id of someone saved before (even if removed now: the core keeps
    their Telegram chat link under it). A saved id the core would refuse (a hand-edited file) is replaced
    the same way. Returns copies, plus which ids changed. */
export function settleIds(base, doc, pos) {
  const saved = new Set(base.contacts.map((c) => c.id));
  const keeps = (c) => saved.has(c.id) && CONTACT_ID.test(c.id);
  const taken = { contacts: [...saved].map((id) => ({ id })) };
  const renamed = new Map();
  for (const c of doc.contacts) {
    if (keeps(c)) continue;
    const id = newContactId(taken, c.name.trim() || "person");
    taken.contacts.push({ id });
    if (id !== c.id) renamed.set(c.id, id);
  }
  const out = clone(doc);
  const at = {};
  const re = (cid) => renamed.get(cid) || cid;
  for (const [k, v] of Object.entries(pos || {})) at[k.startsWith("p:") ? pkey(re(k.slice(2))) : k] = v;
  for (const c of out.contacts) {
    c.id = re(c.id);
    c.backup = c.backup ? re(c.backup) : "";
  }
  for (const r of out.rules) {
    r.owner = re(r.owner);
    r.notify = r.notify.map(re);
  }
  return { doc: out, pos: at, renamed };
}

/** What changed between the saved copy and the working one, in words, for the toast and the audit log. */
export function summarize(base, doc, labels) {
  const out = [];
  const bp = new Map(base.contacts.map((c) => [c.id, c]));
  const dp = new Set(doc.contacts.map((c) => c.id));
  for (const c of doc.contacts) if (!bp.has(c.id)) out.push(`added ${c.name.trim() || "a person"}`);
  for (const c of base.contacts) if (!dp.has(c.id)) out.push(`removed ${c.name.trim()}`);
  for (const c of doc.contacts) {
    const b = bp.get(c.id);
    if (!b) continue;
    const name = c.name.trim();
    if (b.name.trim() !== name) out.push(`renamed ${b.name.trim()} to ${name}`);
    if (b.backup !== c.backup) out.push(c.backup ? `${name}'s backup is ${nameOf(doc, c.backup)}` : `${name} has no backup`);
    if (b.role !== c.role || b.email.trim() !== c.email.trim() || b.telegram.trim() !== c.telegram.trim()) out.push(`updated ${name}'s details`);
  }
  const br = new Map(base.rules.map((r) => [r.key, r]));
  const dr = new Set(doc.rules.map((r) => r.key));
  for (const r of doc.rules) if (!br.has(r.key)) out.push(`added rule ${r.name.trim()}`);
  for (const r of base.rules) if (!dr.has(r.key)) out.push(`deleted rule ${r.name.trim()}`);
  for (const r of doc.rules) {
    const b = br.get(r.key);
    if (!b) continue;
    const name = r.name.trim();
    if (b.name.trim() !== name) out.push(`renamed rule ${b.name.trim()} to ${name}`);
    if (b.owner !== r.owner) out.push(`${name} goes to ${nameOf(doc, r.owner)}`);
    const added = r.notify.filter((x) => !b.notify.includes(x)).map((x) => nameOf(doc, x));
    const dropped = b.notify.filter((x) => !r.notify.includes(x)).map((x) => nameOf(base, x));
    if (added.length) out.push(`${name} now also tells ${added.join(", ")}`);
    if (dropped.length) out.push(`${name} no longer tells ${dropped.join(", ")}`);
    if (!sameMatch(b.match, r.match)) {
      out.push(`${name} now catches ${ruleWhen(r.match, labels) || "everything"}`);
    }
  }
  const kept = doc.rules.filter((r) => br.has(r.key)).map((r) => r.key).join();
  const was = base.rules.filter((r) => dr.has(r.key)).map((r) => r.key).join();
  if (kept !== was) out.push("changed the rule order");
  if (JSON.stringify(base.follow_up) !== JSON.stringify(doc.follow_up)) out.push("changed the follow-up");
  return out;
}

export function summaryText(changes) {
  if (!changes.length) return "Moved things around on the map";
  const shown = changes.slice(0, 3).join("; ");
  const more = changes.length - 3;
  const text = more > 0 ? `${shown}; and ${more} more change${more === 1 ? "" : "s"}` : shown;
  return text.charAt(0).toUpperCase() + text.slice(1);
}

// ------------------------------------------------------------------ the editor (DOM)

const SVG = "http://www.w3.org/2000/svg";
const DRAFT = "sentrai-routing-draft"; // unsaved changes survive a page switch or a reload (this tab only)
const ZOOM = { min: 0.35, max: 1.75 };
const editors = new WeakMap();

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v === null || v === undefined) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid !== null && kid !== undefined && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function s(tag, attrs) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}

const icon = (name) => h("span", { class: "mi", "aria-hidden": "true" }, name);
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
const isTyping = (el) => !!el && (el.tagName === "TEXTAREA" || el.tagName === "SELECT"
  || (el.tagName === "INPUT" && !["checkbox", "radio", "button"].includes(el.type)));

/** A horizontal S-curve from a to b. */
function curve(a, b) {
  const dx = Math.max(36, Math.abs(b.x - a.x) / 2);
  return [a, { x: a.x + dx, y: a.y }, { x: b.x - dx, y: b.y }, b];
}

/** Out of a's right side and back into b's right side, for a backup that sits above, below or left of its person. */
function loop(a, b) {
  const out = Math.max(a.x, b.x) + 34 + Math.min(150, Math.abs(b.y - a.y) * 0.3);
  return [a, { x: out, y: a.y }, { x: out, y: b.y }, b];
}

const pathOf = (p) => `M${p[0].x},${p[0].y} C${p[1].x},${p[1].y} ${p[2].x},${p[2].y} ${p[3].x},${p[3].y}`;
const middle = (p) => ({ x: (p[0].x + 3 * p[1].x + 3 * p[2].x + p[3].x) / 8, y: (p[0].y + 3 * p[1].y + 3 * p[2].y + p[3].y) / 8 });

function arrow(p) {
  const end = p[3];
  const dir = end.x >= p[2].x ? 1 : -1;
  return `M${end.x},${end.y} L${end.x - 8 * dir},${end.y - 4.5} L${end.x - 8 * dir},${end.y + 4.5} Z`;
}

export default function mount(component) {
  const { parentElement, data, setTriggerValue } = component;
  let editor = editors.get(parentElement);
  if (!editor) {
    editor = new Editor(parentElement);
    editors.set(parentElement, editor);
  }
  editor.update(data || {}, setTriggerValue);
}

class Editor {
  constructor(host) {
    this.host = host;
    this.data = {};
    this.doc = null;
    this.base = null;
    this.baseVersion = null;
    this.baseSig = "";
    this.pos = {};
    this.view = { x: 0, y: 0, k: 1 };
    this.sel = null; // {kind: "rule" | "person" | "incident", key} or {kind: "edge", id}
    this.hover = null;
    this.undo = [];
    this.redo = [];
    this.typing = null; // the panel field being typed into: one undo step per field, not per key
    this.nudging = null;
    this.drag = null;
    this.pending = null; // the save waiting for Python's answer
    this.incoming = null; // someone else's newer version, while this one has unsaved changes
    this.queued = null;
    this.error = "";
    this.nodeEls = new Map();
    this.labels = new Map();
    this.build();
  }

  // ---------------------------------------------------------------- skeleton

  build() {
    const tool = (act, label, ico, opts = {}) => h("button", {
      type: "button", class: `re-btn${opts.cls ? ` ${opts.cls}` : ""}${opts.iconOnly ? " icon" : ""}`, "data-act": act,
      "aria-label": opts.iconOnly ? label : null, title: opts.title || (opts.iconOnly ? label : null),
    }, ico ? icon(ico) : null, opts.iconOnly ? null : h("span", {}, label));
    this.btn = {
      addRule: tool("add-rule", "Rule", "add", { title: "Add a rule" }),
      addPerson: tool("add-person", "Person", "person_add", { title: "Add a person" }),
      undo: tool("undo", "Undo", "undo", { iconOnly: true, title: "Undo (Ctrl+Z)" }),
      redo: tool("redo", "Redo", "redo", { iconOnly: true, title: "Redo (Ctrl+Shift+Z)" }),
      tidy: tool("tidy", "Tidy up", "account_tree", { title: "Line everything up again" }),
      zoomOut: tool("zoom-out", "Zoom out", "remove", { iconOnly: true }),
      zoomIn: tool("zoom-in", "Zoom in", "add", { iconOnly: true }),
      fit: tool("fit", "Fit the map in view", "fit_screen", { iconOnly: true }),
      discard: tool("discard", "Discard", null, { title: "Go back to the saved version (Ctrl+Z brings your changes back)" }),
      save: tool("save", "Save changes", "save", { cls: "primary", title: "Save (Ctrl+S)" }),
    };
    this.zoomLabel = h("span", { class: "re-zoom", "aria-hidden": "true" }, "100%");
    this.statusEl = h("span", { class: "re-status", role: "status" });
    const bar = h("div", { class: "re-bar", role: "group", "aria-label": "Map tools" },
      h("div", { class: "re-group edit" }, this.btn.addRule, this.btn.addPerson),
      h("div", { class: "re-group edit" }, this.btn.undo, this.btn.redo),
      h("div", { class: "re-group" }, this.btn.tidy, this.btn.zoomOut, this.zoomLabel, this.btn.zoomIn, this.btn.fit),
      h("div", { class: "re-spacer" }),
      this.statusEl,
      h("div", { class: "re-group edit" }, this.btn.discard, this.btn.save));
    bar.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-act]");
      if (b && !b.disabled) this.act(b.dataset.act);
    });

    this.notice = h("div", { class: "re-notice", hidden: true });
    this.edges = s("svg", { class: "re-edges", "aria-hidden": "true", width: 1, height: 1 });
    this.ghost = s("svg", { class: "re-edges re-ghost", "aria-hidden": "true", width: 1, height: 1 });
    this.nodesEl = h("div", { class: "re-nodes" });
    this.edgeX = h("button", { type: "button", class: "re-edge-x", hidden: true }, icon("close"), h("span", {}, "Remove"));
    this.edgeX.addEventListener("click", () => this.removeSelectedEdge());
    this.world = h("div", { class: "re-world" }, this.edges, this.nodesEl, this.ghost, this.edgeX);
    this.viewport = h("div", { class: "re-viewport" }, this.world);
    this.legend = h("div", { class: "re-legend" },
      h("span", { class: "re-key" }, h("i", { class: "k-owner" }), "owns it: gets it and every reminder"),
      h("span", { class: "re-key" }, h("i", { class: "k-tell" }), "also told, once"),
      h("span", { class: "re-key" }, h("i", { class: "k-backup" }), "backup: takes over when nobody answers"),
      h("span", { class: "re-hint" }, "Rules are checked from the top; the first that matches owns the incident. "
        + "Drag the background to move around, Ctrl + scroll to zoom."));
    this.panel = h("section", { class: "re-panel", "aria-label": "Details" });
    this.problemsEl = h("div", { class: "re-problems", hidden: true });
    this.live = h("div", { class: "re-sr", "aria-live": "polite" });
    this.root = h("div", { class: "re" }, bar, this.notice,
      h("div", { class: "re-body" }, h("div", { class: "re-canvas" }, this.viewport, this.legend), this.panel),
      this.problemsEl, this.live);
    this.host.appendChild(this.root);

    const vp = this.viewport;
    vp.addEventListener("pointerdown", (e) => this.down(e));
    vp.addEventListener("pointermove", (e) => this.move(e));
    vp.addEventListener("pointerup", (e) => this.up(e));
    vp.addEventListener("pointercancel", (e) => this.up(e, true));
    vp.addEventListener("wheel", (e) => this.wheel(e), { passive: false });
    vp.addEventListener("pointerover", (e) => this.hoverAt(e));
    vp.addEventListener("pointerleave", () => this.setHover(null));
    this.nodesEl.addEventListener("keydown", (e) => this.nodeKey(e));
    this.root.addEventListener("keydown", (e) => this.key(e));
    this.panel.addEventListener("focusout", () => { this.typing = null; });
    if (typeof ResizeObserver !== "undefined") {
      // A node that grows (a longer name) moves its handles; a canvas that was hidden gets its first fit.
      this.resizer = new ResizeObserver(() => {
        this.drawEdges();
        if (this.needsFit && this.viewport.clientWidth) this.fit();
      });
      this.resizer.observe(this.viewport);
    }
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => this.doc && this.drawEdges());
  }

  // ---------------------------------------------------------------- data from Python

  update(data, setTrigger) {
    if (setTrigger) this.setTrigger = setTrigger;
    this.data = data;
    this.readOnly = !!data.read_only;
    this.labels = new Map(data.categories || []);
    this.root.classList.toggle("ro", this.readOnly);
    const result = data.result;
    if (this.pending && result && result.id === this.pending.id) {
      clearTimeout(this.pending.timer);
      const { renamed } = this.pending;
      this.pending = null;
      if (result.ok) {
        const was = this.sel && this.sel.kind === "person" ? this.sel.key.slice(2) : null;
        if (was && renamed.has(was)) this.sel = { kind: "person", key: pkey(renamed.get(was)) };
        this.adopt(data, true);
        this.say(result.message || "Saved.");
      } else {
        this.error = result.message || "The change was not saved.";
        this.render();
      }
      return;
    }
    if (!this.doc) {
      this.adopt(data, false);
      return;
    }
    if (data.version !== this.baseVersion) {
      if (this.drag) this.queued = data;
      else if (!this.dirty()) this.adopt(data, true);
      else {
        this.incoming = data;
        this.render();
      }
      return;
    }
    this.render(); // same routing: the lock, the labels or a Telegram link changed
  }

  /** Take the saved routing from Python as the new starting point. */
  adopt(data, keepView) {
    const wasInView = keepView && !!this.doc && this.inView();
    const keepPerson = this.sel && this.sel.kind === "person" ? this.sel.key : null;
    const keepRule = this.sel && this.sel.kind === "rule" ? this.doc.rules.findIndex((r) => r.key === this.sel.key) : -1;
    this.doc = fromRouting(data.routing);
    this.base = clone(this.doc);
    this.baseVersion = data.version;
    this.incoming = null;
    this.queued = null;
    this.error = "";
    this.undo = [];
    this.redo = [];
    this.typing = null;
    this.sel = keepPerson && findPerson(this.doc, keepPerson.slice(2)) ? { kind: "person", key: keepPerson }
      : keepRule >= 0 && this.doc.rules[keepRule] ? { kind: "rule", key: this.doc.rules[keepRule].key } : null;
    this.renderNodes();
    this.pos = this.positionsFrom((data.routing || {}).layout);
    this.basePos = clone(this.pos);
    this.baseSig = this.sig();
    if (!keepView) this.restoreDraft();
    this.sizeCanvas();
    this.render();
    // A saved map can gain a box (the core adds "Everything else" when the last rule has conditions).
    if (!keepView || wasInView) requestAnimationFrame(() => { if (!keepView || !this.inView()) this.fit(); });
  }

  positionsFrom(layout) {
    const size = (k) => this.size(k);
    const L = layout && typeof layout === "object" ? layout : {};
    const pt = (a) => (Array.isArray(a) && a.length === 2 && a.every((n) => Number.isFinite(n)) ? { x: a[0], y: a[1] } : null);
    const pos = {};
    if (pt(L.incident)) pos.incident = pt(L.incident);
    (Array.isArray(L.rules) ? L.rules : []).forEach((a, i) => {
      if (this.doc.rules[i] && pt(a)) pos[this.doc.rules[i].key] = pt(a);
    });
    for (const [cid, a] of Object.entries(L.contacts && typeof L.contacts === "object" ? L.contacts : {})) {
      if (findPerson(this.doc, cid) && pt(a)) pos[pkey(cid)] = pt(a);
    }
    if (!Object.keys(pos).length) return layoutAll(this.doc, size);
    placeMissing(this.doc, pos, size);
    if (!rulesFollowY(this.doc, pos, size)) restackRules(this.doc, pos, size);
    return pos;
  }

  sig() {
    return signature(this.doc, this.pos);
  }

  /** Unsaved changes from before a page switch or reload, made on top of this same saved version. */
  restoreDraft() {
    let draft = null;
    try {
      draft = JSON.parse(window.sessionStorage.getItem(DRAFT) || "null");
    } catch (e) {
      draft = null;
    }
    if (!draft || draft.version !== this.baseVersion || !draft.doc || !draft.pos || this.readOnly) return;
    this.push(this.snapshot());
    this.doc = draft.doc;
    this.pos = draft.pos;
    reserveKeys(this.doc);
    this.renderNodes();
    if (!this.dirty()) {
      this.undo = [];
      return;
    }
    this.restored = true;
  }

  keepDraft() {
    clearTimeout(this.draftTimer);
    this.draftTimer = setTimeout(() => {
      try {
        if (this.dirty() && !this.readOnly) {
          window.sessionStorage.setItem(DRAFT, JSON.stringify({ version: this.baseVersion, doc: this.doc, pos: this.pos }));
        } else window.sessionStorage.removeItem(DRAFT);
      } catch (e) {
        // private windows and full storage: the draft is a convenience only
      }
    }, 300);
  }

  dirty() {
    return !!this.doc && this.sig() !== this.baseSig;
  }

  size(key) {
    const el = this.nodeEls.get(key);
    return el && el.offsetWidth ? { w: el.offsetWidth, h: el.offsetHeight } : { w: key === "incident" ? 130 : 220, h: 64 };
  }

  // ---------------------------------------------------------------- changes and history

  snapshot() {
    return { doc: clone(this.doc), pos: clone(this.pos), sel: this.sel && { ...this.sel } };
  }

  restore(snap) {
    this.doc = snap.doc;
    this.pos = snap.pos;
    this.sel = snap.sel;
    this.typing = null;
    this.nudging = null;
    this.render();
  }

  /** Run one change as one undo step. `fn` returns words for screen readers, or false when nothing changed. */
  change(fn) {
    const snap = this.snapshot();
    const said = fn();
    if (said === false || this.sig() === signature(snap.doc, snap.pos)) {
      this.render();
      return false;
    }
    this.push(snap);
    this.typing = null;
    this.nudging = null;
    this.render();
    if (typeof said === "string" && said) this.say(said);
    return true;
  }

  push(snap) {
    this.undo.push(snap);
    if (this.undo.length > 200) this.undo.shift();
    this.redo = [];
    this.error = "";
  }

  /** A change typed in the panel: the first keystroke in a field opens an undo step, later ones join it. */
  edit(field, fn) {
    if (this.typing !== field) {
      this.push(this.snapshot());
      this.typing = field;
    }
    fn();
    this.render({ panel: false });
  }

  undoLast() {
    if (!this.undo.length) return;
    this.redo.push(this.snapshot());
    this.restore(this.undo.pop());
    this.say("Undone.");
  }

  redoLast() {
    if (!this.redo.length) return;
    this.undo.push(this.snapshot());
    this.restore(this.redo.pop());
    this.say("Redone.");
  }

  // ---------------------------------------------------------------- toolbar

  act(what) {
    const d = this.doc;
    if (what === "zoom-in") return this.zoomBy(1.2);
    if (what === "zoom-out") return this.zoomBy(1 / 1.2);
    if (what === "fit") return this.fit();
    if (what === "undo") return this.undoLast();
    if (what === "redo") return this.redoLast();
    if (what === "save") return this.save();
    if (this.readOnly) return undefined;
    if (what === "tidy") {
      this.change(() => {
        this.pos = layoutAll(d, (k) => this.size(k));
        return "Lined everything up.";
      });
      this.sizeCanvas();
      return requestAnimationFrame(() => this.fit());
    }
    if (what === "discard") {
      if (!this.dirty()) return undefined;
      this.push(this.snapshot());
      this.restore({ doc: clone(this.base), pos: clone(this.basePos), sel: null });
      this.incoming = null;
      return this.say("Back to the saved version. Undo brings your changes back.");
    }
    if (what === "add-rule") {
      if (!d.contacts.length) return this.say("Add a person first: every rule needs an owner.");
      let rule;
      const at = newRuleIndex(d);
      const below = d.rules[at] || null;
      this.change(() => {
        rule = addRule(d, at, below ? below.owner : d.contacts[0].id);
        this.renderNodes();
        const sz = this.size(rule.key);
        if (below && this.pos[below.key]) {
          // Take the catch-all's place and push it (and anything under it) down.
          const top = this.pos[below.key].y;
          this.pos[rule.key] = { x: this.pos[below.key].x, y: top };
          for (const r of d.rules.slice(at + 1)) if (this.pos[r.key]) this.pos[r.key].y += sz.h + GRID.gapY;
        } else placeMissing(d, this.pos, (k) => this.size(k));
        this.sel = { kind: "rule", key: rule.key };
        return `Added ${rule.name} as rule ${at + 1}. Give it a name and conditions in the panel.`;
      });
      this.sizeCanvas(true);
      this.reveal(rule.key);
      return this.focusField("re-f-name", true);
    }
    if (what === "add-person") {
      let cid;
      this.change(() => {
        cid = addPerson(d, "New person", this.base.contacts.map((c) => c.id));
        this.renderNodes();
        placeMissing(d, this.pos, (k) => this.size(k));
        this.sel = { kind: "person", key: pkey(cid) };
        return `Added ${nameOf(d, cid)}. Give them a name in the panel, then connect them.`;
      });
      this.sizeCanvas(true);
      this.reveal(pkey(cid));
      return this.focusField("re-f-name", true);
    }
    return undefined;
  }

  save() {
    if (this.readOnly || this.pending || !this.dirty()) return;
    const errors = problems(this.doc).filter((p) => p.level === "error");
    if (errors.length) {
      this.say(`Not saved yet: ${errors[0].text}`);
      this.showProblem(errors[0]);
      return;
    }
    const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    const summary = summaryText(summarize(this.base, this.doc, this.labels));
    const settled = settleIds(this.base, this.doc, this.pos);
    this.pending = { id, renamed: settled.renamed, timer: setTimeout(() => {
      if (this.pending && this.pending.id === id) {
        this.pending = null;
        this.error = "No answer from the console. Check that it is still running, then save again.";
        this.render();
      }
    }, 20000) };
    this.error = "";
    this.render();
    if (this.setTrigger) this.setTrigger("save", { id, routing: toRouting(settled.doc, settled.pos), summary });
  }

  // ---------------------------------------------------------------- drawing

  render(opts = {}) {
    if (!this.doc) return;
    this.renderNodes();
    this.placeNodes();
    this.drawEdges();
    if (opts.panel !== false) this.renderPanel();
    this.renderChrome();
    this.keepDraft();
  }

  renderNodes() {
    const d = this.doc;
    const want = new Map([["incident", { kind: "incident" }]]);
    d.rules.forEach((r, i) => want.set(r.key, { kind: "rule", i, r }));
    d.contacts.forEach((c) => want.set(pkey(c.id), { kind: "person", c }));
    for (const [key, el] of this.nodeEls) {
      if (!want.has(key)) {
        el.remove();
        this.nodeEls.delete(key);
      }
    }
    const report = problems(d);
    const bad = new Set(report.filter((p) => p.level === "error").map((p) => p.key));
    const warn = new Set(report.filter((p) => p.level === "warning").map((p) => p.key));
    const unreachable = new Set();
    const firstCatch = d.rules.findIndex(isCatchAll);
    if (firstCatch >= 0) d.rules.slice(firstCatch + 1).forEach((r) => unreachable.add(r.key));
    for (const [key, info] of want) {
      let el = this.nodeEls.get(key);
      if (!el) {
        el = h("div", { class: `re-node ${info.kind}`, "data-key": key, tabindex: "0", role: "button" });
        this.nodesEl.appendChild(el);
        this.nodeEls.set(key, el);
        if (this.resizer) this.resizer.observe(el);
      }
      const selected = !!this.sel && this.sel.key === key;
      el.classList.toggle("sel", selected);
      el.classList.toggle("bad", bad.has(key));
      el.classList.toggle("warn", warn.has(key) && !bad.has(key));
      el.setAttribute("aria-pressed", selected ? "true" : "false");
      if (info.kind === "incident") this.fillIncident(el);
      else if (info.kind === "rule") this.fillRule(el, info.r, info.i, bad.has(key), unreachable.has(key));
      else this.fillPerson(el, info.c);
    }
  }

  fillIncident(el) {
    el.setAttribute("aria-label", "New incident. Every new incident goes down the rules from the top.");
    const sig = "incident";
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.replaceChildren(icon("crisis_alert"), h("span", { class: "re-name" }, "New incident"));
  }

  fillRule(el, r, i, bad, unreachable) {
    const d = this.doc;
    const when = ruleWhen(r.match, this.labels);
    const brief = ruleWhen(r.match, this.labels, true);
    const owner = findPerson(d, r.owner) ? nameOf(d, r.owner) : "";
    const told = r.notify.filter((x) => findPerson(d, x)).map((x) => nameOf(d, x));
    const note = !owner ? "needs an owner" : unreachable ? "never reached" : "";
    el.classList.toggle("dim", unreachable && !bad);
    el.setAttribute("aria-label", `Rule ${i + 1}, ${r.name.trim() || "no name"}: ${when ? `when ${when}` : "catches everything"}. `
      + `${owner ? `${owner} owns it` : "No owner yet"}${told.length ? `; also tells ${told.join(", ")}` : ""}.`
      + `${unreachable ? " Never reached: a rule above it catches everything." : ""}`);
    const sig = JSON.stringify([i, r.name, when, note, this.readOnly]);
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.title = brief !== when ? `When ${when}` : "";
    el.replaceChildren(
      h("span", { class: "re-num", "aria-hidden": "true" }, String(i + 1)),
      h("div", { class: "re-main" },
        h("span", { class: "re-name" }, r.name.trim() || "No name"),
        h("span", { class: "re-when" }, brief || "catches everything"),
        note ? h("span", { class: "re-note" }, icon(note === "never reached" ? "block" : "error"), note) : null),
      h("div", { class: "re-outs", "aria-hidden": "true" },
        h("span", { class: "re-out" }, h("span", { class: "re-out-label" }, "owner"),
          h("span", { class: "re-port owner", "data-port": "owner", title: "Drag onto a person to make them the owner" })),
        h("span", { class: "re-out" }, h("span", { class: "re-out-label" }, "tells"),
          h("span", { class: "re-port tell", "data-port": "tell", title: "Drag onto a person to tell them too" }))));
  }

  fillPerson(el, c) {
    const d = this.doc;
    const role = c.role.replace(/_/g, " ");
    const linked = !!(this.data.linked || {})[c.id];
    const used = d.rules.some((r) => r.owner === c.id || r.notify.includes(c.id)) || d.contacts.some((x) => x.backup === c.id);
    const bits = [role && role.toLowerCase() !== c.name.trim().toLowerCase() ? role : "", linked ? "own Telegram chat" : "",
      !used && !c.backup ? "in no rule yet" : ""].filter(Boolean);
    el.classList.toggle("loose", !used && !c.backup);
    const owns = d.rules.map((r, i) => (r.owner === c.id ? ruleName(d, i) : "")).filter(Boolean);
    el.setAttribute("aria-label", `${c.name.trim() || "Person with no name"}${bits.length ? `, ${bits.join(", ")}` : ""}. `
      + `${owns.length ? `Owns ${owns.join(", ")}. ` : ""}Backup: ${c.backup ? nameOf(d, c.backup) : "nobody"}.`);
    const sig = JSON.stringify([c.name, bits, this.readOnly]);
    if (el.dataset.sig === sig) return;
    el.dataset.sig = sig;
    el.replaceChildren(
      h("span", { class: "re-port in", "aria-hidden": "true" }),
      h("div", { class: "re-main" },
        h("span", { class: "re-name" }, c.name.trim() || "No name"),
        bits.length ? h("span", { class: "re-when" }, bits.join(" · ")) : null),
      h("span", { class: "re-out", "aria-hidden": "true" }, h("span", { class: "re-out-label" }, "backup"),
        h("span", { class: "re-port backup", "data-port": "backup", title: "Drag onto whoever takes over when they don't answer" })));
  }

  placeNodes() {
    for (const [key, el] of this.nodeEls) {
      const p = this.pos[key];
      if (!p) continue;
      el.style.left = `${p.x}px`;
      el.style.top = `${p.y}px`;
    }
  }

  /** A point on a node, in map coordinates: its sides, or the middle of one of its handles. */
  anchor(key, where) {
    const el = this.nodeEls.get(key);
    const p = this.pos[key];
    if (!el || !p) return null;
    const w = el.offsetWidth;
    const hgt = el.offsetHeight;
    if (where === "left") return { x: p.x, y: p.y + hgt / 2 };
    if (where === "right") return { x: p.x + w, y: p.y + hgt / 2 };
    if (where === "right-in") return { x: p.x + w, y: p.y + Math.min(hgt * 0.3, 18) };
    const port = el.querySelector(`[data-port="${where}"]`);
    if (!port) return { x: p.x + w, y: p.y + hgt / 2 };
    let x = port.offsetWidth / 2;
    let y = port.offsetHeight / 2;
    for (let n = port; n && n !== el; n = n.offsetParent) {
      x += n.offsetLeft;
      y += n.offsetTop;
    }
    return { x: p.x + x, y: p.y + y };
  }

  /** Every line on the map, with what it means. */
  links() {
    const d = this.doc;
    const out = [];
    d.rules.forEach((r, i) => {
      out.push({ id: `in:${r.key}`, kind: "in", from: "incident", to: r.key });
      if (findPerson(d, r.owner)) out.push({ id: `owner:${r.key}:${r.owner}`, kind: "owner", from: r.key, to: pkey(r.owner), rule: i, cid: r.owner });
      for (const x of r.notify) {
        if (findPerson(d, x) && x !== r.owner) out.push({ id: `tell:${r.key}:${x}`, kind: "tell", from: r.key, to: pkey(x), rule: i, cid: x });
      }
    });
    for (const c of d.contacts) {
      if (c.backup && c.backup !== c.id && findPerson(d, c.backup)) {
        out.push({ id: `backup:${c.id}:${c.backup}`, kind: "backup", from: pkey(c.id), to: pkey(c.backup), cid: c.id, target: c.backup });
      }
    }
    return out;
  }

  geometry(l) {
    if (l.kind === "in") {
      const a = this.anchor("incident", "right");
      const b = this.anchor(l.to, "left");
      return a && b ? curve(a, b) : null;
    }
    const a = this.anchor(l.from, l.kind === "backup" ? "backup" : l.kind);
    if (!a) return null;
    const left = this.anchor(l.to, "left");
    if (!left) return null;
    if (l.kind === "backup" && left.x < a.x + 24) return loop(a, this.anchor(l.to, "right-in"));
    return curve(a, left);
  }

  linkText(l) {
    const d = this.doc;
    if (l.kind === "owner") return `${ruleName(d, l.rule)}: ${nameOf(d, l.cid)} owns it`;
    if (l.kind === "tell") return `${ruleName(d, l.rule)} also tells ${nameOf(d, l.cid)}`;
    if (l.kind === "backup") return `${nameOf(d, l.target)} backs up ${nameOf(d, l.cid)}`;
    return "";
  }

  drawEdges() {
    if (!this.doc) return;
    const focus = this.sel && this.sel.kind !== "edge" ? this.sel.key : this.hover;
    const selEdge = this.sel && this.sel.kind === "edge" ? this.sel.id : null;
    const frag = document.createDocumentFragment();
    let selGeom = null;
    let selLink = null;
    for (const l of this.links()) {
      const g = this.geometry(l);
      if (!g) continue;
      const hot = focus && (l.from === focus || l.to === focus);
      const cls = `e e-${l.kind}${l.id === selEdge ? " sel" : ""}${hot ? " hot" : ""}${(focus || selEdge) && !hot && l.id !== selEdge ? " dim" : ""}`;
      const d = pathOf(g);
      const grp = s("g", { class: cls });
      grp.append(s("path", { class: "line", d }));
      if (l.kind !== "in") {
        grp.append(s("path", { class: "head", d: arrow(g) }));
        if (!this.readOnly) grp.append(s("path", { class: "hit", d, "data-edge": l.id }));
      }
      frag.append(grp);
      if (l.id === selEdge) {
        selGeom = g;
        selLink = l;
      }
    }
    this.edges.replaceChildren(frag);
    if (selGeom && !this.readOnly) {
      const m = middle(selGeom);
      this.edgeX.hidden = false;
      this.edgeX.style.left = `${m.x}px`;
      this.edgeX.style.top = `${m.y}px`;
      this.edgeX.setAttribute("aria-label", `Remove: ${this.linkText(selLink)}`);
    } else this.edgeX.hidden = true;
  }

  renderChrome() {
    const d = this.doc;
    const report = problems(d);
    const errors = report.filter((p) => p.level === "error");
    const dirty = this.dirty();
    const ro = this.readOnly;
    for (const b of [this.btn.addRule, this.btn.addPerson, this.btn.tidy]) b.disabled = ro;
    this.btn.undo.disabled = ro || !this.undo.length;
    this.btn.redo.disabled = ro || !this.redo.length;
    this.btn.discard.disabled = ro || !dirty || !!this.pending;
    this.btn.save.disabled = ro || !dirty || !!this.pending || errors.length > 0;
    this.btn.save.querySelector("span:last-child").textContent = this.pending ? "Saving…" : "Save changes";
    let status;
    if (ro) status = "Read only";
    else if (this.pending) status = "Saving…";
    else if (dirty && errors.length) status = `Fix ${errors.length === 1 ? "1 problem" : `${errors.length} problems`} to save`;
    else if (dirty) status = "Unsaved changes";
    else status = "All changes saved";
    if (this.statusEl.textContent !== status) this.statusEl.textContent = status;
    this.statusEl.classList.toggle("dirty", dirty && !ro);
    this.zoomLabel.textContent = `${Math.round(this.view.k * 100)}%`;

    const notes = [];
    if (ro) notes.push(["lock", this.data.lock_reason || "You can look, but not change anything here.", ""]);
    if (this.error) notes.push(["error", `Not saved: ${this.error}`, "bad"]);
    if (this.restored && dirty && !ro) notes.push(["history", "Your unsaved changes from before are back. Save them, or Discard to go back to the saved version.", ""]);
    if (!dirty) this.restored = false;
    if (this.incoming && !ro) notes.push(["sync_problem", "Someone else saved a change while you were editing. Saving now replaces theirs.", "warn", "Show their version"]);
    this.notice.hidden = !notes.length;
    this.notice.replaceChildren(...notes.map(([ico, text, cls, action]) => h("div", { class: `re-note-row ${cls}`, role: cls === "bad" ? "alert" : null },
      icon(ico), h("span", {}, text),
      action ? h("button", { type: "button", class: "re-btn small", onclick: () => this.adopt(this.incoming, true) }, action) : null)));

    const shown = report.filter((p) => p.level === "error" || p.level === "warning");
    this.problemsEl.hidden = !shown.length || ro;
    if (!this.problemsEl.hidden) {
      const items = shown.slice(0, 8).map((p) => h("li", { class: p.level },
        icon(p.level === "error" ? "error" : "info"), h("span", {}, p.text),
        p.key ? h("button", { type: "button", class: "re-btn small", onclick: () => this.showProblem(p) }, "Show") : null));
      const title = errors.length ? `${errors.length === 1 ? "1 thing" : `${errors.length} things`} to fix before saving`
        : "Worth a look (saving still works)";
      this.problemsEl.replaceChildren(h("p", { class: "re-ptitle" }, title), h("ul", {}, items));
    }
  }

  // ---------------------------------------------------------------- the panel

  renderPanel() {
    const d = this.doc;
    const sel = this.sel;
    const ro = this.readOnly;
    let body;
    if (sel && sel.kind === "rule" && d.rules.some((r) => r.key === sel.key)) body = this.rulePanel(d.rules.findIndex((r) => r.key === sel.key));
    else if (sel && sel.kind === "person" && findPerson(d, sel.key.slice(2))) body = this.personPanel(findPerson(d, sel.key.slice(2)));
    else if (sel && sel.kind === "edge") body = this.edgePanel(this.links().find((l) => l.id === sel.id));
    else if (sel && sel.kind === "incident") body = [h("p", { class: "re-ptitle" }, "New incident"),
      h("p", { class: "re-help" }, "Each new incident goes down the rules from the top. The first rule it matches decides who owns it and who hears about it.")];
    else body = this.followPanel();
    if (!body) {
      this.sel = null;
      body = this.followPanel();
    }
    const had = this.host.activeElement && this.panel.contains(this.host.activeElement) ? this.host.activeElement.id : "";
    this.panel.replaceChildren(...[body].flat().filter(Boolean));
    if (ro) for (const el of this.panel.querySelectorAll("input, select, textarea, button.danger, button.move")) el.disabled = true;
    const back = had && this.panel.querySelector(`#${had}`);
    if (back && !back.disabled) back.focus({ preventScroll: true });
  }

  field(id, label, input, hint) {
    input.id = id;
    const hintId = hint ? `${id}-hint` : null;
    if (hintId) input.setAttribute("aria-describedby", hintId);
    return h("div", { class: "re-field" }, h("label", { for: id }, label), input, hint ? h("p", { class: "re-help", id: hintId }, hint) : null);
  }

  text(value, onInput, attrs = {}) {
    const input = h("input", { type: "text", value: "", maxlength: MAX_TEXT, autocomplete: "off", spellcheck: "false", ...attrs });
    input.value = value;
    input.addEventListener("input", () => onInput(input.value));
    return input;
  }

  dropdown(options, value, onChange) {
    const el = h("select", {}, options.map(([v, label]) => h("option", { value: v }, label)));
    el.value = value;
    el.addEventListener("change", () => onChange(el.value));
    return el;
  }

  checks(id, legend, options, chosen, onChange, hint) {
    const box = h("fieldset", { class: "re-checks", id }, h("legend", {}, legend));
    const grid = h("div", { class: "re-check-grid" });
    for (const [v, label] of options) {
      const boxId = `${id}-${v.replace(/[^A-Za-z0-9_-]/g, "_")}`;
      const cb = h("input", { type: "checkbox", id: boxId, value: v });
      cb.checked = chosen.includes(v);
      cb.addEventListener("change", () => onChange([...grid.querySelectorAll("input:checked")].map((x) => x.value)));
      grid.append(h("label", { class: "re-check", for: boxId }, cb, h("span", {}, label)));
    }
    box.append(grid);
    if (hint) box.append(h("p", { class: "re-help" }, hint));
    return box;
  }

  rulePanel(i) {
    const d = this.doc;
    const r = d.rules[i];
    const key = r.key;
    const rule = () => d.rules.find((x) => x.key === key);
    const setMatch = (field, values) => this.edit(`${key}:${field}`, () => {
      const m = { ...rule().match };
      if (values.length) m[field] = values;
      else delete m[field];
      rule().match = m;
    });
    const people = d.contacts.map((c) => [c.id, c.name.trim() || "No name"]);
    const cats = [...this.labels.entries()];
    for (const v of r.match.category || []) if (!this.labels.has(v)) cats.push([v, v.replace(/_/g, " ")]);
    const sevs = [...(this.data.severities || ["low", "medium", "high", "critical"])];
    for (const v of r.match.severity || []) if (!sevs.includes(v)) sevs.push(v);
    const owner = this.dropdown(findPerson(d, r.owner) ? people : [["", "Nobody yet: choose someone"], ...people], r.owner,
      (v) => this.change(() => connect(d, "owner", d.rules.findIndex((x) => x.key === key), v)));
    const tellable = people.filter(([cid]) => cid !== r.owner);
    const name = this.text(r.name, (v) => this.edit(`${key}:name`, () => { rule().name = v; }), { placeholder: "Web attacks" });
    if (!r.name.trim()) name.setAttribute("aria-invalid", "true");
    const extra = Object.keys(r.match).filter((k) => !["category", "severity", "host"].includes(k));
    return [
      h("p", { class: "re-ptitle" }, `Rule ${i + 1} of ${d.rules.length}`),
      this.field("re-f-name", "Rule name", name),
      this.checks("re-f-cat", "Incident types", cats, r.match.category || [], (v) => setMatch("category", v), "None ticked: any type."),
      this.checks("re-f-sev", "Severity", sevs.map((v) => [v, v]), r.match.severity || [], (v) => setMatch("severity", v), "None ticked: any severity."),
      this.field("re-f-host", "Machines", this.text((r.match.host || []).join(", "),
        (v) => setMatch("host", v.split(",").map((x) => x.trim()).filter(Boolean)), { placeholder: "any machine" }),
        "Names or patterns such as web-* or db-01, separated by commas."),
      extra.length ? h("p", { class: "re-help" }, `Also matches on ${extra.map((k) => `${k} ${r.match[k].join(" or ")}`).join("; ")} (kept as it is).`) : null,
      this.field("re-f-owner", "Owner (gets it and every reminder)", owner),
      tellable.length ? this.checks("re-f-tell", "Also tell, once", tellable, r.notify, (v) => this.change(() => {
        const rr = rule();
        rr.notify = v;
        return `${ruleName(d, d.rules.indexOf(rr))} tells ${v.length ? v.map((x) => nameOf(d, x)).join(", ") : "nobody else"}.`;
      })) : null,
      h("div", { class: "re-row" },
        h("button", { type: "button", class: "re-btn move", disabled: i === 0, onclick: () => this.moveRule(key, -1) }, icon("arrow_upward"), h("span", {}, "Move up")),
        h("button", { type: "button", class: "re-btn move", disabled: i === d.rules.length - 1, onclick: () => this.moveRule(key, 1) }, icon("arrow_downward"), h("span", {}, "Move down"))),
      h("div", { class: "re-row end" },
        h("button", { type: "button", class: "re-btn danger", onclick: () => this.deleteNode(key) }, icon("delete"), h("span", {}, "Delete rule"))),
    ];
  }

  personPanel(c) {
    const d = this.doc;
    const cid = c.id;
    const me = () => findPerson(d, cid);
    const roles = (this.data.roles || [["", "none"], ["on_duty", "on duty"], ["team_lead", "team lead"], ["it_manager", "IT manager"], ["cxo", "CXO"]]);
    const roleOptions = roles.some(([v]) => v === c.role) ? roles : [...roles, [c.role, c.role]];
    const others = d.contacts.filter((x) => x.id !== cid).map((x) => [x.id, x.name.trim() || "No name"]);
    const owns = d.rules.map((r, i) => (r.owner === cid ? ruleName(d, i) : "")).filter(Boolean);
    const told = d.rules.map((r, i) => (r.notify.includes(cid) ? ruleName(d, i) : "")).filter(Boolean);
    const backs = d.contacts.filter((x) => x.backup === cid).map((x) => nameOf(d, x.id));
    const name = this.text(c.name, (v) => this.edit(`${cid}:name`, () => { me().name = v; }));
    if (!c.name.trim() || problems(d).some((p) => p.key === pkey(cid) && p.text.startsWith("Two people"))) name.setAttribute("aria-invalid", "true");
    const email = this.text(c.email, (v) => this.edit(`${cid}:email`, () => { me().email = v; }), { type: "email", inputmode: "email" });
    if (c.email.trim() && !EMAIL.test(c.email.trim())) email.setAttribute("aria-invalid", "true");
    const facts = [owns.length ? `Owns ${owns.join(", ")}.` : "", told.length ? `Told about ${told.join(", ")}.` : "",
      backs.length ? `Backs up ${backs.join(", ")}.` : ""].filter(Boolean);
    return [
      h("p", { class: "re-ptitle" }, "Person"),
      this.field("re-f-name", "Name", name),
      this.field("re-f-role", "Role", this.dropdown(roleOptions, c.role, (v) => this.change(() => {
        setRole(d, cid, v);
        return v ? `${nameOf(d, cid)} is now the ${v.replace(/_/g, " ")}.` : `${nameOf(d, cid)} has no role now.`;
      })), "On duty, team lead, IT manager and CXO stand in for the four names in the settings; one person each."),
      this.field("re-f-email", "Email", email),
      this.field("re-f-telegram", "Telegram", this.text(c.telegram, (v) => this.edit(`${cid}:telegram`, () => { me().telegram = v; }), { placeholder: "@handle" })),
      this.field("re-f-backup", "Backup (takes over when they do not answer)", this.dropdown([["", "nobody"], ...others], c.backup,
        (v) => this.change(() => (v ? connect(d, "backup", cid, v) : disconnect(d, "backup", cid))))),
      h("p", { class: "re-help" }, facts.join(" ") || "Not in any rule yet. Drag a rule's owner or tells handle onto them."),
      h("div", { class: "re-row end" },
        h("button", { type: "button", class: "re-btn danger", disabled: d.contacts.length === 1, onclick: () => this.deleteNode(pkey(cid)) },
          icon("person_remove"), h("span", {}, "Delete person"))),
    ];
  }

  edgePanel(l) {
    if (!l) return null;
    const meaning = { owner: "Owns it: gets the incident and every reminder until someone answers.",
                      tell: "Also told: hears about the incident once, when it opens.",
                      backup: "Backup: takes over when the person before does not answer the reminders." }[l.kind];
    return [
      h("p", { class: "re-ptitle" }, this.linkText(l)),
      h("p", { class: "re-help" }, meaning),
      this.readOnly ? null : h("div", { class: "re-row end" },
        h("button", { type: "button", class: "re-btn danger", onclick: () => this.removeSelectedEdge() }, icon("link_off"), h("span", {}, "Remove this line"))),
    ];
  }

  followPanel() {
    const d = this.doc;
    const fu = d.follow_up;
    const num = (id, label, field, attrs, hint) => {
      const input = h("input", { type: "number", inputmode: "decimal", ...attrs });
      input.value = String(fu[field]);
      input.addEventListener("input", () => this.edit(`follow:${field}`, () => {
        d.follow_up[field] = input.value === "" ? NaN : Number(input.value);
      }));
      return this.field(id, label, input, hint);
    };
    const tips = this.readOnly ? [h("p", { class: "re-help" }, "Click a rule or a person to see the details.")] : [
      h("p", { class: "re-ptitle sub" }, "How to change it"),
      h("ul", { class: "re-tips" },
        h("li", {}, "Drag a rule's ", h("b", {}, "owner"), " handle onto a person to give them that rule's incidents."),
        h("li", {}, "Drag its ", h("b", {}, "tells"), " handle onto someone to tell them as well."),
        h("li", {}, "Drag a person's ", h("b", {}, "backup"), " handle onto whoever takes over when they don't answer."),
        h("li", {}, "Drop a handle on empty space to add a new person there."),
        h("li", {}, "Drag a rule up or down to change its turn. Click a line to remove it."),
        h("li", {}, "Keyboard: arrow keys move the focused box (up and down change a rule's turn), Delete removes it, Ctrl+Z undoes."))];
    return [
      h("p", { class: "re-ptitle" }, "Follow-up"),
      h("p", { class: "re-help" }, this.readOnly ? "For every incident." : "For every incident. Select a rule or a person on the map to change it."),
      num("re-f-after", "Unanswered reminders before the backup takes over", "escalate_after_reminders", { min: 1, max: 20, step: 1 }),
      num("re-f-most", "Hand an incident on at most this many times", "max_escalations", { min: 0, max: 20, step: 1 }),
      num("re-f-hours", "Remind the owner after this many hours when acknowledged but not resolved", "resolve_within_hours",
        { min: 0, max: 720, step: 1 }, "0 = never."),
      ...tips,
    ];
  }

  focusField(id, selectAll) {
    requestAnimationFrame(() => {
      const el = this.host.querySelector ? this.host.querySelector(`#${id}`) : null;
      if (!el) return;
      el.focus({ preventScroll: true });
      if (selectAll && el.select) el.select();
    });
  }

  // ---------------------------------------------------------------- editing actions

  moveRule(key, step) {
    const d = this.doc;
    const i = d.rules.findIndex((r) => r.key === key);
    const j = i + step;
    if (i < 0 || j < 0 || j >= d.rules.length) return;
    this.change(() => {
      const [r] = d.rules.splice(i, 1);
      d.rules.splice(j, 0, r);
      restackRules(d, this.pos, (k) => this.size(k));
      return `${ruleName(d, j)} is now rule ${j + 1}.`;
    });
  }

  deleteNode(key) {
    if (this.readOnly || key === "incident") return;
    const d = this.doc;
    if (key.startsWith("p:")) {
      const cid = key.slice(2);
      const name = nameOf(d, cid);
      let error = "";
      this.change(() => {
        const res = removePerson(d, cid);
        error = res.error;
        if (error) return false;
        delete this.pos[key];
        if (this.sel && this.sel.key === key) this.sel = null;
        return `Removed ${name}${res.notes.length ? `: ${res.notes.join("; ")}` : ""}. Ctrl+Z brings them back.`;
      });
      if (error) this.say(error);
    } else {
      const i = d.rules.findIndex((r) => r.key === key);
      if (i < 0) return;
      const name = ruleName(d, i);
      this.change(() => {
        d.rules.splice(i, 1);
        delete this.pos[key];
        if (this.sel && this.sel.key === key) this.sel = null;
        return `Deleted ${name}. Ctrl+Z brings it back.`;
      });
    }
    this.viewport.focus({ preventScroll: true });
  }

  removeSelectedEdge() {
    if (this.readOnly || !this.sel || this.sel.kind !== "edge") return;
    const l = this.links().find((x) => x.id === this.sel.id);
    if (!l) return;
    this.change(() => {
      this.sel = null;
      return disconnect(this.doc, l.kind, l.kind === "backup" ? l.cid : l.rule, l.cid) || false;
    });
  }

  select(sel, focus = false) {
    const same = JSON.stringify(sel) === JSON.stringify(this.sel);
    this.sel = sel;
    this.typing = null;
    this.nudging = null;
    if (!same) this.render();
    if (focus && sel && sel.key) {
      const el = this.nodeEls.get(sel.key);
      if (el) el.focus({ preventScroll: true });
    }
  }

  showProblem(p) {
    if (!p.key) {
      if (p.kind === "follow") this.select(null);
      return;
    }
    this.select({ kind: p.key.startsWith("p:") ? "person" : "rule", key: p.key }, true);
    this.reveal(p.key);
  }

  /** Pan so a node is in view. */
  reveal(key) {
    const p = this.pos[key];
    if (!p) return;
    const sz = this.size(key);
    const r = this.viewport.getBoundingClientRect();
    const k = this.view.k;
    const x = p.x * k + this.view.x;
    const y = p.y * k + this.view.y;
    if (x < 16 || y < 16 || x + sz.w * k > r.width - 16 || y + sz.h * k > r.height - 16) {
      this.view.x = r.width / 2 - (p.x + sz.w / 2) * k;
      this.view.y = r.height / 2 - (p.y + sz.h / 2) * k;
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
  }

  bounds() {
    let x0 = Infinity;
    let y0 = Infinity;
    let x1 = -Infinity;
    let y1 = -Infinity;
    for (const key of this.nodeEls.keys()) {
      const p = this.pos[key];
      if (!p) continue;
      const sz = this.size(key);
      x0 = Math.min(x0, p.x);
      y0 = Math.min(y0, p.y);
      x1 = Math.max(x1, p.x + sz.w);
      y1 = Math.max(y1, p.y + sz.h);
    }
    if (!Number.isFinite(x0)) return { x0: 0, y0: 0, x1: 400, y1: 300 };
    const loops = this.links().some((l) => l.kind === "backup");
    return { x0, y0, x1: x1 + (loops ? 64 : 16), y1 };
  }

  /** Make the canvas about as tall as the map, within limits, so most maps need no zooming. With `grow`
      (while editing) it only gets taller, so the page doesn't jump about under the pointer. */
  sizeCanvas(grow = false) {
    const b = this.bounds();
    const want = Math.round(clamp(b.y1 - b.y0 + 72, 360, 640));
    if (grow && want <= this.viewport.offsetHeight) return;
    this.viewport.style.height = `${want}px`;
  }

  /** True when the whole map is inside the canvas at the current pan and zoom. */
  inView() {
    const b = this.bounds();
    const r = this.viewport.getBoundingClientRect();
    const { x, y, k } = this.view;
    if (!r.width) return false;
    return b.x0 * k + x >= -1 && b.y0 * k + y >= -1 && b.x1 * k + x <= r.width + 1 && b.y1 * k + y <= r.height + 1;
  }

  fit() {
    const b = this.bounds();
    const r = this.viewport.getBoundingClientRect();
    this.needsFit = !r.width;
    if (!r.width) return;
    const pad = 28;
    const k = clamp(Math.min((r.width - 2 * pad) / (b.x1 - b.x0), (r.height - 2 * pad) / (b.y1 - b.y0)), ZOOM.min, 1);
    this.view = { k, x: (r.width - (b.x1 - b.x0) * k) / 2 - b.x0 * k, y: (r.height - (b.y1 - b.y0) * k) / 2 - b.y0 * k };
    this.applyView();
  }

  zoomBy(f, cx, cy) {
    const r = this.viewport.getBoundingClientRect();
    const px = cx === undefined ? r.width / 2 : cx - r.left;
    const py = cy === undefined ? r.height / 2 : cy - r.top;
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
    const r = this.viewport.getBoundingClientRect();
    return { x: (e.clientX - r.left - this.view.x) / this.view.k, y: (e.clientY - r.top - this.view.y) / this.view.k };
  }

  // ---------------------------------------------------------------- pointer: drag, connect, pan

  down(e) {
    if (e.button !== 0 || !this.doc) return;
    const port = e.target.closest("[data-port]");
    const nodeEl = e.target.closest(".re-node");
    const hit = e.target.closest("[data-edge]");
    if (e.target.closest(".re-edge-x")) return;
    const at = this.toWorld(e);
    if (port && nodeEl && !this.readOnly) {
      this.drag = { type: "link", from: nodeEl.dataset.key, port: port.dataset.port, at, start: at, target: null };
      this.root.classList.add("linking", `linking-${port.dataset.port}`);
    } else if (nodeEl) {
      const key = nodeEl.dataset.key;
      const rule = this.doc.rules.some((r) => r.key === key);
      const top = rule ? Math.min(...this.doc.rules.map((r) => (this.pos[r.key] ? this.pos[r.key].y : Infinity))) : 0;
      this.drag = { type: "node", key, rule, top, start: at, orig: { ...this.pos[key] }, moved: false, snap: this.snapshot() };
    } else if (hit) {
      this.select({ kind: "edge", id: hit.dataset.edge });
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
      this.nodeEls.get(g.key)?.classList.add("lifted");
      this.pos[g.key] = { x: Math.round(g.orig.x + dx), y: Math.round(g.orig.y + dy) };
      if (g.rule) {
        if (sortRulesByY(this.doc, this.pos, (k) => this.size(k))) this.renderNodes();
        this.stackRules(g.top, g.key);
      }
      this.placeNodes();
      this.drawEdges();
      return;
    }
    // Drawing a line: follow the pointer, light up the person under it.
    g.at = at;
    const target = this.personAt(at, g.port === "backup" ? g.from : null);
    if (target !== g.target) {
      if (g.target && this.nodeEls.get(g.target)) this.nodeEls.get(g.target).classList.remove("drop");
      if (target) this.nodeEls.get(target).classList.add("drop");
      g.target = target;
    }
    const a = this.anchor(g.from, g.port);
    const b = target ? this.anchor(target, "left") : at;
    const geo = g.port === "backup" && target && b.x < a.x + 24 ? loop(a, this.anchor(target, "right-in")) : curve(a, b);
    this.ghost.replaceChildren(s("g", { class: `e e-${g.port === "tell" ? "tell" : g.port} hot` },
      s("path", { class: "line", d: pathOf(geo) }), s("path", { class: "head", d: arrow(geo) })));
  }

  up(e, cancelled = false) {
    const g = this.drag;
    if (!g) return;
    this.drag = null;
    if (this.viewport.hasPointerCapture && this.viewport.hasPointerCapture(e.pointerId)) this.viewport.releasePointerCapture(e.pointerId);
    this.root.classList.remove("dragging", "panning", "linking", "linking-owner", "linking-tell", "linking-backup");
    if (g.type === "pan") {
      if (!g.moved && !cancelled) this.select(null);
    } else if (g.type === "node") {
      this.nodeEls.get(g.key)?.classList.remove("lifted");
      if (g.rule && g.moved && !cancelled) {
        this.pos[g.key] = { x: g.orig.x, y: this.pos[g.key].y };
        this.stackRules(g.top);
      }
      if (g.moved && !cancelled) {
        if (this.sig() !== signature(g.snap.doc, g.snap.pos)) {
          this.push(g.snap);
          const order = JSON.stringify(g.snap.doc.rules.map((r) => r.key)) !== JSON.stringify(this.doc.rules.map((r) => r.key));
          if (order) {
            const i = this.doc.rules.findIndex((r) => r.key === g.key);
            this.say(`${ruleName(this.doc, i)} is now rule ${i + 1}.`);
          }
        }
        this.render();
      } else if (cancelled) {
        this.restore(g.snap);
      } else {
        this.select({ kind: g.key === "incident" ? "incident" : g.key.startsWith("p:") ? "person" : "rule", key: g.key }, true);
      }
    } else {
      this.ghost.replaceChildren();
      if (g.target) this.nodeEls.get(g.target)?.classList.remove("drop");
      if (!cancelled) this.finishLink(g);
    }
    if (this.queued) {
      const q = this.queued;
      this.queued = null;
      this.update(q);
    }
  }

  finishLink(g) {
    const d = this.doc;
    const ruleIndex = () => d.rules.findIndex((r) => r.key === g.from);
    const from = g.port === "backup" ? g.from.slice(2) : ruleIndex();
    if (g.target) {
      const to = g.target.slice(2);
      if (!this.change(() => connect(d, g.port, from, to) || false)) {
        this.say(g.port === "backup" && to === from ? "Someone can't be their own backup." : "That line is already there.");
      }
      return;
    }
    const far = Math.hypot(g.at.x - g.start.x, g.at.y - g.start.y) > 40;
    if (!far) return;
    // Dropped on empty space: a new person there, already connected.
    let cid;
    this.change(() => {
      cid = addPerson(d, "New person", this.base.contacts.map((c) => c.id));
      this.renderNodes();
      const sz = this.size(pkey(cid));
      this.pos[pkey(cid)] = { x: Math.round(g.at.x), y: Math.round(g.at.y - sz.h / 2) };
      this.clearSpot(pkey(cid));
      connect(d, g.port, from, cid);
      this.sel = { kind: "person", key: pkey(cid) };
      return "Added a new person and connected them. Type their name in the panel.";
    });
    this.sizeCanvas(true);
    this.reveal(pkey(cid));
    this.focusField("re-f-name", true);
  }

  /** Move a box that was just dropped down past anything it would cover. */
  clearSpot(key) {
    const p = this.pos[key];
    const sz = this.size(key);
    const m = 12;
    const boxes = [...this.nodeEls.keys()].filter((k) => k !== key && this.pos[k]).map((k) => {
      const q = this.pos[k];
      const z = this.size(k);
      return { x0: q.x - m, y0: q.y - m, x1: q.x + z.w + m, y1: q.y + z.h + m };
    });
    for (let i = 0; i < boxes.length; i += 1) {
      const hit = boxes.find((b) => p.x < b.x1 && p.x + sz.w > b.x0 && p.y < b.y1 && p.y + sz.h > b.y0);
      if (!hit) break;
      p.y = hit.y1;
    }
  }

  /** The rules stacked in order from `top`, each keeping its own left edge; `skip` (being dragged) keeps
      where the pointer has it, and the others leave its slot open. */
  stackRules(top, skip) {
    let y = top;
    for (const r of this.doc.rules) {
      if (r.key !== skip) this.pos[r.key] = { x: this.pos[r.key] ? this.pos[r.key].x : 0, y };
      y += this.size(r.key).h + GRID.gapY;
    }
  }

  personAt(at, except) {
    for (const c of this.doc.contacts) {
      const key = pkey(c.id);
      if (except && key === except) continue;
      const p = this.pos[key];
      if (!p) continue;
      const sz = this.size(key);
      if (at.x >= p.x - 10 && at.x <= p.x + sz.w + 10 && at.y >= p.y - 10 && at.y <= p.y + sz.h + 10) return key;
    }
    return null;
  }

  hoverAt(e) {
    if (this.drag) return;
    const nodeEl = e.target.closest(".re-node");
    this.setHover(nodeEl ? nodeEl.dataset.key : null);
  }

  setHover(key) {
    if (this.hover === key) return;
    this.hover = key;
    if (!this.sel) this.drawEdges();
  }

  // ---------------------------------------------------------------- keyboard

  nodeKey(e) {
    const el = e.target.closest(".re-node");
    if (!el || e.target !== el) return;
    const key = el.dataset.key;
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      this.select({ kind: key === "incident" ? "incident" : key.startsWith("p:") ? "person" : "rule", key }, true);
      return;
    }
    if ((e.key === "Delete" || e.key === "Backspace") && !this.readOnly) {
      e.preventDefault();
      this.deleteNode(key);
      return;
    }
    const step = e.shiftKey ? 48 : 12;
    const delta = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step] }[e.key];
    if (!delta || this.readOnly || !this.pos[key]) return;
    e.preventDefault();
    if (this.doc.rules.some((r) => r.key === key)) {
      if (delta[1]) this.moveRule(key, delta[1] < 0 ? -1 : 1);
      this.nodeEls.get(key)?.focus({ preventScroll: true });
      return;
    }
    if (this.nudging !== key) {
      this.push(this.snapshot());
      this.nudging = key;
    }
    this.pos[key] = { x: this.pos[key].x + delta[0], y: this.pos[key].y + delta[1] };
    this.render({ panel: false });
    this.reveal(key);
    el.focus({ preventScroll: true });
  }

  key(e) {
    const mod = e.ctrlKey || e.metaKey;
    const typing = isTyping(e.target);
    if (mod && e.key.toLowerCase() === "s") {
      e.preventDefault();
      this.save();
    } else if (mod && !typing && e.key.toLowerCase() === "z") {
      e.preventDefault();
      if (e.shiftKey) this.redoLast();
      else this.undoLast();
    } else if (mod && !typing && e.key.toLowerCase() === "y") {
      e.preventDefault();
      this.redoLast();
    } else if (e.key === "Escape") {
      if (this.drag) {
        const g = this.drag;
        this.up({ pointerId: -1 }, true);
        if (g.type === "link") this.ghost.replaceChildren();
      } else if (this.sel && !typing) this.select(null);
    } else if ((e.key === "Delete" || e.key === "Backspace") && !typing && this.sel && this.sel.kind === "edge") {
      e.preventDefault();
      this.removeSelectedEdge();
    }
  }

  say(text) {
    this.live.textContent = "";
    requestAnimationFrame(() => { this.live.textContent = text; });
  }
}
