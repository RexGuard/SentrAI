/* The "Who gets what" editor's model (sentrai_ui/routing_editor.mjs): the functions above its DOM part,
   run in Node with nothing but its built-in test runner.

     cd mvp/dashboard && node --test tests/routing_editor.test.mjs

   tests/test_routing_editor_js.py runs this file under pytest, and skips it where Node 20+ is missing. */

import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import * as editor from "../sentrai_ui/routing_editor.mjs";

const {
  MAX_PEOPLE, MAX_RULES, MAX_TEXT, addPerson, addRule, backupLoops, cleanMatch, clone, connect, disconnect,
  findPerson, fromRouting, isCatchAll, layoutAll, nameOf, newContactId, newRuleIndex, peopleOrder, pkey,
  placeMissing, problems, removePerson, reserveKeys, restackRules, ruleName, ruleWhen, rulesFollowY, setRole,
  settleIds, sortRulesByY, summarize, summaryText, toRouting,
} = editor;

const CORE_ROUTING = new URL("../../core/app/routing.py", import.meta.url);
const CORE_ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,39}$/; // CONTACT_ID in core/app/routing.py

const LABELS = new Map([
  ["brute_force", "Brute force"], ["xss", "Cross-site scripting"], ["privilege_escalation", "Privilege escalation"],
  ["data_exfiltration", "Data exfiltration"], ["log_tampering", "Log tampering"], ["malware", "Malware found"],
]);

/** GET /routing as Python hands it to the editor (shaping.routing_editor_data): people as a list, in file order. */
function sampleRouting() {
  return {
    contacts: [
      { id: "on_duty", name: "Amir", role: "on_duty", email: "amir@example.com", telegram: "@amir", backup: "team_lead" },
      { id: "team_lead", name: "Lee", role: "team_lead", email: "", telegram: "", backup: "it_manager" },
      { id: "it_manager", name: "Ika", role: "it_manager", email: "", telegram: "", backup: "cxo" },
      { id: "cxo", name: "Boss", role: "cxo", email: "", telegram: "", backup: "" },
    ],
    rules: [
      { name: "Critical", match: { severity: ["critical"] }, owner: "on_duty", notify: ["team_lead", "it_manager", "cxo"] },
      { name: "Attacker inside", match: { category: ["malware", "data_exfiltration", "log_tampering", "privilege_escalation"] },
        owner: "on_duty", notify: ["team_lead", "it_manager"] },
      { name: "Database", match: { host: ["db-*"] }, owner: "team_lead", notify: [] },
      { name: "Everything else", match: {}, owner: "on_duty", notify: [] },
    ],
    follow_up: { escalate_after_reminders: 2, max_escalations: 3, resolve_within_hours: 24 },
    layout: {
      incident: [0, 150],
      rules: [[210, 0], [210, 90], [210, 180], [210, 270]],
      contacts: { on_duty: [620, 0], team_lead: [620, 80], it_manager: [620, 160], cxo: [620, 240] },
    },
  };
}

const sample = () => fromRouting(sampleRouting());
const person = (id, name, more = {}) => ({ id, name, role: "", email: "", telegram: "", backup: "", ...more });
const rule = (key, name, owner, more = {}) => ({ key, name, match: {}, owner, notify: [], ...more });
const docOf = (contacts, rules = [], followUp = {}) => ({
  contacts, rules, follow_up: { escalate_after_reminders: 2, max_escalations: 3, resolve_within_hours: 24, ...followUp },
});
const texts = (report, level) => report.filter((p) => !level || p.level === level).map((p) => p.text);

/** Box sizes as the browser would measure them. */
const size = (key) => (key === "incident" ? { w: 130, h: 40 } : key.startsWith("p:") ? { w: 180, h: 50 } : { w: 240, h: 60 });

/** The saved layout as map positions, keyed the way the editor keys its boxes (Editor.positionsFrom). */
function posFromLayout(doc, layout) {
  const pos = {};
  if (layout.incident) pos.incident = { x: layout.incident[0], y: layout.incident[1] };
  (layout.rules || []).forEach((p, i) => {
    if (p && doc.rules[i]) pos[doc.rules[i].key] = { x: p[0], y: p[1] };
  });
  for (const [cid, p] of Object.entries(layout.contacts || {})) if (p) pos[pkey(cid)] = { x: p[0], y: p[1] };
  return pos;
}

// ------------------------------------------------------------------ the module

describe("the module", () => {
  test("loads without a DOM: nothing at the top level touches document, window and the like", async () => {
    const names = ["document", "window", "requestAnimationFrame", "ResizeObserver", "sessionStorage", "localStorage",
      "getComputedStyle", "HTMLElement", "customElements"];
    const saved = names.map((n) => [n, Object.getOwnPropertyDescriptor(globalThis, n)]);
    const touched = [];
    for (const n of names) {
      Object.defineProperty(globalThis, n, {
        configurable: true,
        get() {
          touched.push(n);
          throw new Error(`${n} used while the module loads`);
        },
      });
    }
    let fresh;
    try {
      // A query string gives a fresh copy of the module, evaluated under the traps above.
      fresh = await import(new URL(`../sentrai_ui/routing_editor.mjs?no-dom=${Date.now()}`, import.meta.url).href);
    } finally {
      for (const [n, d] of saved) {
        if (d) Object.defineProperty(globalThis, n, d);
        else delete globalThis[n];
      }
    }
    assert.deepEqual(touched, []);
    assert.equal(typeof fresh.default, "function"); // mount(), which Streamlit calls
    assert.equal(typeof fresh.fromRouting, "function");
  });

  test("its limits and ids are the core's (core/app/routing.py)",
    { skip: !existsSync(CORE_ROUTING) && "core/app/routing.py is not next to the dashboard" }, () => {
      const src = readFileSync(CORE_ROUTING, "utf8");
      const limits = /^MAX_CONTACTS, MAX_RULES, MAX_TEXT = (\d+), (\d+), (\d+)\s*$/m.exec(src);
      assert.ok(limits, "routing.py no longer sets MAX_CONTACTS, MAX_RULES, MAX_TEXT on one line: update this test");
      assert.deepEqual([MAX_PEOPLE, MAX_RULES, MAX_TEXT], limits.slice(1).map(Number));
      assert.ok(src.includes(`CONTACT_ID = re.compile(r"${CORE_ID.source}")`), "the core's contact id pattern changed");
    });

  test("clone copies deeply and pkey names a person's box", () => {
    const doc = sample();
    const copy = clone(doc);
    assert.deepEqual(copy, doc);
    copy.contacts[0].name = "Changed";
    copy.rules[0].notify.push("x");
    assert.equal(doc.contacts[0].name, "Amir");
    assert.deepEqual(doc.rules[0].notify, ["team_lead", "it_manager", "cxo"]);
    assert.equal(pkey("lee-tan"), "p:lee-tan");
  });
});

// ------------------------------------------------------------------ in and out

describe("fromRouting and toRouting", () => {
  test("a round trip gives back the same routing, layout included", () => {
    const routing = sampleRouting();
    const doc = fromRouting(routing);
    assert.deepEqual(toRouting(doc, posFromLayout(doc, routing.layout)), routing);
  });

  test("the working copy: people as they came, rules keyed r0, r1, ... and no layout", () => {
    const doc = sample();
    assert.deepEqual(doc.contacts[0],
      { id: "on_duty", name: "Amir", role: "on_duty", email: "amir@example.com", telegram: "@amir", backup: "team_lead" });
    assert.deepEqual(doc.rules.map((r) => r.key), ["r0", "r1", "r2", "r3"]);
    assert.deepEqual(doc.rules[2], { key: "r2", name: "Database", match: { host: ["db-*"] }, owner: "team_lead", notify: [] });
    assert.deepEqual(Object.keys(doc).sort(), ["contacts", "follow_up", "rules"]);
  });

  test("the owner is dropped from the people a rule also tells", () => {
    const routing = sampleRouting();
    routing.rules[0].notify = ["on_duty", "team_lead", "on_duty"];
    assert.deepEqual(toRouting(fromRouting(routing)).rules[0].notify, ["team_lead"]);
  });

  test("text is trimmed and conditions cleaned on the way out", () => {
    const doc = sample();
    Object.assign(doc.contacts[1], { name: "  Lee Tan ", email: " lee@example.com ", telegram: " @lee " });
    doc.rules[2].name = " Database  ";
    doc.rules[2].match = { host: [" db-* ", "", "  "], severity: [] };
    const out = toRouting(doc);
    assert.deepEqual(out.contacts[1],
      { id: "team_lead", name: "Lee Tan", role: "team_lead", email: "lee@example.com", telegram: "@lee", backup: "it_manager" });
    assert.deepEqual(out.rules[2], { name: "Database", match: { host: ["db-*"] }, owner: "team_lead", notify: [] });
  });

  test("without positions there is no layout; positions are rounded and boxes without one are null", () => {
    const doc = sample();
    assert.equal("layout" in toRouting(doc), false);
    const out = toRouting(doc, { incident: { x: 1.4, y: 2.6 }, r1: { x: 10.5, y: -3.2 }, "p:cxo": { x: 7, y: 8 } });
    assert.deepEqual(out.layout, {
      incident: [1, 3],
      rules: [null, [11, -3], null, null],
      contacts: { on_duty: null, team_lead: null, it_manager: null, cxo: [7, 8] },
    });
  });

  test("the follow-up is copied, not shared with the working copy", () => {
    const doc = sample();
    const out = toRouting(doc);
    out.follow_up.max_escalations = 9;
    assert.equal(doc.follow_up.max_escalations, 3);
  });

  test("gaps in what arrives are filled: no routing, people without an id, missing fields, odd values", () => {
    assert.deepEqual(fromRouting(null),
      { contacts: [], rules: [], follow_up: { escalate_after_reminders: 2, max_escalations: 3, resolve_within_hours: 24 } });
    const doc = fromRouting({
      contacts: [{ id: "lee", name: "Lee", email: null }, { name: "No id" }, { id: "lee", name: "Second Lee" }, null, { id: 7 }],
      rules: [{ name: "Web", match: { category: "xss", host: [" web-* ", ""] }, owner: "lee", notify: "lee" }, { notify: ["", " "] }],
      follow_up: { escalate_after_reminders: "4", max_escalations: "", resolve_within_hours: "soon" },
    });
    assert.deepEqual(doc.contacts, [person("lee", "Lee"), person("7", "")]);
    assert.deepEqual(doc.rules, [
      { key: "r0", name: "Web", match: { category: ["xss"], host: ["web-*"] }, owner: "lee", notify: ["lee"] },
      { key: "r1", name: "", match: {}, owner: "", notify: [] },
    ]);
    assert.deepEqual(doc.follow_up, { escalate_after_reminders: 4, max_escalations: 3, resolve_within_hours: 24 });
  });
});

// ------------------------------------------------------------------ conditions in words

describe("cleanMatch, isCatchAll and ruleWhen", () => {
  test("cleanMatch trims values, drops blanks and empty conditions, and makes single values lists", () => {
    const match = { category: ["malware", " xss ", "", "  "], severity: "critical", host: [], layer: null, other: " " };
    assert.deepEqual(cleanMatch(match), { category: ["malware", "xss"], severity: ["critical"] });
    assert.deepEqual(match.category, ["malware", " xss ", "", "  "]); // the input is left alone
    assert.deepEqual(cleanMatch(undefined), {});
    assert.deepEqual(cleanMatch({ layer: ["network"] }), { layer: ["network"] });
  });

  test("a rule with no real conditions catches everything", () => {
    assert.equal(isCatchAll({ match: {} }), true);
    assert.equal(isCatchAll({ match: { host: ["  "], severity: [] } }), true);
    assert.equal(isCatchAll({}), true);
    assert.equal(isCatchAll({ match: { severity: ["high"] } }), false);
  });

  test("ruleWhen reads the conditions in plain words, with the category labels", () => {
    assert.equal(ruleWhen({ category: ["malware", "log_tampering"], severity: ["critical"] }, LABELS),
      "Malware found or Log tampering · critical severity");
    assert.equal(ruleWhen({ category: ["port_scan"], severity: ["high", "critical"], host: ["web-*", "db-01"], layer: ["network"] }, LABELS),
      "port scan · high or critical severity · on web-* or db-01 · layer network");
    assert.equal(ruleWhen({ category: ["brute_force"] }, null), "brute force");
    assert.equal(ruleWhen({}, LABELS), "");
  });

  test("the short form for the box on the map: \"A, B and 2 more\" past three types", () => {
    const four = { category: ["malware", "data_exfiltration", "log_tampering", "privilege_escalation"] };
    assert.equal(ruleWhen(four, LABELS, true), "Malware found, Data exfiltration and 2 more");
    assert.equal(ruleWhen(four, LABELS), "Malware found or Data exfiltration or Log tampering or Privilege escalation");
    assert.equal(ruleWhen({ category: ["malware", "log_tampering", "xss"] }, LABELS, true),
      "Malware found or Log tampering or Cross-site scripting");
    assert.equal(ruleWhen({ ...four, severity: ["critical"] }, LABELS, true), "Malware found, Data exfiltration and 2 more · critical severity");
  });
});

// ------------------------------------------------------------------ people

describe("people", () => {
  test("newContactId makes a short id from the name that nobody has yet", () => {
    const none = { contacts: [] };
    assert.equal(newContactId(none, "Lee Tan"), "lee-tan");
    assert.equal(newContactId(none, "  Lee   Tan!! "), "lee-tan");
    assert.equal(newContactId(none, "O'Brien & Co."), "o-brien-co");
    assert.equal(newContactId(none, "李"), "person");
    assert.equal(newContactId(none, ""), "person");
    const taken = { contacts: [{ id: "lee-tan" }, { id: "lee-tan-2" }] };
    assert.equal(newContactId(taken, "Lee Tan"), "lee-tan-3");
    const long = newContactId(none, "A very long name for somebody who works nights");
    assert.ok(long.length <= 30 && long.startsWith("a-very-long-name-for-somebody"), long);
    for (const id of ["lee-tan", "o-brien-co", "person", "lee-tan-3", long]) assert.match(id, CORE_ID);
  });

  test("addPerson gives each new person a free name and a matching id", () => {
    const doc = docOf([person("lee", "Lee")]);
    assert.equal(addPerson(doc), "new-person");
    assert.equal(addPerson(doc, "New person"), "new-person-2");
    assert.equal(addPerson(doc, "New person"), "new-person-3");
    assert.deepEqual(doc.contacts.slice(1).map((c) => [c.id, c.name]),
      [["new-person", "New person"], ["new-person-2", "New person 2"], ["new-person-3", "New person 3"]]);
    assert.deepEqual(findPerson(doc, "new-person"), person("new-person", "New person"));
  });

  test("addPerson compares names without case or spaces, and ids separately", () => {
    const doc = docOf([person("np", " new PERSON "), person("lee-tan", "Somebody else")]);
    assert.equal(addPerson(doc), "new-person-2");
    assert.equal(findPerson(doc, "new-person-2").name, "New person 2");
    assert.equal(addPerson(doc, "Lee Tan"), "lee-tan-2");
    assert.equal(findPerson(doc, "lee-tan-2").name, "Lee Tan");
  });

  test("nameOf and ruleName fall back to words a sentence can use", () => {
    const doc = docOf([person("lee", " Lee "), person("x", "  ")], [rule("r0", " Web ", "lee"), rule("r1", " ", "lee")]);
    assert.equal(nameOf(doc, "lee"), "Lee");
    assert.equal(nameOf(doc, "x"), "someone with no name");
    assert.equal(nameOf(doc, "ghost"), "nobody");
    assert.equal(ruleName(doc, 0), "Web");
    assert.equal(ruleName(doc, 1), "rule 2");
    assert.equal(ruleName(doc, 5), "rule 6");
  });

  test("removePerson refuses to take out the last person, or someone who is not there", () => {
    const doc = docOf([person("lee", "Lee")], [rule("r0", "All", "lee")]);
    const before = clone(doc);
    assert.deepEqual(removePerson(doc, "lee"), { error: "Keep at least one person: incidents need someone to go to.", notes: [] });
    assert.deepEqual(removePerson(doc, "ghost"), { error: "That person is not in the routing any more.", notes: [] });
    assert.deepEqual(doc, before);
  });

  test("removePerson hands their backup on, takes them off tells lists and leaves their rules without an owner", () => {
    const doc = sample();
    assert.deepEqual(removePerson(doc, "team_lead"), {
      error: "",
      notes: ["Amir's backup is now Ika", "Critical no longer tells Lee", "Attacker inside no longer tells Lee",
        "Database needs a new owner"],
    });
    assert.deepEqual(doc.contacts.map((c) => [c.id, c.backup]), [["on_duty", "it_manager"], ["it_manager", "cxo"], ["cxo", ""]]);
    assert.deepEqual(doc.rules.map((r) => [r.owner, r.notify]),
      [["on_duty", ["it_manager", "cxo"]], ["on_duty", ["it_manager"]], ["", []], ["on_duty", []]]);
    assert.deepEqual(texts(problems(doc), "error"), ["Rule 3 (Database) has no owner. Drag its owner handle onto a person."]);
  });

  test("removePerson never makes someone their own backup", () => {
    const doc = docOf([person("a", "Ann", { backup: "b" }), person("b", "Bob", { backup: "a" })], [rule("r0", "", "a", { notify: ["b"] })]);
    assert.deepEqual(removePerson(doc, "b").notes, ["Ann's backup is now nobody", "rule 1 no longer tells Bob"]);
    assert.equal(findPerson(doc, "a").backup, "");
  });

  test("removePerson passes on no backup that is not there: their own, or someone already gone", () => {
    for (const backup of ["b", "ghost"]) {
      const doc = docOf([person("a", "Ann", { backup: "b" }), person("b", "Bob", { backup }), person("c", "Cy")]);
      assert.deepEqual(removePerson(doc, "b").notes, ["Ann's backup is now nobody"]);
      assert.equal(findPerson(doc, "a").backup, "", backup);
    }
  });

  test("setRole: one person per role, and taking a role away touches nobody else", () => {
    const doc = sample();
    setRole(doc, "cxo", "on_duty");
    assert.deepEqual(doc.contacts.map((c) => c.role), ["", "team_lead", "it_manager", "on_duty"]);
    setRole(doc, "team_lead", "");
    assert.deepEqual(doc.contacts.map((c) => c.role), ["", "", "it_manager", "on_duty"]);
    setRole(doc, "it_manager", "it_manager");
    assert.deepEqual(doc.contacts.map((c) => c.role), ["", "", "it_manager", "on_duty"]);
  });
});

// ------------------------------------------------------------------ rules

describe("rules", () => {
  test("addRule puts a new rule with no conditions where it is asked, with a free name and a new key", () => {
    const doc = sample();
    const first = addRule(doc, 1, "cxo");
    assert.equal(doc.rules[1], first);
    assert.deepEqual({ ...first, key: "" }, { key: "", name: "New rule", match: {}, owner: "cxo", notify: [] });
    assert.match(first.key, /^n\d+$/);
    const second = addRule(doc, 99, "ghost"); // past the end: last; an owner nobody knows: the first person
    assert.equal(doc.rules.at(-1), second);
    assert.equal(second.name, "New rule 2");
    assert.equal(second.owner, "on_duty");
    assert.equal(addRule(doc, -3, "").key, doc.rules[0].key);
    assert.equal(new Set(doc.rules.map((r) => r.key)).size, doc.rules.length);
    assert.equal(addRule(docOf([]), 0, "x").owner, "");
  });

  test("newRuleIndex: just above a final catch-all, so it keeps catching the rest", () => {
    const doc = sample();
    assert.equal(newRuleIndex(doc), 3);
    addRule(doc, newRuleIndex(doc), "team_lead");
    assert.deepEqual(doc.rules.map((r) => r.name), ["Critical", "Attacker inside", "Database", "New rule", "Everything else"]);
    doc.rules.pop();
    assert.equal(newRuleIndex(doc), 3); // the new last rule has no conditions either: above it
    doc.rules[3].match = { severity: ["low"] };
    assert.equal(newRuleIndex(doc), 4); // the last rule has conditions: at the end
    assert.equal(newRuleIndex(docOf([person("a", "A")])), 0);
  });

  test("reserveKeys: rules added after a draft comes back never reuse its keys", () => {
    const doc = sample();
    const n = Number(addRule(doc, 0, "cxo").key.slice(1));
    reserveKeys({ rules: [{ key: "r0" }, { key: `n${n + 50}` }, { key: "n2" }, { key: "nope" }] });
    assert.equal(addRule(doc, 0, "cxo").key, `n${n + 51}`);
  });
});

// ------------------------------------------------------------------ lines on the map

describe("connect and disconnect", () => {
  test("owner: the new owner stops being merely told, and the same owner again changes nothing", () => {
    const doc = sample();
    assert.equal(connect(doc, "owner", 0, "cxo"), "Boss now owns Critical.");
    assert.deepEqual([doc.rules[0].owner, doc.rules[0].notify], ["cxo", ["team_lead", "it_manager"]]);
    assert.equal(connect(doc, "owner", 0, "cxo"), "");
    assert.equal(connect(doc, "owner", 2, "ghost"), "");
    assert.equal(connect(doc, "owner", 9, "cxo"), "");
    assert.equal(doc.rules[2].owner, "team_lead");
  });

  test("tell: once per person, and never the owner", () => {
    const doc = sample();
    assert.equal(connect(doc, "tell", 2, "cxo"), "Database now also tells Boss.");
    assert.equal(connect(doc, "tell", 2, "cxo"), "");
    assert.equal(connect(doc, "tell", 2, "team_lead"), "");
    assert.deepEqual(doc.rules[2].notify, ["cxo"]);
  });

  test("backup: nobody backs themselves up, and a line that is already there is not drawn twice", () => {
    const doc = sample();
    assert.equal(connect(doc, "backup", "cxo", "on_duty"), "Amir now backs up Boss.");
    assert.equal(findPerson(doc, "cxo").backup, "on_duty");
    assert.equal(connect(doc, "backup", "cxo", "on_duty"), "");
    assert.equal(connect(doc, "backup", "it_manager", "it_manager"), "");
    assert.equal(findPerson(doc, "it_manager").backup, "cxo");
    assert.equal(connect(doc, "backup", "ghost", "cxo"), "");
    assert.equal(connect(doc, "backup", "cxo", "ghost"), "");
  });

  test("a rule with no name is called by its number", () => {
    const doc = sample();
    doc.rules[1].name = "  ";
    assert.equal(connect(doc, "tell", 1, "cxo"), "rule 2 now also tells Boss.");
  });

  test("disconnect takes a line away only when it is there", () => {
    const doc = sample();
    assert.equal(disconnect(doc, "owner", 2, "cxo"), "");
    assert.equal(disconnect(doc, "owner", 2, "team_lead"), "Database has no owner now. Connect someone before saving.");
    assert.equal(doc.rules[2].owner, "");
    assert.equal(disconnect(doc, "tell", 2, "cxo"), "");
    assert.equal(disconnect(doc, "tell", 0, "cxo"), "Critical no longer tells Boss.");
    assert.deepEqual(doc.rules[0].notify, ["team_lead", "it_manager"]);
    assert.equal(disconnect(doc, "backup", "on_duty"), "Amir has no backup now.");
    assert.equal(findPerson(doc, "on_duty").backup, "");
    assert.equal(disconnect(doc, "backup", "on_duty"), "");
    assert.equal(disconnect(doc, "backup", "ghost"), "");
    assert.equal(disconnect(doc, "tell", 9, "cxo"), "");
  });
});

// ------------------------------------------------------------------ what stops a save

describe("problems", () => {
  test("a good routing has none", () => {
    assert.deepEqual(problems(sample()), []);
  });

  test("no people", () => {
    assert.deepEqual(problems(docOf([])), [{ level: "error", text: "Add at least one person.", kind: "", key: "" }]);
  });

  test("too many people or rules", () => {
    const many = Array.from({ length: MAX_PEOPLE + 1 }, (_, i) => person(`p${i}`, `Person ${i}`));
    assert.deepEqual(texts(problems(docOf(many)), "error"), [`At most ${MAX_PEOPLE} people.`]);
    assert.deepEqual(texts(problems(docOf(many.slice(0, MAX_PEOPLE))), "error"), []);
    const rules = Array.from({ length: MAX_RULES + 1 }, (_, i) => rule(`r${i}`, `Rule ${i}`, "p0"));
    assert.deepEqual(texts(problems(docOf(many.slice(0, 1), rules)), "error"), [`At most ${MAX_RULES} rules.`]);
    assert.deepEqual(texts(problems(docOf(many.slice(0, 1), rules.slice(0, MAX_RULES))), "error"), []);
  });

  test("a person with no name", () => {
    const doc = sample();
    doc.contacts[2].name = "   ";
    assert.deepEqual(problems(doc), [{ level: "error", text: "A person has no name.", kind: "person", key: "p:it_manager" }]);
  });

  test("two people with the same name, whatever the case and spaces: the second one is pointed at", () => {
    const doc = sample();
    doc.contacts[3].name = " LEE ";
    assert.deepEqual(problems(doc),
      [{ level: "error", text: "Two people are called LEE. Give each a different name.", kind: "person", key: "p:cxo" }]);
  });

  test("an email that does not look like one (spaces around a good one are fine)", () => {
    for (const email of ["lee", "lee@", "@example.com", "lee@example", "lee@example.", "lee@exa mple.com", "lee@@example.com"]) {
      const doc = sample();
      doc.contacts[1].email = email;
      assert.deepEqual(problems(doc),
        [{ level: "error", text: "Lee's email doesn't look like an email address.", kind: "person", key: "p:team_lead" }], email);
    }
    for (const email of ["", "lee@example.com", "  lee@example.com ", "lee.tan+alerts@mail.example.org"]) {
      const doc = sample();
      doc.contacts[1].email = email;
      assert.deepEqual(problems(doc), [], email);
    }
  });

  test("text longer than the core takes (exactly MAX_TEXT is fine)", () => {
    const long = "x".repeat(MAX_TEXT + 1);
    const doc = sample();
    Object.assign(doc.contacts[1], { email: `${"a".repeat(MAX_TEXT - 11)}@example.com`, telegram: `@${"t".repeat(MAX_TEXT)}`,
      role: "r".repeat(MAX_TEXT + 1) });
    doc.contacts[2].name = long;
    assert.deepEqual(problems(doc).map((p) => [p.text, p.key]), [
      [`Lee's email is longer than ${MAX_TEXT} characters.`, "p:team_lead"],
      [`Lee's Telegram is longer than ${MAX_TEXT} characters.`, "p:team_lead"],
      [`Lee's role is longer than ${MAX_TEXT} characters.`, "p:team_lead"],
      [`${long}'s name is longer than ${MAX_TEXT} characters.`, "p:it_manager"],
    ]);
    const ok = sample(); // spaces around do not count: the core trims before it measures
    Object.assign(ok.contacts[1], { name: ` ${"n".repeat(MAX_TEXT)}  `, telegram: `@${"t".repeat(MAX_TEXT - 1)}`, role: "r".repeat(MAX_TEXT) });
    ok.rules[2].name = "d".repeat(MAX_TEXT);
    ok.rules[2].match = { host: ["h".repeat(MAX_TEXT)] };
    assert.deepEqual(problems(ok), []);
  });

  test("someone who is their own backup, or whose backup is gone", () => {
    const doc = sample();
    doc.contacts[1].backup = "ghost";
    assert.deepEqual(problems(doc),
      [{ level: "error", text: "Lee's backup is not one of the people any more.", kind: "person", key: "p:team_lead" }]);
    doc.contacts[1].backup = "team_lead";
    assert.ok(problems(doc).some((p) => p.level === "error" && p.text === "Lee can't be their own backup." && p.key === "p:team_lead"));
  });

  test("a self-backup is reported once, as an error, not also as a backup circle",
    () => {
      const doc = sample();
      doc.contacts[1].backup = "team_lead";
      const report = problems(doc);
      assert.deepEqual(report.filter((p) => p.key === "p:team_lead").map((p) => p.text), ["Lee can't be their own backup."]);
      assert.ok(report.every((p) => /^\S/.test(p.text)), "every problem starts with a word");
    });

  test("rules with no name, a name or machine name too long, or no owner", () => {
    const doc = sample();
    doc.rules[0].name = " ";
    doc.rules[1].name = "n".repeat(MAX_TEXT + 1);
    doc.rules[2].match = { host: ["db-*", "h".repeat(MAX_TEXT + 1)] };
    doc.rules[2].owner = "";
    doc.rules[3].owner = "ghost";
    assert.deepEqual(problems(doc), [
      { level: "error", text: "Rule 1 has no name.", kind: "rule", key: "r0" },
      { level: "error", text: `Rule 2 (${"n".repeat(MAX_TEXT + 1)}): the name is longer than ${MAX_TEXT} characters.`, kind: "rule", key: "r1" },
      { level: "error", text: "Rule 3 (Database) has no owner. Drag its owner handle onto a person.", kind: "rule", key: "r2" },
      { level: "error", text: `Rule 3 (Database): a machine name is longer than ${MAX_TEXT} characters.`, kind: "rule", key: "r2" },
      { level: "error", text: "Rule 4 (Everything else) has no owner. Drag its owner handle onto a person.", kind: "rule", key: "r3" },
    ]);
    const unnamed = sample();
    Object.assign(unnamed.rules[1], { name: "", owner: "" });
    assert.deepEqual(texts(problems(unnamed)), ["Rule 2 has no name.", "Rule 2 has no owner. Drag its owner handle onto a person."]);
  });

  test("follow-up numbers out of range", () => {
    const messages = {
      escalate_after_reminders: "Follow-up: reminders before the backup takes over must be a whole number from 1 to 20.",
      max_escalations: "Follow-up: hand-overs must be a whole number from 0 to 20.",
      resolve_within_hours: "Follow-up: hours must be a number from 0 to 720.",
    };
    const bad = { escalate_after_reminders: [0, 21, 2.5, -1, NaN, Infinity], max_escalations: [-1, 21, 1.5, NaN],
      resolve_within_hours: [-1, 720.5, 721, NaN, Infinity] };
    const good = { escalate_after_reminders: [1, 20], max_escalations: [0, 20], resolve_within_hours: [0, 0.5, 720] };
    for (const [field, values] of Object.entries(bad)) {
      for (const v of values) {
        const doc = sample();
        doc.follow_up[field] = v;
        assert.deepEqual(problems(doc), [{ level: "error", text: messages[field], kind: "follow", key: "" }], `${field} = ${v}`);
      }
    }
    for (const [field, values] of Object.entries(good)) {
      for (const v of values) {
        const doc = sample();
        doc.follow_up[field] = v;
        assert.deepEqual(problems(doc), [], `${field} = ${v}`);
      }
    }
  });

  test("warning: rules under a catch-all never run", () => {
    const doc = sample();
    doc.rules[2].match = {};
    assert.deepEqual(problems(doc), [{
      level: "warning", kind: "rule", key: "r2",
      text: "The rule below Database never runs: it has no conditions, so it catches every incident first. "
        + "Give it some, or drag it to the bottom.",
    }]);
    doc.rules[1].match = { host: [" "] };
    assert.deepEqual(problems(doc).map((p) => [p.level, p.key, p.text.slice(0, 50)]),
      [["warning", "r1", "The 2 rules below Attacker inside never run: it ha"]]);
  });

  test("warning: no catch-all at the end, so the first person gets what no rule matches", () => {
    const doc = sample();
    doc.rules.pop();
    const warning = {
      level: "warning", kind: "", key: "",
      text: "Incidents that no rule matches go to Amir (the first person). To choose someone else, end with a rule that has no conditions.",
    };
    assert.deepEqual(problems(doc), [warning]);
    doc.rules = [];
    assert.deepEqual(problems(doc), [warning]);
  });

  test("warning: people who back each other up in a circle", () => {
    const doc = sample();
    findPerson(doc, "cxo").backup = "it_manager";
    assert.deepEqual(problems(doc), [{
      level: "warning", kind: "person", key: "p:it_manager",
      text: "Ika and Boss back each other up: an incident nobody answers goes round them until the hand-over limit.",
    }]);
    findPerson(doc, "cxo").backup = "on_duty";
    assert.deepEqual(problems(doc), [{
      level: "warning", kind: "person", key: "p:on_duty",
      text: "Amir, Lee, Ika and Boss back each other up in a circle: an incident nobody answers goes round them until the hand-over limit.",
    }]);
  });

  test("errors come before warnings, each pointing at its box", () => {
    const doc = sample();
    doc.rules.pop();
    doc.contacts[0].email = "nope";
    assert.deepEqual(problems(doc).map((p) => [p.level, p.key]), [["error", "p:on_duty"], ["warning", ""]]);
  });
});

// ------------------------------------------------------------------ backups and the people column

describe("backupLoops and peopleOrder", () => {
  test("backupLoops finds each circle once, from the first person in it", () => {
    const doc = docOf([
      person("f", "F", { backup: "a" }), person("a", "A", { backup: "b" }), person("b", "B", { backup: "a" }),
      person("c", "C", { backup: "d" }), person("d", "D", { backup: "e" }), person("e", "E", { backup: "c" }),
      person("g", "G", { backup: "ghost" }), person("h", "H"),
    ]);
    assert.deepEqual(backupLoops(doc), [["a", "b"], ["c", "d", "e"]]);
    assert.deepEqual(backupLoops(sample()), []);
  });

  test("peopleOrder: each rule's owner with their backups, then the people told, then the rest, each once", () => {
    const doc = docOf(
      [person("x", "X"), person("y", "Y", { backup: "x" }), person("z", "Z"), person("a", "A"), person("b", "B", { backup: "z" }),
        person("c", "C", { backup: "c" })],
      [rule("r0", "One", "b", { notify: ["y", "b"] }), rule("r1", "Two", "ghost"), rule("r2", "Three", "z")],
    );
    assert.deepEqual(peopleOrder(doc), ["b", "z", "y", "x", "a", "c"]);
    assert.deepEqual(peopleOrder(sample()), ["on_duty", "team_lead", "it_manager", "cxo"]);
  });
});

// ------------------------------------------------------------------ where the boxes go

describe("layout", () => {
  test("layoutAll: the incident, the rules in order, then the people, the columns centred on each other", () => {
    assert.deepEqual(layoutAll(sample(), size), {
      r0: { x: 194, y: 0 }, r1: { x: 194, y: 80 }, r2: { x: 194, y: 160 }, r3: { x: 194, y: 240 },
      "p:on_duty": { x: 566, y: 11 }, "p:team_lead": { x: 566, y: 87 }, "p:it_manager": { x: 566, y: 163 }, "p:cxo": { x: 566, y: 239 },
      incident: { x: 0, y: 130 },
    });
  });

  test("layoutAll without rules leaves room for one", () => {
    assert.deepEqual(layoutAll(docOf([person("a", "A")]), size), { "p:a": { x: 546, y: 0 }, incident: { x: 0, y: 5 } });
    assert.deepEqual(layoutAll(docOf([]), size), { incident: { x: 0, y: 0 } });
  });

  test("placeMissing puts new rules under the lowest rule and new people under the lowest person", () => {
    const pos = { r0: { x: 300, y: 10 }, "p:on_duty": { x: 700, y: 0 } };
    const out = placeMissing(sample(), pos, size);
    assert.equal(out, pos);
    assert.deepEqual(pos, {
      r0: { x: 300, y: 10 }, r1: { x: 300, y: 90 }, r2: { x: 300, y: 170 }, r3: { x: 300, y: 250 },
      "p:on_duty": { x: 700, y: 0 }, "p:team_lead": { x: 700, y: 70 }, "p:it_manager": { x: 700, y: 140 }, "p:cxo": { x: 700, y: 210 },
      incident: { x: 106, y: 140 }, // left of the rules, level with their middle
    });
  });

  test("placeMissing leaves placed boxes alone and starts empty columns at the top", () => {
    const pos = placeMissing(sample(), { incident: { x: -50, y: -50 } }, size);
    assert.deepEqual(pos, {
      incident: { x: -50, y: -50 },
      r0: { x: 194, y: 0 }, r1: { x: 194, y: 80 }, r2: { x: 194, y: 160 }, r3: { x: 194, y: 240 },
      "p:on_duty": { x: 566, y: 0 }, "p:team_lead": { x: 566, y: 70 }, "p:it_manager": { x: 566, y: 140 }, "p:cxo": { x: 566, y: 210 },
    });
    const doc = sample();
    const p = layoutAll(doc, size);
    const before = clone(p);
    placeMissing(doc, p, size);
    assert.deepEqual(p, before);
  });

  test("rulesFollowY compares the middles of the boxes", () => {
    const doc = sample();
    const pos = layoutAll(doc, size);
    assert.equal(rulesFollowY(doc, pos, size), true);
    pos.r2.y = 70; // its middle is above r1's
    assert.equal(rulesFollowY(doc, pos, size), false);
    const tall = (k) => (k === "r0" ? { w: 240, h: 200 } : size(k));
    const two = docOf([person("a", "A")], [rule("r0", "Tall", "a"), rule("r1", "Short", "a")]);
    assert.equal(rulesFollowY(two, { r0: { x: 0, y: 0 }, r1: { x: 0, y: 50 } }, tall), false); // top lower, middle higher
    assert.equal(rulesFollowY(two, { r0: { x: 0, y: 0 }, r1: { x: 0, y: 50 } }, size), true);
    assert.equal(rulesFollowY(two, { r0: { x: 0, y: 7 }, r1: { x: 300, y: 7 } }, size), true); // level: still in order
  });

  test("sortRulesByY puts the rules in their order on the map; ties keep their order, boxes without a place go last", () => {
    const doc = sample();
    const pos = { r0: { x: 0, y: 200 }, r1: { x: 0, y: 0 }, r2: { x: 0, y: 100 } };
    assert.equal(sortRulesByY(doc, pos, size), true);
    assert.deepEqual(doc.rules.map((r) => r.key), ["r1", "r2", "r0", "r3"]);
    assert.equal(sortRulesByY(doc, pos, size), false);
    const tied = sample();
    assert.equal(sortRulesByY(tied, { r0: { x: 0, y: 5 }, r1: { x: 0, y: 5 }, r2: { x: 0, y: 5 }, r3: { x: 0, y: 5 } }, size), false);
    assert.deepEqual(tied.rules.map((r) => r.key), ["r0", "r1", "r2", "r3"]);
  });

  test("restackRules stacks the rules in file order from the top one, each keeping its left edge", () => {
    const doc = sample();
    doc.rules.pop();
    const pos = { r0: { x: 300, y: 200 }, r2: { x: 310, y: 50 }, "p:cxo": { x: 9, y: 9 } };
    restackRules(doc, pos, size);
    assert.deepEqual(pos, { r0: { x: 300, y: 50 }, r1: { x: 300, y: 130 }, r2: { x: 310, y: 210 }, "p:cxo": { x: 9, y: 9 } });
    const none = {};
    restackRules(doc, none, size);
    assert.deepEqual(none, { r0: { x: 0, y: 0 }, r1: { x: 0, y: 80 }, r2: { x: 0, y: 160 } });
    const empty = { incident: { x: 1, y: 1 } };
    restackRules(docOf([person("a", "A")]), empty, size);
    assert.deepEqual(empty, { incident: { x: 1, y: 1 } });
  });
});

// ------------------------------------------------------------------ ids for new people

describe("settleIds", () => {
  /** The sample plus three people added since the last save, renamed and connected. */
  function edited() {
    const base = sample();
    const doc = clone(base);
    const a = addPerson(doc);
    const b = addPerson(doc);
    const c = addPerson(doc);
    findPerson(doc, a).name = "Lee Tan";
    findPerson(doc, b).name = "New person"; // free again now that the first one is Lee Tan
    findPerson(doc, c).name = "CXO"; // "cxo" is a saved id
    connect(doc, "backup", "on_duty", a);
    connect(doc, "backup", a, b);
    connect(doc, "backup", c, "on_duty");
    connect(doc, "tell", 0, b);
    connect(doc, "owner", 2, a);
    const pos = { incident: { x: 0, y: 0 }, r0: { x: 1, y: 1 }, "p:on_duty": { x: 2, y: 2 },
      [pkey(a)]: { x: 3, y: 3 }, [pkey(b)]: { x: 4, y: 4 }, [pkey(c)]: { x: 5, y: 5 } };
    return { base, doc, pos, ids: [a, b, c] };
  }

  test("people added since the last save take their id from the name they ended up with", () => {
    const { base, doc, pos, ids } = edited();
    assert.deepEqual(ids, ["new-person", "new-person-2", "new-person-3"]);
    const out = settleIds(base, doc, pos);
    assert.deepEqual([...out.renamed], [["new-person", "lee-tan"], ["new-person-2", "new-person"], ["new-person-3", "cxo-2"]]);
    assert.deepEqual(out.doc.contacts.map((c) => [c.id, c.name, c.backup]), [
      ["on_duty", "Amir", "lee-tan"], ["team_lead", "Lee", "it_manager"], ["it_manager", "Ika", "cxo"], ["cxo", "Boss", ""],
      ["lee-tan", "Lee Tan", "new-person"], ["new-person", "New person", ""], ["cxo-2", "CXO", "on_duty"],
    ]);
  });

  test("backups, owners, the people told and positions follow the new ids", () => {
    const { base, doc, pos } = edited();
    const out = settleIds(base, doc, pos);
    assert.deepEqual(out.doc.rules.map((r) => [r.owner, r.notify]), [
      ["on_duty", ["team_lead", "it_manager", "cxo", "new-person"]], ["on_duty", ["team_lead", "it_manager"]],
      ["lee-tan", []], ["on_duty", []],
    ]);
    assert.deepEqual(out.pos, { incident: { x: 0, y: 0 }, r0: { x: 1, y: 1 }, "p:on_duty": { x: 2, y: 2 },
      "p:lee-tan": { x: 3, y: 3 }, "p:new-person": { x: 4, y: 4 }, "p:cxo-2": { x: 5, y: 5 } });
    assert.deepEqual(problems(out.doc), []);
    const routing = toRouting(out.doc, out.pos);
    assert.deepEqual(Object.keys(routing.layout.contacts), ["on_duty", "team_lead", "it_manager", "cxo", "lee-tan", "new-person", "cxo-2"]);
  });

  test("saved ids stay as they are, all ids stay unique, and what it was given is left alone", () => {
    const { base, doc, pos } = edited();
    const before = clone({ doc, pos });
    const out = settleIds(base, doc, pos);
    assert.deepEqual({ doc, pos }, before);
    assert.notEqual(out.doc, doc);
    assert.deepEqual(out.doc.contacts.slice(0, 4).map((c) => c.id), base.contacts.map((c) => c.id));
    assert.equal(new Set(out.doc.contacts.map((c) => c.id)).size, out.doc.contacts.length);
    for (const c of out.doc.contacts) assert.match(c.id, CORE_ID);
  });

  test("new people whose names make the same id get -2, -3; a blank name becomes person", () => {
    const base = docOf([person("lee", "Lee")]);
    const doc = clone(base);
    findPerson(doc, addPerson(doc)).name = "Lee Tan";
    findPerson(doc, addPerson(doc)).name = "Lee-Tan";
    findPerson(doc, addPerson(doc)).name = "  ";
    findPerson(doc, addPerson(doc)).name = "LEE";
    assert.deepEqual(settleIds(base, doc).doc.contacts.map((c) => c.id), ["lee", "lee-tan", "lee-tan-2", "person", "lee-2"]);
  });

  test("with nobody new, nothing changes", () => {
    const base = sample();
    const doc = clone(base);
    doc.contacts[1].name = "Lee Tan"; // a saved person keeps their id whatever their name
    const out = settleIds(base, doc, { r0: { x: 1, y: 2 } });
    assert.equal(out.renamed.size, 0);
    assert.deepEqual(out.doc, doc);
    assert.deepEqual(out.pos, { r0: { x: 1, y: 2 } });
  });

  test("a new person never gets the id of someone removed in the same edit",
    () => {
      const base = docOf([person("amir", "Amir"), person("lee", "Lee")], [rule("r0", "All", "amir", { notify: ["lee"] })]);
      const doc = clone(base);
      removePerson(doc, "lee");
      findPerson(doc, addPerson(doc)).name = "Lee";
      const out = settleIds(base, doc, {});
      assert.notEqual(out.doc.contacts.find((c) => c.name === "Lee").id, "lee");
    });
});

// ------------------------------------------------------------------ the words for the toast and the audit log

describe("summarize and summaryText", () => {
  test("nothing changed but the map", () => {
    const base = sample();
    assert.deepEqual(summarize(base, clone(base), LABELS), []);
    assert.equal(summaryText([]), "Moved things around on the map");
  });

  test("people: added, removed, renamed, a new backup or none, new details", () => {
    const base = sample();
    const doc = clone(base);
    addPerson(doc, "Kim");
    findPerson(doc, addPerson(doc, "Temp")).name = " ";
    removePerson(doc, "cxo"); // Ika loses her backup, Critical stops telling Boss
    findPerson(doc, "team_lead").name = "Lee Tan";
    connect(doc, "backup", "on_duty", "it_manager");
    findPerson(doc, "it_manager").telegram = "@ika";
    assert.deepEqual(summarize(base, doc, LABELS), [
      "added Kim", "added a person", "removed Boss", "Amir's backup is Ika", "renamed Lee to Lee Tan", "Ika has no backup",
      "updated Ika's details", "Critical no longer tells Boss",
    ]);
  });

  test("a new role, email or Telegram each count as new details", () => {
    const base = sample();
    for (const [field, value] of [["role", "cxo"], ["email", "lee@example.com"], ["telegram", "@lee"]]) {
      const doc = clone(base);
      findPerson(doc, "team_lead")[field] = value;
      assert.deepEqual(summarize(base, doc, LABELS), ["updated Lee's details"], field);
    }
    const spaces = clone(base);
    findPerson(spaces, "on_duty").email = " amir@example.com  "; // the same once trimmed, as it is saved
    assert.deepEqual(summarize(base, spaces, LABELS), []);
  });

  test("rules: added, deleted, renamed, a new owner, told or not, new conditions, a new order, the follow-up", () => {
    const base = sample();
    const doc = clone(base);
    addRule(doc, newRuleIndex(doc), "team_lead");
    doc.rules.splice(2, 1); // Database
    doc.rules[0].name = "Very critical";
    connect(doc, "owner", 1, "team_lead");
    disconnect(doc, "tell", 0, "cxo");
    connect(doc, "tell", 3, "cxo");
    doc.rules[1].match = { category: ["malware"], severity: ["critical"] };
    doc.rules[0].match = {};
    doc.rules.splice(0, 2, doc.rules[1], doc.rules[0]);
    doc.follow_up.max_escalations = 5;
    const changes = summarize(base, doc, LABELS);
    assert.deepEqual(changes, [
      "added rule New rule", "deleted rule Database", "Attacker inside goes to Lee", "Attacker inside no longer tells Lee",
      "Attacker inside now catches Malware found · critical severity", "renamed rule Critical to Very critical",
      "Very critical no longer tells Boss", "Very critical now catches everything", "Everything else now also tells Boss",
      "changed the rule order", "changed the follow-up",
    ]);
    assert.equal(summaryText(changes), "Added rule New rule; deleted rule Database; Attacker inside goes to Lee; and 8 more changes");
  });

  test("adding or deleting a rule is not a new order; moving one is", () => {
    const base = sample();
    const deleted = clone(base);
    deleted.rules.splice(1, 1);
    assert.deepEqual(summarize(base, deleted, LABELS), ["deleted rule Attacker inside"]);
    const added = clone(base);
    addRule(added, 1, "cxo");
    assert.deepEqual(summarize(base, added, LABELS), ["added rule New rule"]);
    const moved = clone(base);
    moved.rules.push(moved.rules.shift());
    assert.deepEqual(summarize(base, moved, LABELS), ["changed the rule order"]);
  });

  test("summaryText: the first three, how many more, and a capital letter", () => {
    assert.equal(summaryText(["added Kim"]), "Added Kim");
    assert.equal(summaryText(["a", "b", "c"]), "A; b; c");
    assert.equal(summaryText(["a", "b", "c", "d"]), "A; b; c; and 1 more change");
    assert.equal(summaryText(["a", "b", "c", "d", "e"]), "A; b; c; and 2 more changes");
  });

  test("the same conditions in another order are not a change",
    () => {
      const base = sample();
      base.rules[1].match = { category: ["malware"], severity: ["critical"] };
      const doc = clone(base);
      doc.rules[1].match = { severity: ["critical"], category: ["malware"] }; // untick and tick a type again in the panel
      assert.deepEqual(summarize(base, doc, LABELS), []);
    });
});
