/* The pipeline overview canvas's model (sentrai_ui/flow_canvas.mjs): the functions above its DOM part, run in
   Node with nothing but its built-in test runner.

     cd mvp/dashboard && node --test tests/canvas.test.mjs

   tests/test_routing_editor_js.py runs this file under pytest, and skips it where Node 20+ is missing. */

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import * as c from "../sentrai_ui/flow_canvas.mjs";

const step = (id, col, row, state = "ok") => ({ id: `step:${id}`, kind: "step", col, row, title: id, state, what: `${id} does things.` });
const DATA = {
  blocks: [step("logs", 0, 1, "busy"), step("sort", 1, 1, "alert"), step("score", 2, 1), step("alerts", 4, 2),
    { id: "machine:web-01", kind: "machine", title: "web-01", state: "alert", what: "A machine." },
    { id: "machine:office-pc", kind: "machine", title: "office-pc", state: "ok" },
    { id: "ext:telegram", kind: "ext", step: "alerts", title: "Telegram", state: "ok", badge: "On" },
    { id: "ext:slack", kind: "ext", step: "alerts", title: "Slack", state: "off", badge: "Off" }],
  wires: [{ from: "step:logs", to: "step:sort", live: true }, { from: "step:sort", to: "step:score", live: false },
    { from: "machine:web-01", to: "step:logs", live: true }, { from: "step:alerts", to: "ext:telegram", live: false }],
  defaults: ["step:logs", "step:sort", "step:score", "step:alerts", "machine:web-01", "machine:office-pc", "ext:telegram"],
};
const fresh = (doc = {}) => c.applyDoc(DATA, doc);

describe("canvas: where blocks start", () => {
  test("steps sit on their grid, machines in a column left of the logs, an extension under its step", () => {
    const pos = c.defaultLayout(DATA.blocks, DATA.defaults);
    assert.deepEqual(pos["step:logs"], { x: 0, y: c.ROW_H });
    assert.deepEqual(pos["step:score"], { x: 2 * c.COL_W, y: c.ROW_H });
    assert.ok(pos["machine:web-01"].x < 0 && pos["machine:office-pc"].x < 0, "machines are left of the logs");
    assert.ok(pos["machine:office-pc"].y > pos["machine:web-01"].y, "machines stack");
    assert.equal(pos["ext:telegram"].x, pos["step:alerts"].x);
    assert.ok(pos["ext:telegram"].y >= pos["step:alerts"].y + c.BOX_H, "the extension hangs under its step");
  });

  test("a block put where another one is slides down until it covers nothing", () => {
    const pos = { a: { x: 0, y: 0 }, b: { x: 10, y: 20 } };
    c.clearSpot(pos, "b", c.fallbackSize, ["a"]);
    assert.ok(pos.b.y >= c.BOX_H, `b moved to y=${pos.b.y}`);
  });

  test("every block on the canvas gets a place, a saved one is kept", () => {
    const st = fresh({ pos: { "step:logs": [300, 400] } });
    assert.deepEqual(st.pos["step:logs"], { x: 300, y: 400 });
    for (const id of st.shown) assert.ok(st.pos[id], `${id} has a position`);
  });
});

describe("canvas: the saved layout", () => {
  test("a fresh canvas shows the default blocks and nothing else", () => {
    const st = fresh();
    assert.deepEqual(st.shown, DATA.defaults);
    assert.deepEqual(c.toDoc(st, DATA.defaults).hidden, []);
  });

  test("hidden default blocks stay off, added blocks and notes come back, unknown ids are dropped", () => {
    const st = fresh({ hidden: ["machine:office-pc", "step:gone"], added: ["ext:slack", "ext:nothing"], notes: { "note:3": "Check this" },
      pos: { "ext:slack": [50, 60], "note:3": ["x", 1] }, wires: { added: [["ext:slack", "step:logs"]], removed: [["step:logs", "step:sort"]] } });
    assert.ok(!st.shown.includes("machine:office-pc") && st.hidden.includes("machine:office-pc"));
    assert.ok(st.shown.includes("ext:slack") && !st.shown.includes("ext:nothing"));
    assert.ok(st.shown.includes("note:3") && st.notes["note:3"] === "Check this");
    assert.deepEqual(st.pos["ext:slack"], { x: 50, y: 60 });
    assert.ok(st.pos["note:3"], "a bad saved position is replaced");
    assert.deepEqual(st.addedWires, [{ from: "ext:slack", to: "step:logs" }]);
    assert.deepEqual(st.removedWires, [{ from: "step:logs", to: "step:sort" }]);
  });

  test("what goes to the file comes back the same", () => {
    const st = fresh({ hidden: ["step:score"], added: ["ext:slack"], notes: { "note:1": "hello" }, pos: { "step:logs": [1, 2] } });
    const doc = c.toDoc(st, DATA.defaults);
    assert.equal(doc.version, 1);
    assert.deepEqual(doc.hidden, ["step:score"]);
    assert.deepEqual(doc.added, ["ext:slack", "note:1"]);
    assert.equal(c.signature(c.applyDoc(DATA, doc), DATA.defaults), c.signature(st, DATA.defaults));
  });

  test("a machine that left stays in the layout but is not drawn, and is back when it returns", () => {
    const st = fresh({ pos: { "machine:office-pc": [5, 5] } });
    const gone = { ...DATA, blocks: DATA.blocks.filter((b) => b.id !== "machine:office-pc") };
    assert.ok(!c.visibleIds(gone, st).includes("machine:office-pc"));
    assert.ok(c.visibleIds(DATA, st).includes("machine:office-pc"));
    assert.deepEqual(st.pos["machine:office-pc"], { x: 5, y: 5 });
  });
});

describe("canvas: wires", () => {
  test("default wires join blocks that are both on the canvas; a hidden block takes its wires with it", () => {
    const st = fresh();
    assert.equal(c.wiresOf(DATA, st).length, 4);
    c.hideBlock(DATA, st, "step:sort");
    const left = c.wiresOf(DATA, st).map((w) => `${w.from}>${w.to}`);
    assert.ok(!left.some((k) => k.includes("step:sort")));
    assert.equal(left.length, 2);
  });

  test("a wire taken away is remembered; drawing it again forgets that; a wire drawn by hand is marked", () => {
    const st = fresh();
    assert.equal(c.removeWire(DATA, st, "step:logs", "step:sort"), "Wire removed.");
    assert.deepEqual(st.removedWires, [{ from: "step:logs", to: "step:sort" }]);
    assert.equal(c.wiresOf(DATA, st).length, 3);
    assert.equal(c.addWire(DATA, st, "step:logs", "step:sort"), "Connected.");
    assert.deepEqual(st.removedWires, []);
    assert.equal(c.addWire(DATA, st, "step:logs", "step:sort"), "", "a wire that is there already is not drawn twice");
    assert.equal(c.addWire(DATA, st, "step:score", "step:alerts"), "Connected.");
    const mine = c.wiresOf(DATA, st).find((w) => w.from === "step:score");
    assert.ok(mine.user && !mine.live);
    assert.equal(c.addWire(DATA, st, "step:score", "step:score"), "", "no wire from a block to itself");
  });

  test("a hand-drawn wire moves when both ends are busy", () => {
    const st = fresh();
    c.addWire(DATA, st, "machine:web-01", "step:sort");
    assert.ok(c.wiresOf(DATA, st).find((w) => w.from === "machine:web-01" && w.to === "step:sort").live);
  });

  test("a wire leaves the right side for a block to the right, and the bottom for one below", () => {
    const a = { x: 0, y: 0, w: 156, h: 140 };
    const right = c.wirePath(a, { x: 300, y: 0, w: 156, h: 140 });
    assert.match(right.d, /^M 156 70 C /);
    assert.deepEqual(right.end, { x: 300, y: 70 });
    const below = c.wirePath(a, { x: 20, y: 300, w: 156, h: 140 });
    assert.match(below.d, /^M 78 140 C /);
    assert.equal(below.dy, 1);
    const left = c.wirePath(a, { x: -400, y: 0, w: 156, h: 140 });
    assert.equal(left.dx, -1);
    assert.match(c.arrowHead(right), /^M300,70 L/);
  });
});

describe("canvas: adding and taking off", () => {
  test("a default block taken off is remembered and offered again under + Add; a note is gone for good", () => {
    const st = fresh();
    assert.match(c.hideBlock(DATA, st, "machine:office-pc"), /under \+ Add/);
    assert.deepEqual(st.hidden, ["machine:office-pc"]);
    const groups = c.catalogue(DATA, st);
    assert.deepEqual(groups.find((g) => g.kind === "machine").items.map((x) => x.id), ["machine:office-pc"]);
    assert.deepEqual(groups.find((g) => g.kind === "ext").items.map((x) => x.id), ["ext:slack"]);
    assert.deepEqual(groups.find((g) => g.kind === "step").items, []);
    const id = c.addNote(DATA, st, "remember", { x: 500, y: 500 });
    assert.equal(id, "note:1");
    assert.equal(c.hideBlock(DATA, st, id), "Note deleted.");
    assert.ok(!(id in st.notes) && !st.shown.includes(id));
    assert.equal(c.hideBlock(DATA, st, id), "", "nothing to take off twice");
  });

  test("a block put back lands where the view is and is no longer hidden", () => {
    const st = fresh({ hidden: ["step:score"] });
    assert.equal(c.showBlock(DATA, st, "step:score", { x: 1000, y: 1000 }), "Added to the canvas.");
    assert.deepEqual(st.hidden, []);
    assert.deepEqual(st.pos["step:score"], { x: 1000 - c.BOX_W / 2, y: 1000 - c.BOX_H / 2 });
    assert.equal(c.showBlock(DATA, st, "step:score"), "", "already there");
    assert.deepEqual(c.toDoc(st, DATA.defaults).added, [], "a default block put back is not an addition");
  });

  test("notes get the next free number and keep their text within bounds", () => {
    const st = fresh({ notes: { "note:1": "a", "note:2": "b" } });
    assert.equal(c.addNote(DATA, st, "x".repeat(5000)), "note:3");
    assert.equal(st.notes["note:3"].length, c.MAX_NOTE);
  });
});

describe("canvas: the panel", () => {
  const fields = [{ env: "RISK_THRESHOLD", label: "Danger", kind: "int", value: "80" },
    { env: "HOTPATCH_TTL_HOURS", label: "Hours", kind: "float", value: "2" },
    { env: "SMTP_SECURITY", label: "Security", kind: "choice", choices: ["starttls", "ssl"], value: "starttls" },
    { env: "AUTO_ACTIONS", label: "Allowed", kind: "set", choices: [["block_ip", "block"]], value: "block_ip" },
    { env: "ON_DUTY", label: "On duty", kind: "str", value: "someone" }];

  test("only changed values go to Python, trimmed", () => {
    assert.deepEqual(c.settingChanges(fields, { RISK_THRESHOLD: " 80 ", ON_DUTY: "Dana " }), { ON_DUTY: "Dana" });
  });

  test("a wrong kind of value says what to fix, in words", () => {
    assert.deepEqual(c.settingProblems(fields, { RISK_THRESHOLD: "80" }), []);
    assert.deepEqual(c.settingProblems(fields, { RISK_THRESHOLD: "8.5", HOTPATCH_TTL_HOURS: "two", SMTP_SECURITY: "tls" }),
      ["Danger must be a whole number.", "Hours must be a number.", "Security must be one of: starttls, ssl."]);
  });

  test("a block reads out its numbers, its state and what it does", () => {
    assert.equal(c.faceText({ title: "Logs come in", value: "2,716", unit: "", note: "lines read", state: "busy", what: "Every line is read." }),
      "Logs come in: 2,716, lines read. busy. Every line is read.");
    assert.equal(c.faceText({ title: "Edge", badge: "Off", state: "off" }), "Edge: Off. off.");
  });

  test("the hover tip sits under a block when there is room, over it otherwise, and never leaves the view", () => {
    const room = { w: 800, h: 500 };
    const tip = { w: 200, h: 60 };
    const under = c.tipAt({ x: 10, y: 10, w: 156, h: 140 }, room, tip);
    assert.ok(under.below && under.y === 156);
    assert.equal(under.x, 4, "kept inside on the left");
    const over = c.tipAt({ x: 700, y: 400, w: 156, h: 140 }, room, tip);
    assert.ok(!over.below && over.y === 400 - 66);
    assert.equal(over.x, 800 - 200 - 4, "kept inside on the right");
  });
});
