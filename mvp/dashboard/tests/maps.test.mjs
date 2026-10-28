/* The pipeline overview canvas's grid and Automation guardrails' model (sentrai_ui/flow_canvas.mjs and
   limits_map.mjs): the functions above their DOM parts, run in Node with nothing but its built-in test runner.

     cd mvp/dashboard && node --test tests/maps.test.mjs

   tests/test_routing_editor_js.py runs this file under pytest, and skips it where Node 20+ is missing. */

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import * as flow from "../sentrai_ui/flow_canvas.mjs";
import * as limits from "../sentrai_ui/limits_map.mjs";

describe("overview canvas: the grid the steps start on", () => {
  test("a step's column and row become pixels on the canvas", () => {
    assert.deepEqual(flow.gridPos({ col: 0, row: 1 }), { x: 0, y: flow.ROW_H });
    assert.deepEqual(flow.gridPos({ col: 2, row: 0.5 }), { x: 2 * flow.COL_W, y: flow.ROW_H / 2 });
  });

  test("a wire runs from the right side of one box into the left side of the next, or down a column", () => {
    const box = (x, y) => ({ x, y, w: flow.BOX_W, h: flow.BOX_H });
    const across = flow.wirePath(box(0, 0), box(flow.COL_W, 0));
    assert.match(across.d, new RegExp(`^M ${flow.BOX_W} ${flow.BOX_H / 2} C `));
    assert.equal(across.dx, 1);
    const down = flow.wirePath(box(0, 0), box(0, flow.ROW_H));
    assert.match(down.d, new RegExp(`^M ${flow.BOX_W / 2} ${flow.BOX_H} C `));
    assert.deepEqual(down.end, { x: flow.BOX_W / 2, y: flow.ROW_H });
  });

  test("the six step columns fit the room a 1440 px screen leaves next to the sidebar before anyone zooms", () => {
    assert.ok(5 * flow.COL_W + flow.BOX_W <= 1040);
  });
});

describe("limits map", () => {
  const actions = [["block_ip", "block an address"], ["rate_limit", "slow down"], ["lock_user", "lock an account"]];
  const settings = { AUTO_ACTIONS: "rate_limit, block_ip, unknown", NEEDLE_MIN_CONFIDENCE: "0.6", RISK_THRESHOLD: "80",
    MAX_AUTO_ACTIONS_PER_HOUR: "10", HOTPATCH_TTL_HOURS: "2", MAX_TTL_HOURS: "24", PROTECTED_IPS: "127.0.0.1", PROTECTED_USERS: "" };

  test("the allowed actions come in as a list of known ones, and go back in the listed order", () => {
    const d = limits.fromSettings(settings, actions);
    assert.deepEqual(d.auto, ["block_ip", "rate_limit"]);
    d.auto = ["lock_user", "block_ip"];
    assert.equal(limits.toSettings(d, actions).AUTO_ACTIONS, "block_ip,lock_user");
  });

  test("a draft that is fine has no problems; out-of-range numbers each say what to fix", () => {
    const d = limits.fromSettings(settings, actions);
    assert.deepEqual(limits.problems(d), []);
    for (const [k, v] of [["CONFIDENCE_PCT", "120"], ["RISK_THRESHOLD", "80.5"], ["MAX_AUTO_ACTIONS_PER_HOUR", ""],
      ["HOTPATCH_TTL_HOURS", "0"], ["HOTPATCH_TTL_HOURS", "48"]]) {
      assert.equal(limits.problems({ ...d, [k]: v }).length, 1, `${k}=${v}`);
    }
  });
});
