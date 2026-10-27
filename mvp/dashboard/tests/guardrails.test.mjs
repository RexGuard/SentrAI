/* Automation guardrails (sentrai_ui/limits_map.mjs) and the pipeline overview's hover tips (flow_map.mjs):
   the parts above their DOM, run in Node with nothing but its built-in test runner.

     cd mvp/dashboard && node --test tests/guardrails.test.mjs

   tests/test_routing_editor_js.py runs this file under pytest, and skips it where Node 20+ is missing. */

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import * as flow from "../sentrai_ui/flow_map.mjs";
import * as g from "../sentrai_ui/limits_map.mjs";

const actions = [["block_ip", "block an address"], ["rate_limit", "slow an address down"], ["lock_user", "lock an account"]];
const settings = { AUTO_ACTIONS: "block_ip,rate_limit", NEEDLE_MIN_CONFIDENCE: "0.6", RISK_THRESHOLD: "80",
  MAX_AUTO_ACTIONS_PER_HOUR: "10", HOTPATCH_TTL_HOURS: "2", MAX_TTL_HOURS: "24", PROTECTED_IPS: "127.0.0.1,::1,localhost",
  PROTECTED_USERS: "" };

describe("guardrails: how sure, in percent", () => {
  test("the settings file's 0 to 1 shows as 0 to 100, and goes back the same", () => {
    assert.equal(g.toPercent("0.6"), "60");
    assert.equal(g.toPercent("0.755"), "75.5");
    assert.equal(g.fromPercent("60"), "0.6");
    assert.equal(g.fromPercent("75.5"), "0.755");
    assert.equal(g.fromPercent(" "), "");
    const d = g.fromSettings(settings, actions);
    assert.equal(d.CONFIDENCE_PCT, "60");
    assert.equal(g.toSettings(d, actions).NEEDLE_MIN_CONFIDENCE, "0.6");
    assert.equal(g.toSettings({ ...d, CONFIDENCE_PCT: "85" }, actions).NEEDLE_MIN_CONFIDENCE, "0.85");
  });

  test("a percentage outside 0 to 100 is a problem; one inside is not", () => {
    const d = g.fromSettings(settings, actions);
    assert.deepEqual(g.problems({ ...d, CONFIDENCE_PCT: "100" }), []);
    assert.match(g.problems({ ...d, CONFIDENCE_PCT: "0.6x" })[0], /percentage from 0 to 100/);
    assert.equal(g.problems({ ...d, CONFIDENCE_PCT: "101" }).length, 1);
  });
});

describe("guardrails: never-touched tags", () => {
  test("a comma list becomes tags without blanks or repeats, and back", () => {
    assert.deepEqual(g.tagsOf(" 10.0.0.0/8 ,, 127.0.0.1,10.0.0.0/8 "), ["10.0.0.0/8", "127.0.0.1"]);
    assert.equal(g.joinTags(["a", "b"]), "a,b");
    assert.deepEqual(g.tagsOf(""), []);
  });

  test("addresses, networks and host names pass; typos do not", () => {
    for (const ok of ["127.0.0.1", "10.0.0.0/8", "::1", "::", "fe80::1", "2001:db8::/32", "::ffff:192.0.2.1",
      "2001:0db8:0000:0000:0000:ff00:0042:8329", "localhost", "db-1.internal"]) assert.ok(g.addressOk(ok), ok);
    for (const bad of ["10.0.0.300", "10.0.0", "10.0.0.0/33", "10.0.0.1 10.0.0.2", "1:2:3", "fe80:::1", "-bad", "a/b/c", "",
      "2001:db8::/129"]) assert.ok(!g.addressOk(bad), bad);
  });

  test("an account is one word; a bad address in the list stops Save with its name", () => {
    assert.ok(g.accountOk("backup-svc") && !g.accountOk("two words") && !g.accountOk(" "));
    const d = g.fromSettings({ ...settings, PROTECTED_IPS: "127.0.0.1,10.0.0.300" }, actions);
    assert.deepEqual(g.problems(d), ["10.0.0.300 is not an address, a network or a host name."]);
  });
});

describe("guardrails: the policy in words", () => {
  test("says when it acts, what it may do and that the rest asks a person", () => {
    const text = g.summary(g.fromSettings(settings, actions), actions);
    assert.match(text, /at least 60 % sure, the danger score is 80 or more, and it has acted fewer than 10 times/);
    assert.match(text, /may block an address and slow an address down; anything else asks a person first/);
    assert.match(text, /after 2 h/);
  });

  test("with nothing allowed it says every action waits", () => {
    assert.match(g.summary({ ...g.fromSettings(settings, actions), auto: [] }, actions), /every action waits for a person/);
  });
});

describe("overview map: hover tips", () => {
  const width = 5 * flow.COL_W + flow.BOX_W;

  test("a tip sits under a box in the top rows and over a box lower down", () => {
    const top = flow.tipAt({ x: 0, y: 0 }, width);
    assert.ok(top.below && top.y === flow.BOX_H + 6);
    const low = flow.tipAt({ x: flow.COL_W, y: 2 * flow.ROW_H }, width);
    assert.ok(!low.below && low.y === 2 * flow.ROW_H - 6);
  });

  test("a tip never leaves the stage sideways", () => {
    assert.equal(flow.tipAt({ x: 0, y: 0 }, width).x, 0);
    assert.equal(flow.tipAt({ x: 5 * flow.COL_W, y: 0 }, width).x, width - flow.TIP_W);
  });

  test("the six columns fit the room a 1440 px screen leaves next to the sidebar, so nothing shrinks", () => {
    assert.ok(width <= 1040, `stage ${width}px`);
  });
});
