/* The Incidents page's tables (sentrai_ui/incident_table.mjs): the filter and the count line, run in Node with
   nothing but its built-in test runner.

     cd mvp/dashboard && node --test tests/incident_table.test.mjs

   tests/test_routing_editor_js.py runs this file under pytest, and skips it where Node 20+ is missing. */

import { describe, test } from "node:test";
import assert from "node:assert/strict";

import { countLine, filterRows, nonce } from "../sentrai_ui/incident_table.mjs";

const rows = [
  { id: "RSK-2026-001", cells: ["RSK-2026-001", "High", "Password guessing", "web-01", "Open", "On duty", "5 min", "Overdue"] },
  { id: "RSK-2026-002", cells: ["RSK-2026-002", "Critical", "Root access", "game-01", "Open", "Team lead", "1 h", "Was this you?"] },
  { id: "W-1 (40)", cells: ["W-1 (40)", "Medium", "Port scan", "web-01", "40 open", "On duty", "2 h", "In hand"] },
];

describe("incident table: filter", () => {
  test("no filter keeps every row, in order", () => {
    assert.deepEqual(filterRows(rows, ""), rows);
    assert.deepEqual(filterRows(rows, "   "), rows);
  });
  test("every word must appear somewhere in the row, any case", () => {
    assert.deepEqual(filterRows(rows, "web-01").map((r) => r.id), ["RSK-2026-001", "W-1 (40)"]);
    assert.deepEqual(filterRows(rows, "WEB on duty overdue").map((r) => r.id), ["RSK-2026-001"]);
    assert.deepEqual(filterRows(rows, "002").map((r) => r.id), ["RSK-2026-002"]);
    assert.deepEqual(filterRows(rows, "nothing-like-this"), []);
  });
  test("a missing list is an empty one", () => {
    assert.deepEqual(filterRows(undefined, "x"), []);
  });
});

describe("incident table: count line", () => {
  test("says how many are shown when not all fit", () => {
    assert.equal(countLine(25, 300, 300), "Showing 25 of 300");
    assert.equal(countLine(3, 3, 3), "3 incidents");
    assert.equal(countLine(1, 1, 1), "1 incident");
  });
  test("with a filter, says how many match out of how many", () => {
    assert.equal(countLine(2, 300, 2), "2 incidents matching (300 in all)");
    assert.equal(countLine(25, 300, 40), "Showing 25 of 40 matching (300 in all)");
  });
});

test("every event gets its own n, so one click is acted on once", () => {
  const a = nonce(), b = nonce();
  assert.notEqual(a, b);
});
