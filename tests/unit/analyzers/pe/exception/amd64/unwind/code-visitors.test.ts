import assert from "node:assert/strict";
import { test } from "node:test";
import { visitAmd64UnwindCodeSlots }
  from "../../../../../../../analyzers/pe/exception/amd64/unwind-code-slots.js";

void test("slot visitors retain only the decoded prefix before an operand exceeds CountOfCodes", () => {
  const emitted: number[][] = [];
  const view = new DataView(Uint8Array.from([0xff, 1, 2, 1, 0x11, 0, 0, 0, 0]).buffer, 1, 8);
  const analysis = visitAmd64UnwindCodeSlots(view, 2, 1, (...values) => emitted.push(values));
  assert.deepEqual(emitted, [[1, 2, 0, 8]]);
  assert.equal(analysis.isTruncated, true);
  assert.deepEqual(analysis.issues, []);
  assert.equal("operations" in analysis, false);
});
