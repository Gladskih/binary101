import assert from "node:assert/strict";
import { test } from "node:test";
import { managedGcStatistics } from "../../../renderers/managed-gc-statistics.js";

void test("explains GC roots and interruptibility without exposing address dumps", () => {
  const statistics = managedGcStatistics([{ header: { flags: 0, codeLength: 32 },
    slots: [{ kind: "register", register: 1, flags: 1 },
      { kind: "stack", base: 0, offset: 8, flags: 6 }],
    safePoints: [{ offset: 4, liveSlots: [0] }],
    interruptibleRanges: [{ startOffset: 8, endOffset: 16 }],
    transitions: [{ offset: 8, slot: 0, live: true }] }]);

  assert.deepEqual(statistics.map(statistic => statistic.value), [1, 1, 1, 1, 1, 1, 1, 1, 1, 0]);
  assert.ok(statistics.every(statistic => statistic.description.length > 20));
  assert.equal(managedGcStatistics([])[0]?.value, 0);
});

void test("counts partial GC records and methods without root slots", () => {
  const statistics = managedGcStatistics([{ header: { flags: 0, codeLength: 1 },
    slots: [], safePoints: [], interruptibleRanges: [], transitions: [], warnings: ["truncated"] }]);

  assert.equal(statistics[0]?.value, 1);
  assert.equal(statistics[1]?.value, 0);
  assert.equal(statistics[9]?.value, 1);
});
