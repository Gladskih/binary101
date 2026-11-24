import assert from "node:assert/strict";
import { test } from "node:test";
import { elfRangesCover } from "../../../../analyzers/elf/range-coverage.js";

for (const [name, spans, start, end, covered] of [
  ["empty range", [], 2n, 2n, true],
  ["inverted range", [[1n, 8n]], 3n, 2n, false],
  ["empty mapping", [], 2n, 3n, false],
  ["missing beginning", [[3n, 8n]], 2n, 8n, false],
  ["adjacent unordered spans", [[4n, 8n], [1n, 4n]], 2n, 8n, true],
  ["nested and overlapping spans", [[5n, 8n], [1n, 6n], [1n, 2n]], 2n, 8n, true],
  ["gap", [[5n, 8n], [1n, 4n]], 2n, 8n, false],
  ["missing end", [[1n, 7n]], 2n, 8n, false]
] as const) {
  void test(`tests complete range coverage across ${name}`, () => {
    const ranges = spans.map(([first, last]) => ({ start: first, end: last }));

    assert.equal(elfRangesCover(ranges, start, end), covered);
  });
}
