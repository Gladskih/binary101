import assert from "node:assert/strict";
import { test } from "node:test";
import { locateElfHeaderTable } from "../../../../analyzers/elf/header-table-range.js";

void test("accepts exact ranges, larger strides and truncates partial entries", () => {
  const issues: string[] = [];
  assert.deepEqual(locateElfHeaderTable(100, 20n, 4, 20, 16, "Headers", issues),
    { offset: 20, count: 4 });
  assert.deepEqual(issues, []);
  assert.deepEqual(locateElfHeaderTable(99, 20n, 4, 20, 16, "Headers", issues),
    { offset: 20, count: 3 });
  assert.match(issues.join(" "), /truncated/);
});

for (const [offset, count, stride, diagnostic] of [
  [0n, 1, 16, ""], [20n, 0, 16, ""], [20n, 1, 15, "entry size"],
  [1n << 60n, 1, 16, "too large"], [-1n, 1, 16, "negative"]
] as const) {
  void test(`rejects absent or invalid header table ${offset}/${count}/${stride}`, () => {
    const issues: string[] = [];
    assert.equal(locateElfHeaderTable(100, offset, count, stride, 16, "Headers", issues), null);
    assert.equal(issues.length, diagnostic ? 1 : 0);
    assert.ok(issues.join(" ").includes(diagnostic));
  });
}

for (const offset of [100n, 101n]) {
  void test(`warns at an out-of-file table offset ${offset}`, () => {
    const issues: string[] = [];
    assert.deepEqual(locateElfHeaderTable(100, offset, 1, 16, 16, "Headers", issues),
      { offset: Number(offset), count: 0 });
    assert.match(issues.join(" "), /outside the file/);
  });
}
