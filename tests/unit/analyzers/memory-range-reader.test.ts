import assert from "node:assert/strict";
import { test } from "node:test";
import { createMemoryRangeReader } from "../../../analyzers/memory-range-reader.js";

void test("memory ranges preserve subarray origins and clamp at EOF", async () => {
  const bytes = Uint8Array.from([9, 1, 2, 3, 9]);
  const reader = createMemoryRangeReader(bytes.subarray(1, 4));
  assert.equal(reader.size, 3);
  assert.deepEqual([...await reader.readBytes(0, 3)], [1, 2, 3]);
  assert.equal((await reader.read(1, 1)).getUint8(0), 2);
  assert.deepEqual([...await reader.readBytes(2, 5)], [3]);
  assert.equal((await reader.read(3, 1)).byteLength, 0);
  assert.equal((await reader.read(4, 1)).byteLength, 0);
  assert.equal((await reader.read(0, 0)).byteLength, 0);
});
for (const [offset, size] of [[-1, 1], [0, -1], [NaN, 1], [0, Infinity], [0.5, 1], [0, 0.5]]) {
  void test(`invalid memory range ${offset}:${size} yields an empty view`, async () => {
    assert.equal((await createMemoryRangeReader(new Uint8Array(3)).read(offset!, size!)).byteLength, 0);
  });
}
