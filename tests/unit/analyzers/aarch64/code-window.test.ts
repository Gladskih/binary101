import assert from "node:assert/strict";
import { test } from "node:test";
import { createAarch64CodeWindow } from "../../../../analyzers/aarch64/code-window.js";

void test("code windows reuse nearby bytes synchronously and preserve truncated tails", async () => {
  const requests: bigint[] = [];
  const bytes = Uint8Array.from({ length: 10 }, (_, index) => index);
  const read = createAarch64CodeWindow(async address => { requests.push(address); return bytes; });

  assert.deepEqual(await read(100n), bytes.subarray(0, 4));
  assert.deepEqual(read(104n), bytes.subarray(4, 8));
  assert.deepEqual(read(108n), bytes.subarray(8));
  assert.deepEqual(read(100n), bytes.subarray(0, 4));
  await read(96n);
  await read(106n);
  await read(110n);
  assert.deepEqual(requests, [100n, 96n, 106n]);
  assert.deepEqual(await createAarch64CodeWindow(async () => new Uint8Array())(0n), new Uint8Array());
});
