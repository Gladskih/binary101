"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getBigUint64, getSafeNumber, readDataView } from "../../analyzers/zip/io.js";
import { MockFile } from "../helpers/mock-file.js";

void test("getSafeNumber converts safe bigints and rejects large values", () => {
  assert.strictEqual(getSafeNumber(123n), 123);
  assert.strictEqual(getSafeNumber(BigInt(Number.MAX_SAFE_INTEGER) + 1n), null);
});

void test("getBigUint64 reads little-endian values", () => {
  const buf = new Uint8Array(8);
  const dv = new DataView(buf.buffer);
  dv.setBigUint64(0, 0x1122334455667788n, true);
  assert.strictEqual(getBigUint64(dv, 0), 0x1122334455667788n);
});

void test("readDataView clamps to file size and returns null when offset exceeds file", async () => {
  const file = new MockFile(new Uint8Array([1, 2, 3, 4]));
  const view = await readDataView(file, 2, 4);
  assert.ok(view);
  assert.strictEqual(view?.byteLength, 2);
  const missing = await readDataView(file, 10, 1);
  assert.strictEqual(missing, null);
});
