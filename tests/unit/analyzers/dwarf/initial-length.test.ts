import assert from "node:assert/strict";
import { test } from "node:test";
import { readDwarfInitialLength } from "../../../../analyzers/dwarf/initial-length.js";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { concatenateBytes, encodeUint32, encodeUint64 } from "../../../fixtures/dwarf-fixture-encoding.js";

const readLength = async (bytes: number[], issues: string[] = []) => {
  const file = new MockFile(Uint8Array.from(bytes));
  return readDwarfInitialLength(new DwarfCursor(file,
    { name: "unit", offset: 0, size: file.size, compressed: false }, 0, file.size, true, issues));
};

void test("initial lengths distinguish DWARF32/64 and reject unrepresentable or truncated lengths", async () => {
  // DWARF 5 7.4: 0xffffffff selects an eight-byte length, unlike reserved 0xfffffff0.
  assert.deepEqual(await readLength(concatenateBytes(encodeUint32(1), [0])),
    { length: 1n, format: 32, end: 5 });
  assert.deepEqual(await readLength(concatenateBytes(encodeUint32(0xffffffff), encodeUint64(1), [0])),
    { length: 1n, format: 64, end: 13 });
  assert.equal(await readLength(encodeUint32(0xffffffff)), null);
  assert.equal(await readLength(concatenateBytes(encodeUint32(0xffffffff), encodeUint64(1n << 60n))), null);
  assert.equal(await readLength(encodeUint32(0xfffffff0)), null);
  assert.equal(await readLength([1]), null);
  const issues: string[] = [];
  assert.deepEqual(await readLength(encodeUint32(0), issues), { length: 0n, format: 32, end: 4 });
  assert.match(issues.join(" "), /zero-length/);
});
