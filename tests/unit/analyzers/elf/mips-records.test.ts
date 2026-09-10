import assert from "node:assert/strict";
import { test } from "node:test";
import { readMipsAbiFlags, readMips32RegInfo, readMips64RegInfo } from "../../../../analyzers/elf/mips-records.js";

void test("reads all MIPS ABI flag fields at their fixed offsets", () => {
  const bytes = new Uint8Array(24);
  const view = new DataView(bytes.buffer);
  bytes.set([0, 0, 32, 2, 1, 2, 0, 5]);
  [3, 4, 5, 6].forEach((value, index) => view.setUint32(8 + index * 4, value));
  assert.deepEqual(readMipsAbiFlags(view, "big"), { version: 0, isaLevel: 32, isaRevision: 2,
    gprSize: 1, cpr1Size: 2, cpr2Size: 0, fpAbi: 5, isaExtension: 3, ases: 4, flags1: 5, flags2: 6 });
  assert.equal(readMipsAbiFlags(new DataView(bytes.buffer, 0, 23), "little"), null);
});

void test("keeps separate MIPS32 and MIPS64 register info layouts", () => {
  const view = new DataView(new ArrayBuffer(32));
  [1, 2, 3, 4, 5, 6, 7, 8].forEach((value, index) => view.setUint32(index * 4, value, true));
  assert.deepEqual(readMips32RegInfo(view, "little"), { gprMask: 1, cprMasks: [2, 3, 4, 5], gpValue: 6n });
  assert.deepEqual(readMips64RegInfo(view, "little"), { gprMask: 1, cprMasks: [3, 4, 5, 6], gpValue: 0x800000007n });
  assert.equal(readMips32RegInfo(new DataView(view.buffer, 0, 23), "little"), null);
  assert.equal(readMips64RegInfo(new DataView(view.buffer, 0, 31), "little"), null);
});
