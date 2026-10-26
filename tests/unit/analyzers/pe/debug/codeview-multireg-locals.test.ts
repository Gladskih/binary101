import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewMultiRegisterLocal } from "../../../../../analyzers/pe/debug/codeview-multireg-locals.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { localRecord } from "../../../../fixtures/pe-codeview-locals.js";

// MANYREG{SYM_16t,SYM,SYM2}, ATTRMANYREG{SYM,SYM2}; register order is most-significant first.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h
for (const [types, prefix, expected] of [
  [[0x000c], [...legacyU16(0x1234), 2, 17, 18],
    { local: { typeIndex: 0x1234, location: { kind: "registers", registers: [17, 18] } }, nameOffset: 9 }],
  [[0x1005, 0x110a], [...legacyU32(0x1234), 2, 17, 18],
    { local: { typeIndex: 0x1234, location: { kind: "registers", registers: [17, 18] } }, nameOffset: 11 }],
  [[0x1014, 0x1117], [...legacyU32(0x1234), ...legacyU16(2), ...legacyU16(328), ...legacyU16(329)],
    { local: { typeIndex: 0x1234, location: { kind: "registers", registers: [328, 329] } }, nameOffset: 14 }],
  [[0x1025, 0x1121], [...legacyU32(0x1234), ...legacyU32(32), ...legacyU16(1), ...legacyU16(3), 2, 17, 18],
    { local: { typeIndex: 0x1234, firstLiveAddress: { offset: 32, section: 1 }, flags: 3,
      location: { kind: "registers", registers: [17, 18] } }, nameOffset: 19 }],
  [[0x1027, 0x1123, 0x1131], [...legacyU32(0x1234), ...legacyU32(32), ...legacyU16(1), ...legacyU16(3),
    ...legacyU16(2), ...legacyU16(328), ...legacyU16(329)],
    { local: { typeIndex: 0x1234, firstLiveAddress: { offset: 32, section: 1 }, flags: 3,
      location: { kind: "registers", registers: [328, 329] } }, nameOffset: 22 }]
] as const) for (const type of types) {
  void test(`Multi-register local ${type} preserves ordered registers and attributes`, async () => {
    const warnings: string[] = [];
    const parsed = await readCodeViewMultiRegisterLocal(legacyReader(localRecord(type, [...prefix]), warnings), type);
    assert.deepEqual(parsed, expected);
    assert.deepEqual(warnings, []);
  });
}

void test("Multi-register locals bound-check counted arrays and fixed prefixes", async () => {
  await assert.rejects(readCodeViewMultiRegisterLocal(legacyReader(localRecord(0x1117,
    [...legacyU32(1), ...legacyU16(0xffff)])), 0x1117), /bounds/);
  await assert.rejects(readCodeViewMultiRegisterLocal(legacyReader(localRecord(0x000c, [])), 0x000c), /bounds/);
  assert.equal(await readCodeViewMultiRegisterLocal(legacyReader([]), 0x1133), null);
});

void test("Multi-register locals retain an empty declared register array", async () => {
  assert.deepEqual(await readCodeViewMultiRegisterLocal(legacyReader(localRecord(0x110a,
    [...legacyU32(1), 0])), 0x110a),
  { local: { typeIndex: 1, location: { kind: "registers", registers: [] } }, nameOffset: 9 });
});

void test("Multi-register locals retain the high type-index bits in the 32-bit forms", async () => {
  assert.deepEqual(await readCodeViewMultiRegisterLocal(legacyReader(localRecord(0x1117,
    [...legacyU32(0xffffffff), ...legacyU16(1), ...legacyU16(328)])), 0x1117),
  { local: { typeIndex: 0xffffffff, location: { kind: "registers", registers: [328] } }, nameOffset: 12 });
});
