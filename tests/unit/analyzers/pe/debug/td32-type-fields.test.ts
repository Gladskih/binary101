import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32TypeFields } from "../../../../../analyzers/pe/debug/td32-type-fields.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

// Unchanged map2dbg Program.cs MemInstanceData/MemNestedType/MemMethods.Read.
const member = () => [...legacyU16(0x406), ...legacyU32(0x1001), ...legacyU16(3),
  ...legacyU32(2), ...legacyU32(0), ...legacyU16(8)];
void test("TD32 field lists preserve named members, nested types and method groups", async () => {
  const warnings: string[] = [];
  const parsed = await readTd32TypeFields(legacyReader([
    ...member(), 0xf2, 0xf1, ...legacyU16(0x409), ...legacyU32(0x1002), ...legacyU32(3), ...legacyU32(0),
    0xf2, 0xf1, ...legacyU16(0x408), ...legacyU16(2), ...legacyU32(0x1003), ...legacyU32(4)
  ], warnings));
  assert.deepEqual(parsed, [
    { type: 0x406, targetType: 0x1001, attributes: 3, nameIndex: 2, browserOffset: 0, offset: { value: "8" } },
    { type: 0x409, targetType: 0x1002, nameIndex: 3, browserOffset: 0 },
    { type: 0x408, count: 2, targetType: 0x1003, nameIndex: 4 }
  ]);
  assert.deepEqual(warnings, []);
});
void test("TD32 field lists stop unknown leaves and preserve prior complete members", async () => {
  const warnings: string[] = [];
  const parsed = await readTd32TypeFields(legacyReader([...member(), ...legacyU16(0x7777)], warnings));
  assert.equal(parsed.length, 1);
  assert.match(warnings.join(" | "), /Unsupported TD32 field kind/);
});
const checkTruncations = async (): Promise<void> => {
  for (let size = 1; size < member().length; size++) {
    const warnings: string[] = [];
    assert.deepEqual(await readTd32TypeFields(legacyReader(member().slice(0, size), warnings)), []);
    assert.match(warnings.join(" | "), /bounds/);
  }
};
void test("TD32 fields and padding are bounded by the record instead of guessed sizes", async () => {
  await checkTruncations();
  const warnings: string[] = [];
  assert.deepEqual(await readTd32TypeFields(legacyReader([0xf0], warnings)), []);
  assert.deepEqual(await readTd32TypeFields(legacyReader([0xf3, 0xf2], warnings)), []);
  assert.match(warnings.join(" | "), /PAD0/);
  assert.match(warnings.join(" | "), /bounds/);
  assert.deepEqual(await readTd32TypeFields(legacyReader([])), []);
});
