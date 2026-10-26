import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewShaderRange } from "../../../../../analyzers/pe/debug/codeview-shader-ranges.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { localRecord, localRangeBytes } from "../../../../fixtures/pe-codeview-locals.js";

// DEFRANGESYMHLSL stores fixed fields, address range, gaps, then regIndices u32 offsets.
// https://github.com/microsoft/microsoft-pdb/blob/805655a28bd8198004be2ac27e6e0290121a5e89/include/cvinfo.h#L4293
const shaderPrefix = (attributes: number): number[] =>
  [...legacyU16(3), ...legacyU16(attributes), ...legacyU16(8), ...legacyU16(4)];

for (const type of [0x1150, 0x1157]) {
  void test(`Shader/DPC range ${type} bounds register indices after the gap array`, async () => {
    const warnings: string[] = [];
    const record = localRecord(type, [...shaderPrefix(0x16), ...localRangeBytes(), ...legacyU16(4),
      ...legacyU16(8), ...legacyU32(0xffffffff), ...legacyU32(9)]);
    assert.deepEqual(await readCodeViewShaderRange(legacyReader(record, warnings), type),
      { localRange: { location: { kind: "shaderRegister", registerType: 3, attributes: 0x16,
        registerOffsets: [0xffffffff, 9] }, parentOffset: 8, sizeInParent: 4, gaps: [] }, prefix: 12, gapEnd: 24 });
    assert.deepEqual(warnings, []);
  });
}

void test("Shader range without index dimensions needs no invented register offsets", async () => {
  assert.deepEqual(await readCodeViewShaderRange(legacyReader(localRecord(0x1150,
    [...shaderPrefix(0), ...localRangeBytes()])), 0x1150),
  { localRange: { location: { kind: "shaderRegister", registerType: 3, attributes: 0, registerOffsets: [] },
    parentOffset: 8, sizeInParent: 4, gaps: [] }, prefix: 12, gapEnd: 20 });
  assert.equal(await readCodeViewShaderRange(legacyReader([]), 0x1134), null);
});

void test("Shader range preserves fields when register offsets are truncated", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewShaderRange(legacyReader(localRecord(0x1157,
    [...shaderPrefix(2), ...localRangeBytes(), ...legacyU32(1)]), warnings), 0x1157);
  assert.deepEqual(parsed, { localRange: { location: { kind: "shaderRegister", registerType: 3, attributes: 2 },
    parentOffset: 8, sizeInParent: 4, gaps: [] }, prefix: 12, gapEnd: 20 });
  assert.match(warnings.join(" | "), /register offsets.*truncated/);
  const truncated = localRecord(0x1150, shaderPrefix(0).slice(0, 7));
  await assert.rejects(readCodeViewShaderRange(legacyReader(truncated), 0x1150), /bounds/);
});

void test("Shader range warns about reserved dimensionality and padding while retaining stored values", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewShaderRange(legacyReader(localRecord(0x1150,
    [...shaderPrefix(0x83), ...localRangeBytes(), ...legacyU32(1), ...legacyU32(2), ...legacyU32(3)]), warnings),
  0x1150);
  assert.deepEqual(parsed?.localRange.location,
    { kind: "shaderRegister", registerType: 3, attributes: 0x83, registerOffsets: [1, 2, 3] });
  assert.match(warnings.join(" | "), /dimensionality.*reserved/);
  assert.match(warnings.join(" | "), /attributes.*reserved/);
});
