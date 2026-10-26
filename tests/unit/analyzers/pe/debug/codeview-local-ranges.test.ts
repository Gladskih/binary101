import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewLocalRange } from "../../../../../analyzers/pe/debug/codeview-local-ranges.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { localRecord, localRangeBytes } from "../../../../fixtures/pe-codeview-locals.js";

for (const [type, prefix, expected] of [
  [0x113f, legacyU32(15), { location: { kind: "program", program: 15 } }],
  [0x1140, [...legacyU32(15), ...legacyU32(0xffffffff)], { location: { kind: "program", program: 15 }, parentOffset: 0xffffffff }],
  [0x1141, [...legacyU16(328), ...legacyU16(1)], { location: { kind: "register", register: 328 }, attributes: 1 }],
  [0x1142, legacyU32(0xfffffff8), { location: { kind: "frameRelative", offset: -8 } }],
  [0x1143, [...legacyU16(328), ...legacyU16(0), ...legacyU32(0xfff)],
    { location: { kind: "register", register: 328 }, attributes: 0, parentOffset: 0xfff }],
  [0x1145, [...legacyU16(335), ...legacyU16(0xfff1), ...legacyU32(0xfffffff8)],
    { location: { kind: "registerRelative", register: 335, offset: -8 }, attributes: 0xfff1 }]
] as const) {
  void test(`CodeView local range ${type} preserves its location and relative gap offsets`, async () => {
    const warnings: string[] = [];
    const result = await readCodeViewLocalRange(legacyReader(localRecord(type, [...prefix, ...localRangeBytes(),
      ...legacyU16(4), ...legacyU16(8)]), warnings), type);

    assert.deepEqual(result, { localRange: { ...expected, range: { section: 1, offset: 32, length: 32 },
      gaps: [{ offset: 4, length: 8 }] } });
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView full-scope frame offsets have no invented range", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewLocalRange(
    legacyReader(localRecord(0x1144, legacyU32(0x80000000)), warnings), 0x1144);

  assert.deepEqual(parsed, { localRange: { location: { kind: "frameRelative", offset: -2147483648 }, gaps: [] } });
  assert.deepEqual(warnings, []);
  assert.equal(await readCodeViewLocalRange(legacyReader([]), 0x1146), null);
});

void test("CodeView local ranges preserve complete prefixes when later range bytes are truncated", async () => {
  const warnings: string[] = [];
  const result = await readCodeViewLocalRange(
    legacyReader(localRecord(0x1142, [...legacyU32(7), 0]), warnings), 0x1142);

  assert.deepEqual(result, { localRange: { location: { kind: "frameRelative", offset: 7 }, gaps: [] } });
  assert.match(warnings.join(" | "), /range.*bounds/);
  await assert.rejects(readCodeViewLocalRange(legacyReader(localRecord(0x1142, [0])), 0x1142), /bounds/);
});

void test("CodeView local range attributes, oversized offsets and malformed gaps are diagnosed", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x1143, [...legacyU16(328), ...legacyU16(2), ...legacyU32(0x1000),
    ...localRangeBytes(0xffffffff, 32), ...legacyU16(24), ...legacyU16(16),
    ...legacyU16(8), ...legacyU16(8), 0]);
  const parsed = await readCodeViewLocalRange(legacyReader(bytes, warnings), 0x1143);

  assert.equal(parsed?.localRange.gaps.length, 2);
  assert.match(warnings.join(" | "), /attributes.*reserved/);
  assert.match(warnings.join(" | "), /subfield.*reserved/);
  assert.match(warnings.join(" | "), /32-bit/);
  assert.match(warnings.join(" | "), /exceeds its live range/);
  assert.match(warnings.join(" | "), /overlap/);
  assert.match(warnings.join(" | "), /truncated gap/);
});

void test("CodeView full-scope tails and seeded range encodings remain visibly unsupported", async () => {
  const warnings: string[] = [];
  await readCodeViewLocalRange(legacyReader(localRecord(0x1144, [...legacyU32(0), 0]), warnings), 0x1144);
  await readCodeViewLocalRange(
    legacyReader(localRecord(0x1142, [...legacyU32(0), ...localRangeBytes(0, 0xf000)]), warnings), 0x1142);

  assert.match(warnings.join(" | "), /trailing bytes/);
  assert.match(warnings.join(" | "), /reserved length/);
});

void test("Local gaps may be adjacent and end exactly at the live-range boundary", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x1142, [...legacyU32(0), ...localRangeBytes(0xffffffff, 1),
    ...legacyU16(0), ...legacyU16(0), ...legacyU16(0), ...legacyU16(1)]);
  const result = await readCodeViewLocalRange(legacyReader(bytes, warnings), 0x1142);

  assert.deepEqual(result?.localRange.range, { offset: 0xffffffff, section: 1, length: 1 });
  assert.deepEqual(result?.localRange.gaps, [{ offset: 0, length: 0 }, { offset: 0, length: 1 }]);
  assert.deepEqual(warnings, []);
});

for (const type of [0x1150, 0x1157]) {
  void test(`Shader local range ${type} separates gap records from trailing register offsets`, async () => {
    const warnings: string[] = [];
    const parsed = await readCodeViewLocalRange(legacyReader(localRecord(type, [...legacyU16(3), ...legacyU16(1),
      ...legacyU16(8), ...legacyU16(4), ...localRangeBytes(), ...legacyU16(4), ...legacyU16(8),
      ...legacyU32(0xffffffff)]), warnings), type);
    assert.deepEqual(parsed, { localRange: { location: { kind: "shaderRegister", registerType: 3, attributes: 1,
      registerOffsets: [0xffffffff] }, parentOffset: 8, sizeInParent: 4,
    range: { offset: 32, section: 1, length: 32 }, gaps: [{ offset: 4, length: 8 }] } });
    assert.deepEqual(warnings, []);
  });
}

void test("Shader ranges diagnose an incomplete gap without reading it as a register offset", async () => {
  const warnings: string[] = [];
  const result = await readCodeViewLocalRange(legacyReader(localRecord(0x1150, [...legacyU16(3), ...legacyU16(1),
    ...legacyU16(8), ...legacyU16(4), ...localRangeBytes(), 0, ...legacyU32(0xffffffff)]), warnings), 0x1150);
  assert.deepEqual(result?.localRange.location, { kind: "shaderRegister", registerType: 3, attributes: 1,
    registerOffsets: [0xffffffff] });
  assert.deepEqual(result?.localRange.gaps, []);
  assert.match(warnings.join(" | "), /truncated gap/);
  assert.equal(await readCodeViewLocalRange(legacyReader([]), 0x1134), null);
});

// LLVM DefRangeRegisterRelIndirHeader uses signed BasePointerOffset/OffsetInUdt.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/DebugInfo/CodeView/SymbolRecord.h#L593
void test("Indirect register ranges retain signed offsets, spilled-member flags and complete gaps", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewLocalRange(legacyReader(localRecord(0x1177,
    [...legacyU16(334), ...legacyU16(0xfff1), ...legacyU32(0xfffffff8), ...legacyU32(0x80000000),
      ...localRangeBytes(), ...legacyU16(4), ...legacyU16(8)]), warnings), 0x1177),
  { localRange: { location: { kind: "registerIndirectRelative", register: 334, offset: -8, memberOffset: -2147483648 },
    attributes: 0xfff1, range: { offset: 32, section: 1, length: 32 }, gaps: [{ offset: 4, length: 8 }] } });
  assert.deepEqual(warnings, []);
});

void test("Indirect register ranges retain positive offsets and warn about reserved flags", async () => {
  const warnings: string[] = [];
  const parsed = await readCodeViewLocalRange(legacyReader(localRecord(0x1177,
    [...legacyU16(334), ...legacyU16(0x000e), ...legacyU32(7), ...legacyU32(9), ...localRangeBytes()]), warnings),
  0x1177);
  assert.deepEqual(parsed?.localRange.location,
    { kind: "registerIndirectRelative", register: 334, offset: 7, memberOffset: 9 });
  assert.match(warnings.join(" | "), /attributes.*reserved/);
});

void test("Indirect register ranges preserve fixed placement when range bytes are missing", async () => {
  const warnings: string[] = [];
  const bytes = localRecord(0x1177, [...legacyU16(334), ...legacyU16(0), ...legacyU32(0), ...legacyU32(0)]);
  assert.deepEqual(await readCodeViewLocalRange(legacyReader(bytes, warnings), 0x1177),
    { localRange: { location: { kind: "registerIndirectRelative", register: 334, offset: 0, memberOffset: 0 },
      attributes: 0, gaps: [] } });
  assert.match(warnings.join(" | "), /range.*bounds/);
  await assert.rejects(readCodeViewLocalRange(legacyReader(bytes.slice(0, -1)), 0x1177), /bounds/);
});
