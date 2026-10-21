import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32Types } from "../../../../../analyzers/pe/debug/td32-type-records.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

const namedType = (type: number, name: number, offset: number): number[] => {
  const bytes = new Uint8Array(offset + 4);
  bytes.set(legacyU16(bytes.length - 2));
  bytes.set(legacyU16(type), 2);
  bytes.set(legacyU32(name), offset);
  return [...bytes];
};
const types = (records: number[][]): Uint8Array => {
  let offset = 8 + records.length * 4;
  const offsets = records.map(record => { const start = offset; offset += record.length; return start; });
  return Uint8Array.from([...legacyU32(1), ...legacyU32(records.length),
    ...offsets.flatMap(legacyU32), ...records.flat()]);
};

void test("TD32 type offsets are relative to the subsection and retain shared class/enum name indices", async () => {
  const warnings: string[] = [];
  const parsed = await readTd32Types(legacyReader(types([
    namedType(4, 7, 24), namedType(5, 8, 24), namedType(7, 9, 18), [2, 0, 2, 0]
  ]), warnings));

  assert.deepEqual(parsed.records, [{ index: 0, type: 4, nameIndex: 7 },
    { index: 1, type: 5, nameIndex: 8 }, { index: 2, type: 7, nameIndex: 9 }, { index: 3, type: 2 }]);
  assert.deepEqual(warnings, []);
});

void test("TD32 does not infer type layout from unknown versions or impossible offset counts", async () => {
  const warnings: string[] = [];
  const unknown = await readTd32Types(legacyReader([...legacyU32(2), ...legacyU32(0)], warnings));
  const truncated = await readTd32Types(legacyReader([...legacyU32(1), ...legacyU32(0xffffffff)], warnings));

  assert.deepEqual(unknown.records, []);
  assert.deepEqual(truncated.records, []);
  assert.match(warnings.join(" | "), /version/);
  assert.match(warnings.join(" | "), /offset table is truncated/);
  await assert.rejects(readTd32Types(legacyReader([])), /bounds/);
});

void test("TD32 type framing rejects overlapping headers, short records and sizes beyond the subsection", async () => {
  const warnings: string[] = [];
  const bytes = types([[0, 0, 4, 0], [255, 255, 5, 0], [2, 0, 7, 0], [2, 0, 2, 0]]);
  bytes.set(legacyU32(4), 8);
  bytes.set(legacyU32(bytes.length - 1), 20);
  const parsed = await readTd32Types(legacyReader(bytes, warnings));

  assert.deepEqual(parsed.records, [{ index: 2, type: 7 }]);
  assert.match(warnings.join(" | "), /offset overlaps/);
  assert.match(warnings.join(" | "), /length exceeds/);
  assert.match(warnings.join(" | "), /name.*bounds/);
  assert.match(warnings.join(" | "), /bounds/);
});

void test("TD32 caches repeated type offsets, including malformed records", async () => {
  const bytes = types([[2, 0, 2, 0], [2, 0, 2, 0], [0, 0, 2, 0], [0, 0, 2, 0]]);
  bytes.set(bytes.subarray(8, 12), 12);
  bytes.set(bytes.subarray(16, 20), 20);
  const warnings: string[] = [];

  const parsed = await readTd32Types(legacyReader(bytes, warnings));

  assert.deepEqual(parsed.records, [{ index: 0, type: 2 }, { index: 1, type: 2 }]);
  assert.equal(warnings.length, 1);
});

void test("TD32 accepts empty type tables but rejects even small offset-table truncations", async () => {
  const warnings: string[] = [];
  const empty = await readTd32Types(legacyReader([...legacyU32(1), ...legacyU32(0)], warnings));

  assert.deepEqual(empty.records, []);
  assert.deepEqual(warnings, []);
  assert.deepEqual((await readTd32Types(legacyReader([
    ...legacyU32(1), ...legacyU32(2), ...legacyU32(12)], warnings))).records, []);
  assert.deepEqual(warnings, ["TD32 type offset table is truncated."]);
});

void test("TD32 rejects offsets into the offset table and modest record overflows", async () => {
  const tableWarnings: string[] = [];
  const lengthWarnings: string[] = [];
  const overlap = await readTd32Types(legacyReader([
    ...legacyU32(1), ...legacyU32(2), ...legacyU32(12), ...legacyU32(2)], tableWarnings));
  const overrun = await readTd32Types(legacyReader(types([[8, 0, 2, 0]]), lengthWarnings));

  assert.deepEqual(overlap.records, []);
  assert.deepEqual(overrun.records, []);
  assert.equal(tableWarnings.length, 2);
  assert.match(tableWarnings.join(" | "), /offset overlaps/);
  assert.deepEqual(lengthWarnings, ["Error: TD32 type length exceeds subsection bounds."]);
});
