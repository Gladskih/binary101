import assert from "node:assert/strict";
import { test } from "node:test";
import { readTd32TypeField } from "../../../../../analyzers/pe/debug/td32-type-field-record.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

const field = (type: number, payload: number[]) => legacyReader([...legacyU16(type), ...payload]);
// map2dbg Program.cs field dispatch; numbers test stored offsets and member IDs.
void test("TD32 field prefixes decode base, virtual base and enum numeric values", async () => {
  assert.deepEqual(await readTd32TypeField(field(0x400, [
    ...legacyU32(0x1001), ...legacyU16(3), ...legacyU16(8)])),
  { field: { type: 0x400, targetType: 0x1001, attributes: 3, offset: { value: "8" } }, end: 10 });
  assert.deepEqual(await readTd32TypeField(field(0x401, [
    ...legacyU32(0x1001), ...legacyU32(0x1002), ...legacyU16(2), ...legacyU16(8), ...legacyU16(1)])),
  { field: { type: 0x401, targetType: 0x1001, pointerType: 0x1002, attributes: 2,
    offset: { value: "8" }, virtualBaseIndex: { value: "1" } }, end: 16 });
  assert.deepEqual(await readTd32TypeField(field(0x403, [
    ...legacyU16(0), ...legacyU32(2), ...legacyU32(0), ...legacyU16(7)])),
  { field: { type: 0x403, attributes: 0, nameIndex: 2, browserOffset: 0, value: { value: "7" } }, end: 14 });
});
void test("TD32 field prefixes retain static members, continuations and vtable pointers", async () => {
  assert.deepEqual(await readTd32TypeField(field(0x407, [
    ...legacyU32(0x1001), ...legacyU16(1), ...legacyU32(2), ...legacyU32(9)])),
  { field: { type: 0x407, targetType: 0x1001, attributes: 1, nameIndex: 2, browserOffset: 9 }, end: 16 });
  assert.deepEqual(await readTd32TypeField(field(0x405, legacyU32(0x1001))),
    { field: { type: 0x405, targetType: 0x1001 }, end: 6 });
  assert.deepEqual(await readTd32TypeField(field(0x40a, [...legacyU32(0x1001), ...legacyU16(0)])),
    { field: { type: 0x40a, targetType: 0x1001, offset: { value: "0" } }, end: 8 });
});
void test("TD32 field decoder rejects unavailable, truncated and unknown leaf extents", async () => {
  await assert.rejects(readTd32TypeField(legacyReader([])), /bounds/);
  await assert.rejects(readTd32TypeField(field(0x7777, [])), /Unsupported TD32 field/);
  await assert.rejects(readTd32TypeField(field(0x408, [])), /bounds/);
  await assert.rejects(readTd32TypeField(field(0x409, [])), /bounds/);
  await assert.rejects(readTd32TypeField(field(0x401, [])), /bounds/);
  await assert.rejects(readTd32TypeField(field(0x403, [])), /bounds/);
});
