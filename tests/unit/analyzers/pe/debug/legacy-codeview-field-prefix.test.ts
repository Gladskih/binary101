import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewFieldPrefix } from "../../../../../analyzers/pe/debug/legacy-codeview-field-prefix.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView narrow and wide member prefixes use their documented field order", async () => {
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x406), ...legacyU16(0x1234), ...legacyU16(3)]), 0x406),
  { typeIndex: 0x1234, attributes: 3 });
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x150d), ...legacyU16(1), ...legacyU32(0x12345678)]), 0x150d),
  { typeIndex: 0x12345678, attributes: 1 });
});

void test("CodeView virtual bases retain their virtual-base-pointer type and attributes", async () => {
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x401), ...legacyU16(0x1001), ...legacyU16(0x1002), ...legacyU16(2)]), 0x401),
  { typeIndex: 0x1001, virtualBasePointer: 0x1002, attributes: 2 });
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x1401), ...legacyU16(3), ...legacyU32(0x1001), ...legacyU32(0x1002)]), 0x1401),
  { typeIndex: 0x1001, virtualBasePointer: 0x1002, attributes: 3 });
});

void test("CodeView overloaded methods, virtual tables and named-only records have distinct prefixes", async () => {
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x150f), ...legacyU16(7), ...legacyU32(0x12345678)]), 0x150f),
  { typeIndex: 0x12345678, methodCount: 7 });
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x40d), ...legacyU16(0x1234), ...legacyU32(-8)]), 0x40d),
  { typeIndex: 0x1234, vtableOffset: -8 });
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x140c), 0, 0, ...legacyU32(0x12345678), ...legacyU32(-4)]), 0x140c),
  { typeIndex: 0x12345678, vtableOffset: -4 });
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([]), 0x1514), {});
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([]), 0x7777), {});
});

void test("CodeView field attribute extensions and truncated prefixes remain visible", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readCodeViewFieldPrefix(legacyReader([
    ...legacyU16(0x1502), ...legacyU16(0x8003)], warnings), 0x1502), { attributes: 0x8003 });
  assert.match(warnings.join(" | "), /unknown attribute bits/);
  await assert.rejects(readCodeViewFieldPrefix(legacyReader([0x0d, 0x15, 3]), 0x150d), /bounds/);
});
