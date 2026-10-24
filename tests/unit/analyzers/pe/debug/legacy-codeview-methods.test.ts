import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewMethods } from "../../../../../analyzers/pe/debug/legacy-codeview-methods.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView method lists retain narrow type indices and introducing virtual offsets", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([
    ...legacyU16(3), ...legacyU16(0x1234),
    ...legacyU16(19), ...legacyU16(0x4321), ...legacyU32(-8)
  ], warnings), 2), [{ attributes: 3, typeIndex: 0x1234 },
    { attributes: 19, typeIndex: 0x4321, vtableOffset: -8 }]);
  assert.deepEqual(warnings, []);
});

void test("CodeView wide method lists check internal padding, reserved properties and attribute bits", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([
    ...legacyU16(0x103), ...legacyU16(0), ...legacyU32(0x12345678),
    ...legacyU16(27), ...legacyU16(0), ...legacyU32(0x87654321), ...legacyU32(16),
    ...legacyU16(0x801f), ...legacyU16(1), ...legacyU32(0xffffffff)
  ], warnings), 4), [{ attributes: 0x103, typeIndex: 0x12345678 },
    { attributes: 27, typeIndex: 0x87654321, vtableOffset: 16 },
    { attributes: 0x801f, typeIndex: 0xffffffff }]);
  assert.match(warnings.join(" | "), /reserved method property/);
  assert.match(warnings.join(" | "), /reserved padding/);
  assert.match(warnings.join(" | "), /unknown attribute bits/);
});

for (const width of [2, 4] as const) {
  void test(`CodeView method lists preserve a complete prefix before a truncated ${width}-byte index`, async () => {
    const warnings: string[] = [];
    assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([1], warnings), width), []);
    assert.match(warnings.join(" | "), /bounds/);
    warnings.length = 0;
    assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([
      ...legacyU16(3), ...new Array<number>(width * 2 - 2).fill(0), ...legacyU16(19),
      ...new Array<number>(width * 2 - 2).fill(0), 0, 0, 0
    ], warnings), width), [{ attributes: 3, typeIndex: 0 }]);
    assert.match(warnings.join(" | "), /bounds/);
    assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([]), width), []);
  });
}

void test("CodeView method-list padding is bounded and cannot hide trailing bytes silently", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([0xf3, 0xf2, 0xf1]), 4), []);
  await readLegacyCodeViewMethods(legacyReader([0xf0], warnings), 4);
  await readLegacyCodeViewMethods(legacyReader([0xf2], warnings), 4);
  await readLegacyCodeViewMethods(legacyReader([0xf1, 0], warnings), 4);
  assert.match(warnings.join(" | "), /LF_PAD0/);
  assert.match(warnings.join(" | "), /bounds/);
  assert.match(warnings.join(" | "), /bytes after padding/);
});

void test("CodeView valid method padding after a complete entry adds no diagnostics", async () => {
  const warnings: string[] = [];
  assert.deepEqual(await readLegacyCodeViewMethods(legacyReader([
    ...legacyU16(3), ...legacyU16(0), ...legacyU32(0x12345678), 0xf3, 0xf2, 0xf1
  ], warnings), 4), [{ attributes: 3, typeIndex: 0x12345678 }]);
  assert.deepEqual(warnings, []);
});
