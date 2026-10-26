import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewInlineAnnotations } from "../../../../../analyzers/pe/debug/codeview-inline-annotations.js";
import { legacyReader } from "../../../../fixtures/pe-legacy-codeview.js";

void test("Inline annotations decode signed deltas, packed operations and both unsigned compression widths", async () => {
  const warnings: string[] = [];
  // cvinfo.h BinaryAnnotationOpcode and CompressAnnotation: big-endian 7/14/29-bit integers.
  const bytes = Uint8Array.from([1, 0x80, 0x80, 2, 0xc0, 0, 0x40, 0, 6, 7, 10, 8, 11, 0x75, 12, 9, 2, 0, 0]);
  const result = await readCodeViewInlineAnnotations(legacyReader(bytes, warnings), 0);

  assert.deepEqual(result, [{ opcode: 1, operands: [128] }, { opcode: 2, operands: [16384] },
    { opcode: 6, operands: [-3] }, { opcode: 10, operands: [4] }, { opcode: 11, operands: [5, -3] },
    { opcode: 12, operands: [9, 2] }]);
  assert.deepEqual(warnings, []);
});

for (const bytes of [[1], [1, 0x80], [1, 0xc0, 0], [1, 0xe0], [12, 3], [14, 1], [0, 1]]) {
  void test(`Malformed inline annotations retain their complete prefix: ${bytes}`, async () => {
    const warnings: string[] = [];
    const result = await readCodeViewInlineAnnotations(legacyReader(Uint8Array.from([3, 4, ...bytes]), warnings), 0);

    assert.deepEqual(result, [{ opcode: 3, operands: [4] }]);
    assert.ok(warnings.length);
  });
}

for (const opcode of [1, 2, 3, 4, 5, 7, 8, 9, 13]) {
  void test(`Inline unsigned annotation ${opcode} preserves its operand`, async () => {
    assert.deepEqual(await readCodeViewInlineAnnotations(legacyReader(Uint8Array.from([opcode, 42]), []), 0),
      [{ opcode, operands: [42] }]);
  });
}

void test("Inline operands preserve maximum compressed values and zero signed deltas", async () => {
  assert.deepEqual(await readCodeViewInlineAnnotations(
    legacyReader(Uint8Array.from([1, 0xdf, 255, 255, 255, 6, 0]), []), 0),
    [{ opcode: 1, operands: [0x1fffffff] }, { opcode: 6, operands: [0] }]);
});

void test("An invalid annotation start warns without reading outside its record", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readCodeViewInlineAnnotations(legacyReader(new Uint8Array(), warnings), 1), []);
  assert.match(warnings.join(" | "), /bounds/);
});

void test("Reserved full-width integer prefixes are rejected even when enough bytes remain", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readCodeViewInlineAnnotations(
    legacyReader(Uint8Array.from([1, 0xe0, 0, 0, 0]), warnings), 0), []);
  assert.match(warnings.join(" | "), /Invalid or truncated compressed integer/);
});

void test("A two-byte integer preserves all fourteen bits", async () => {
  assert.deepEqual(await readCodeViewInlineAnnotations(legacyReader(Uint8Array.from([1, 0xbf, 0xff]), []), 0),
    [{ opcode: 1, operands: [0x3fff] }]);
});

void test("Truncated compressed operands identify the truncation in their warning", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readCodeViewInlineAnnotations(legacyReader(Uint8Array.from([1, 0x80]), warnings), 0), []);
  assert.match(warnings.join(" | "), /Truncated compressed integer/);
});
