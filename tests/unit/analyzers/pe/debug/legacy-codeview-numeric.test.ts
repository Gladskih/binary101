import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewNumeric, skipLegacyCodeViewNumeric } from "../../../../../analyzers/pe/debug/legacy-codeview-numeric.js";
import { legacyReader, legacyU16 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewInteger } from "../../../../fixtures/pe-codeview-numeric-values.js";

for (const [leaf, width, value] of [
  [0x8000, 1, -128n], [0x8001, 2, -32768n], [0x8002, 2, 65535n],
  [0x8003, 4, -2147483648n], [0x8004, 4, 4294967295n],
  [0x8009, 8, -9223372036854775808n], [0x800a, 8, 18446744073709551615n],
  [0x8017, 16, -(1n << 127n)], [0x8018, 16, (1n << 128n) - 1n]
] as const) {
  void test(`CodeView integer leaf ${leaf} retains its exact signed or unsigned value`, async () => {
    assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader(codeViewInteger(leaf, value, width)), 0),
      { end: 2 + width, leaf, value: value.toString() });
    assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader(codeViewInteger(leaf, 1n, width)), 0),
      { end: 2 + width, leaf, value: "1" });
    await assert.rejects(readLegacyCodeViewNumeric(legacyReader(codeViewInteger(leaf, value, width).slice(0, -1)), 0), /bounds/);
  });
}

void test("CodeView immediate integer and noninteger numeric leaves remain distinguishable", async () => {
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader([0xff, 0x7f]), 0),
    { end: 2, value: "32767" });
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader([0x1b, 0x80, 65, 0]), 0),
    { end: 4, leaf: 0x801b });
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader([0x10, 0x80, 1, 0, 65]), 0),
    { end: 5, leaf: 0x8010 });
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader([5, 0x80, 0, 0, 0, 0]), 0),
    { end: 6, leaf: 0x8005 });
  await assert.rejects(readLegacyCodeViewNumeric(legacyReader([0, 0]), -1), /bounds/);
  await assert.rejects(readLegacyCodeViewNumeric(legacyReader([0, 0]), Infinity), /bounds/);
});

void test("CodeView octwords preserve byte order in both 64-bit halves", async () => {
  // CV4 LF_OCTWORD/LF_UOCTWORD use little-endian high and low halves (cvinfo.h).
  const value = 0x123456789abcdef0fedcba9876543210n;
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader(codeViewInteger(0x8018, value, 16)), 0),
    { end: 18, leaf: 0x8018, value: value.toString() });
  assert.deepEqual(await readLegacyCodeViewNumeric(legacyReader(codeViewInteger(0x8017, -value, 16)), 0),
    { end: 18, leaf: 0x8017, value: (-value).toString() });
});

void test("CodeView numeric leaf skips immediate, variable-length and UTF-8 strings exactly", async () => {
  assert.equal(await skipLegacyCodeViewNumeric(legacyReader([0xff, 0x7f]), 0), 2);
  assert.equal(await skipLegacyCodeViewNumeric(legacyReader([0x10, 0x80, 3, 0, 65, 66, 67]), 0), 7);
  assert.equal(await skipLegacyCodeViewNumeric(legacyReader([0x1b, 0x80, 0xc3, 0xa9, 0]), 0), 5);
  await assert.rejects(skipLegacyCodeViewNumeric(legacyReader([0xff, 0x80]), 0), /Unknown.*numeric leaf/);
  await assert.rejects(skipLegacyCodeViewNumeric(legacyReader([0x10, 0x80, 4, 0, 65]), 0), /bounds/);
});

// Encoded payload widths from Microsoft's CV4 numeric-leaf structs, not production constants.
for (const [type, size] of [[0x8000, 1], [0x8001, 2], [0x8002, 2], [0x8003, 4], [0x8004, 4],
  [0x8005, 4], [0x8006, 8], [0x8007, 10], [0x8008, 16], [0x8009, 8], [0x800a, 8], [0x800b, 6],
  [0x800c, 8], [0x800d, 16], [0x800e, 20], [0x800f, 32], [0x8017, 16], [0x8018, 16],
  [0x8019, 16], [0x801a, 8], [0x801c, 2]] as const) {
  void test(`CodeView numeric leaf ${type.toString(16)} checks its complete payload`, async () => {
    const bytes = [...legacyU16(type), ...new Array<number>(size).fill(0)];

    assert.equal(await skipLegacyCodeViewNumeric(legacyReader(bytes), 0), size + 2);
    await assert.rejects(skipLegacyCodeViewNumeric(legacyReader(bytes.slice(0, -1)), 0), /bounds/);
  });
}
