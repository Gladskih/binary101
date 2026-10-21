import assert from "node:assert/strict";
import { test } from "node:test";
import { skipLegacyCodeViewNumeric } from "../../../../../analyzers/pe/debug/legacy-codeview-numeric.js";
import { legacyReader, legacyU16 } from "../../../../fixtures/pe-legacy-codeview.js";

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
