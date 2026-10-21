import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewSource } from "../../../../../analyzers/pe/debug/legacy-codeview-source.js";
import { legacyReader, legacySource, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("legacy source tables retain file names, segment ranges and every line pair", async () => {
  const source = await readLegacyCodeViewSource(legacyReader(legacySource()));

  assert.deepEqual(source, { kind: "source", files: [{ name: "source.c", segments: [
    { segment: 2, start: 16, end: 24, lines: [{ offset: 16, line: 7 }, { offset: 24, line: 9 }] }
  ] }] });
  assert.deepEqual(await readLegacyCodeViewSource(legacyReader([0, 0, 0, 0])), { kind: "source", files: [] });
});

void test("legacy source parsing warns for reversed ranges, bad line offsets and reserved words", async () => {
  const bytes = legacySource();
  bytes[22] = 1;
  bytes.set(legacyU32(25), 28);
  const warnings: string[] = [];
  await readLegacyCodeViewSource(legacyReader(bytes, warnings));

  assert.equal(warnings.length, 3);
  assert.match(warnings.join(" | "), /reserved field/);
  assert.match(warnings.join(" | "), /reversed/);
  assert.match(warnings.join(" | "), /outside its source segment/);
});

for (const [size, pattern] of [[17, /module arrays/], [26, /file segment arrays/], [55, /line pairs/]] as const) {
  void test(`legacy source rejects a truncated table of ${size} bytes`, async () => {
    await assert.rejects(readLegacyCodeViewSource(legacyReader(legacySource().slice(0, size))), pattern);
  });
}

void test("legacy source shares repeated file and line references without re-decoding", async () => {
  const bytes = legacySource();
  bytes[0] = 2;
  bytes.set(legacyU32(20), 8);
  const parsed = await readLegacyCodeViewSource(legacyReader(bytes));

  assert.equal(parsed.files.length, 2);
  assert.equal(parsed.files[0], parsed.files[1]);
});
