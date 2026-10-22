import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewTypeStrings } from "../../../../../analyzers/pe/debug/legacy-codeview-type-strings.js";
import { legacyReader, legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8, codeViewVtableRecord } from "../../../../fixtures/pe-codeview-type-strings.js";

for (const [type, offset] of [[0x13, 12], [0x100e, 16], [0x1509, 16], [0x16, 12],
  [0x1501, 12], [0x1515, 24], [0x202, 6], [0x1202, 8], [0x150b, 8],
  [0x1601, 12], [0x1602, 12], [0x1605, 8]] as const) {
  void test(`CodeView stored strings use the published offset and encoding for ${type}`, async () => {
    const warnings: string[] = [];
    const text = type < 0x1500 ? legacyPascal("value") : codeViewUtf8("значение");
    const result = await readLegacyCodeViewTypeStrings(
      legacyReader(codeViewTextRecord(type, offset, text), warnings), type);

    assert.deepEqual(result, [type < 0x1500 ? "value" : "значение"]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView string extraction leaves unknown and non-string leaves untouched", async () => {
  const warnings: string[] = [];

  assert.equal(await readLegacyCodeViewTypeStrings(legacyReader([], warnings), 0xffff), undefined);
  assert.equal(await readLegacyCodeViewTypeStrings(legacyReader([], warnings), 0x1505), undefined);
  assert.deepEqual(warnings, []);
});

void test("CodeView string IDs preserve empty stored strings and leading UTF-8 BOM", async () => {
  assert.deepEqual(await readLegacyCodeViewTypeStrings(legacyReader(
    codeViewTextRecord(0x1605, 8, [0])), 0x1605), [""]);
  assert.deepEqual(await readLegacyCodeViewTypeStrings(legacyReader(
    codeViewTextRecord(0x1605, 8, [0xef, 0xbb, 0xbf, 65, 0])), 0x1605), ["\ufeffA"]);
});

for (const [type, offset, text] of [[0x1501, 12, [0xff, 0]], [0x1605, 8, [65]],
  [0x13, 12, [2, 65]], [0x1515, 4, []]] as const) {
  void test(`CodeView malformed stored string ${type}/${offset} cannot overrun its record`, async () => {
    await assert.rejects(readLegacyCodeViewTypeStrings(legacyReader(
      codeViewTextRecord(type, offset, text)), type), /bounds|terminated|encoded data/);
  });
}

void test("CodeView ST strings retain ANSI bytes with an explicit code-page warning", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewTypeStrings(
    legacyReader(codeViewTextRecord(0x202, 6, [1, 0xe9]), warnings), 0x202);

  assert.deepEqual(result, ["é"]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /Windows-1252/);
});

void test("CodeView virtual table strings exclude record padding and retain empty names", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewTypeStrings(legacyReader(codeViewVtableRecord(
    [...codeViewUtf8("Table"), 0, ...codeViewUtf8("метод"), ...codeViewUtf8("padding")], 18), warnings), 0x151d);

  assert.deepEqual(result, ["Table", "", "метод"]);
  assert.deepEqual(warnings, []);
});

for (const tail of [[65], [0xff, 0]]) {
  void test(`CodeView virtual table retains complete names before malformed text ${tail}`, async () => {
    const warnings: string[] = [];
    const result = await readLegacyCodeViewTypeStrings(legacyReader(codeViewVtableRecord(
      [...codeViewUtf8("Table"), ...tail]), warnings), 0x151d);

    assert.deepEqual(result, ["Table"]);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /virtual table name/);
  });
}

void test("CodeView virtual table warns for an absent name and rejects a missing length", async () => {
  const warnings: string[] = [];

  assert.deepEqual(await readLegacyCodeViewTypeStrings(
    legacyReader(codeViewVtableRecord([], 0), warnings), 0x151d), []);
  assert.deepEqual(warnings, ["CodeView virtual table Names array has no table name."]);
  await assert.rejects(readLegacyCodeViewTypeStrings(legacyReader(new Uint8Array(19)), 0x151d), /bounds/);
});

void test("CodeView virtual table bounds a truncated declared Names array and preserves complete names", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewTypeStrings(legacyReader(codeViewVtableRecord(codeViewUtf8("Table"), 0xffffffff),
    warnings), 0x151d);

  assert.deepEqual(result, ["Table"]);
  assert.deepEqual(warnings, ["CodeView virtual table Names array is truncated."]);
});

void test("CodeView virtual table warns when Names exceeds the record by exactly one byte", async () => {
  const warnings: string[] = [];
  const result = await readLegacyCodeViewTypeStrings(legacyReader(codeViewVtableRecord(codeViewUtf8("Table"), 7),
    warnings), 0x151d);

  assert.deepEqual(result, ["Table"]);
  assert.deepEqual(warnings, ["CodeView virtual table Names array is truncated."]);
});
