import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewGlobalTypes, readLegacyCodeViewModuleTypes } from "../../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { legacyReader, legacySymbol, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView type streams retain structural records and names from sized type leaves", async () => {
  const records = [...legacySymbol(5, "MyStruct", 16), 2, 0, 2, 0];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), ...records], warnings));

  assert.deepEqual(parsed, { kind: "types", records: [{ type: 5, name: "MyStruct" }, { type: 2 }] });
  assert.deepEqual(warnings, []);
  await assert.rejects(readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(9)])), /signature/);
});

void test("CodeView type record boundaries reject a short tag and a payload missing exactly two bytes", async () => {
  const tagWarnings: string[] = [];
  const shortWarnings: string[] = [];
  const tag = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), 1, 0, 2], tagWarnings));
  const short = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), 4, 0, 2, 0], shortWarnings));
  const emptyWarnings: string[] = [];
  const empty = await readLegacyCodeViewGlobalTypes(legacyReader([...legacyU32(1), ...legacyU32(0)], emptyWarnings));

  assert.deepEqual(tag.records, []);
  assert.deepEqual(tagWarnings, ["Error: Invalid CodeView type record length."]);
  assert.deepEqual(short.records, []);
  assert.deepEqual(shortWarnings, ["Error: CodeView subsection bounds exceeded."]);
  assert.deepEqual(empty.records, []);
  assert.deepEqual(emptyWarnings, []);
});

void test("CodeView modern type names use UTF-8 and enum names have no numeric size field", async () => {
  const records = [...legacySymbol(0x1504, "😀", 22), ...legacySymbol(7, "Enum", 12)];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(2), ...records]));

  assert.deepEqual(parsed.records, [{ type: 0x1504, name: "😀" }, { type: 7, name: "Enum" }]);
});

void test("CodeView global type offsets use record-base for NB09 and subsection-base before it", async () => {
  const records = legacySymbol(5, "MyStruct", 16);
  const nb09 = [1, 0, 0, 0, ...legacyU32(2), ...legacyU32(0), ...legacyU32(0), ...records];
  const nb08 = [1, 0, 0, 0, ...legacyU32(1), ...legacyU32(12), ...records];
  const parsed = await readLegacyCodeViewGlobalTypes(legacyReader(nb09));

  assert.equal(parsed.records.length, 2);
  assert.equal(parsed.records[0], parsed.records[1]);
  assert.deepEqual((await readLegacyCodeViewGlobalTypes(legacyReader(nb08), "NB08")).records, [parsed.records[0]]);
  assert.deepEqual((await readLegacyCodeViewGlobalTypes(legacyReader(nb08), "NB07")).records, [parsed.records[0]]);
  await assert.rejects(readLegacyCodeViewGlobalTypes(legacyReader([0, 0, 0, 0, 255, 255, 255, 255])), /offsets/);
});

void test("CodeView global types warn for invalid individual offsets without discarding later types", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalTypes(legacyReader([
    1, 0, 0, 0, ...legacyU32(2), ...legacyU32(999), ...legacyU32(0), 2, 0, 2, 0], warnings));

  assert.deepEqual(parsed.records, [{ type: 2 }]);
  assert.match(warnings.join(" | "), /type 0:.*bounds/);
});

for (const record of [[1, 0, 2], [255, 255, 2], [1]]) {
  void test(`CodeView module types terminate safely on malformed record ${record}`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), ...record], warnings));

    assert.deepEqual(parsed.records, []);
    assert.match(warnings.join(" | "), /length|bounds/);
  });
}
