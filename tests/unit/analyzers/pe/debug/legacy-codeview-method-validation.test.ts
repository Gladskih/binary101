import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewModuleTypes, readLegacyCodeViewGlobalTypes,
  type LegacyCodeViewTypeRecord } from "../../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { validateCodeViewMethodLists } from "../../../../../analyzers/pe/debug/legacy-codeview-method-validation.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord, codeViewUtf8 } from "../../../../fixtures/pe-codeview-type-strings.js";
import { createPeWithCodeViewComposites } from "../../../../fixtures/pe-codeview-composites.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";

void test("CodeView declared overloads exceeding a complete method list produce an explicit warning", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1206, 4, [...legacyU16(3), ...legacyU16(0), ...legacyU32(0x1002)]),
    ...codeViewTextRecord(0x1203, 4, [...legacyU16(0x150f), ...legacyU16(2), ...legacyU32(0x1000),
      ...codeViewUtf8("read")])
  ], warnings));
  assert.equal(parsed.records.length, 2);
  assert.match(warnings.join(" | "), /read.*declared variants 2.*recovered variants 1/);
});

void test("CodeView global type lists also diagnose incomplete overload lists", async () => {
  const warnings: string[] = [];
  const methods = codeViewTextRecord(0x1206, 4, []);
  const fields = codeViewTextRecord(0x1203, 4, [...legacyU16(0x150f), ...legacyU16(1),
    ...legacyU32(0x1000), ...codeViewUtf8("read")]);
  await readLegacyCodeViewGlobalTypes(legacyReader([...legacyU32(0), ...legacyU32(2), ...legacyU32(0),
    ...legacyU32(methods.length), ...methods, ...fields], warnings));
  assert.deepEqual(warnings, ["CodeView overloaded method read: declared variants 1; " +
    "recovered variants 0. Some method declarations are unavailable."]);
});

for (const type of [0x408, 0x1407, 0x150f]) {
  void test(`CodeView overload count validation covers field encoding ${type}`, () => {
    const warnings: string[] = [];
    validateCodeViewMethodLists([
      { type: 0x1203, index: 0x1000, members: [{ type, typeIndex: 0x1001, methodCount: 1 }] },
      { type: 0x1206, index: 0x1001, shape: { kind: "methods", methods: [] } }
    ], message => warnings.push(message));
    assert.deepEqual(warnings, ["CodeView overloaded method (unnamed): declared variants 1; " +
      "recovered variants 0. Some method declarations are unavailable."]);
  });
}

void test("CodeView overload validation accepts sufficient lists and skips fields without a declared local count", () => {
  const warnings: string[] = [];
  const records: LegacyCodeViewTypeRecord[] = [
    { type: 0x1206, index: 0x1000, shape: { kind: "methods", methods: [{ typeIndex: 0x74, attributes: 3 }] } },
    { type: 0x1203, index: 0x1001, members: [
      { type: 0x150f, typeIndex: 0x1000, methodCount: 1 },
      { type: 0x150f, typeIndex: 0x1000, methodCount: 0 },
      { type: 0x150f, typeIndex: 0x1000 }, { type: 0x150f, methodCount: 1 },
      { type: 0x150d, typeIndex: 0x1000, methodCount: 100 },
      { type: 0x150f, typeIndex: 0x2000, methodCount: 1 },
      { type: 0x150f, typeIndex: 0x1002, methodCount: 1 }
    ] }, { type: 0x1505, index: 0x1002 },
    { type: 0x1203, members: [{ type: 0x150f, typeIndex: 0x1000, methodCount: 100 }] }
  ];
  validateCodeViewMethodLists(records, message => warnings.push(message));
  assert.deepEqual(warnings, []);
});

void test("CodeView ambiguous target indices cannot produce a false overload deficit", () => {
  const warnings: string[] = [];
  validateCodeViewMethodLists([
    { type: 0x1206, index: 0x1000, shape: { kind: "methods", methods: [] } },
    { type: 0x1206, index: 0x1000, shape: { kind: "methods", methods: [] } },
    { type: 0x1203, index: 0x1001, members: [{ type: 0x150f, typeIndex: 0x1000, methodCount: 100 }] }
  ], message => warnings.push(message));
  validateCodeViewMethodLists([], message => warnings.push(message));
  assert.deepEqual(warnings, []);
});

void test("PE debug integration surfaces the actual overload deficit without rejecting recovered types", async () => {
  const file = createPeWithCodeViewComposites(3);
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  assert.match(debug.warning ?? "", /read: declared variants 3; recovered variants 2/);
  assert.ok(debug.entries[0]?.legacyCodeView);
});
