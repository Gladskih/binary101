import assert from "node:assert/strict";
import { test } from "node:test";
import { readLegacyCodeViewGlobalTypes, readLegacyCodeViewModuleTypes } from "../../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { legacyReader, legacySymbol, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewField, codeViewFieldList, codeViewUniqueType } from "../../../../fixtures/pe-codeview-fields.js";
import { codeViewStoredTypeText, codeViewTextRecord, codeViewUtf8, codeViewVtableRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { legacyPascal } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewEntryThis, codeViewPointerBase } from "../../../../fixtures/pe-codeview-embedded-symbols.js";
import { codeViewArguments, codeViewCallableStream, codeViewProcedure } from "../../../../fixtures/pe-codeview-callables.js";
import { legacyU16 } from "../../../../fixtures/pe-legacy-codeview.js";

void test("CodeView malformed bitfields warn without losing following type records", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1205, 4, [...legacyU32(0x75), 3]),
    ...codeViewTextRecord(0x206, 4, [5, 1, ...legacyU16(0x74)])], warnings));
  assert.deepEqual(parsed.records, [{ type: 0x1205, index: 0x1000 },
    { type: 0x206, index: 0x1001,
      shape: { kind: "bitfield", typeIndex: 0x74, length: 5, position: 1 } }]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /CodeView type record:.*bounds/);
});

void test("CodeView type leaves preserve referenced symbols and based-pointer names without consuming padding", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x20c, 4, [...codeViewEntryThis(legacySymbol()), 0xf2, 0xf1]),
    ...codeViewPointerBase(2, 8, [0, 0, ...legacyPascal("Base")]),
    ...codeViewPointerBase(0x1002, 4, legacySymbol(0x110d, "base", 14))], warnings));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [
    { type: 0x20c, symbols: [{ type: 0xe, children: [{ type: 0x203, name: "public_name" }] }] },
    { type: 2, strings: ["Base"] }, { type: 0x1002, symbols: [{ type: 0x110d, name: "base" }] }
  ]);
  assert.deepEqual(warnings, []);
});

// Opaque 0x7777 records below isolate framing checks from known-leaf body validation.
// Microsoft cvinfo.h: DIMARRAY, STRIDED_ARRAY, VECTOR and packed MATRIX.
for (const [type, offset] of [[0x11, 8], [0x100c, 12], [0x1508, 12],
  [0x1516, 18], [0x151b, 14], [0x151c, 23]] as const) {
  void test(`CodeView named array-like leaf ${type} retains its stored name`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewTextRecord(type, offset, type < 0x1500 ? legacyPascal("Named") : codeViewUtf8("Named"))], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type, name: "Named" }]);
    assert.deepEqual(warnings, []);
  });
}

for (const [type, offset] of [[0x13, 12], [0x100e, 16], [0x1509, 16], [0x16, 12],
  [0x1501, 12], [0x1515, 24], [0x202, 6], [0x1202, 8], [0x150b, 8],
  [0x1601, 12], [0x1602, 12], [0x1605, 8]] as const) {
  void test(`CodeView string leaf ${type} retains text without mislabelling it as a type name`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewTextRecord(type, offset, type < 0x1500 ? legacyPascal("stored") : codeViewUtf8("stored"))], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type, strings: ["stored"] }]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView virtual table strings respect Names length and retain all methods", async () => {
  const text = [...codeViewUtf8("Table"), ...codeViewUtf8("first"), ...codeViewUtf8("second")];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewVtableRecord([...text, ...codeViewUtf8("padding")], text.length)]));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x151d, strings: ["Table", "first", "second"] }]);
});

for (const [type, offset, bytes] of [[0x1605, 8, [0xff, 0]], [0x1501, 12, [65]],
  [0x13, 12, [2, 65]], [0x1515, 4, []], [0x151d, 4, []]] as const) {
  void test(`CodeView malformed string leaf ${type} retains its tag and the following record`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewTextRecord(type, offset, bytes), 2, 0, 0x77, 0x77], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type }, { type: 0x7777 }]);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0]!, /^CodeView type record:/);
  });
}

void test("CodeView type streams preserve a virtual table's complete string prefix", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewVtableRecord([...codeViewUtf8("Table"), 65]), 2, 0, 0x77, 0x77], warnings));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x151d, strings: ["Table"] }, { type: 0x7777 }]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /virtual table name/);
});

for (const [type, offset] of [[0x1504, 22], [0x1505, 22], [0x1506, 14],
  [0x1507, 16], [0x1519, 22]] as const) {
  void test(`CodeView leaf ${type} retains the separate decorated type identity`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewUniqueType(type, offset, "名", [...new TextEncoder().encode(".?AUNamed@@"), 0])], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type, name: "名", uniqueName: ".?AUNamed@@" }]);
    assert.deepEqual(warnings, []);
  });
}

for (const identity of [[], [0x41], [0xff, 0]]) {
  void test(`CodeView preserves the readable type name when the decorated identity is malformed: ${identity}`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewUniqueType(0x1505, 22, "Readable", identity), 2, 0, 0x77, 0x77], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x1505, name: "Readable" }, { type: 0x7777 }]);
    assert.match(warnings.join(" | "), /decorated type name/);
  });
}

void test("CodeView does not infer a decorated identity without the UDT property flag", async () => {
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...legacySymbol(0x1505, "Readable", 22), ...codeViewUniqueType(0x1503, 14, "Array", [0]) ]));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x1505, name: "Readable" }, { type: 0x1503, name: "Array" }]);
});

for (const [recordType, fieldType, body] of [[0x204, 0x407, [0x74, 0, 3, 0]],
  [0x1203, 0x150e, [3, 0, 0x74, 0, 0, 0]]] as const) {
  void test(`CodeView type ${recordType} exposes member names instead of leaving LF_FIELDLIST opaque`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1),
      ...codeViewFieldList(codeViewField(fieldType, body, "value"), recordType)], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: recordType, members: [{ type: fieldType, name: "value" }] }]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView caches malformed type records as well as successfully decoded ones", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalTypes(legacyReader([
    ...legacyU32(1), ...legacyU32(3), ...legacyU32(0), ...legacyU32(0), ...legacyU32(2),
    0, 0, 2, 0, 0x77, 0x77], warnings));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x7777 }]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /Invalid CodeView type record length/);
});

for (const signature of ["NB07", "NB08"]) {
  void test(`${signature} rejects global type offsets into its offset table`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewGlobalTypes(legacyReader([
      ...legacyU32(1), ...legacyU32(2), ...legacyU32(8), ...legacyU32(16), 2, 0, 0x77, 0x77], warnings), signature);

    assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x7777 }]);
    assert.match(warnings.join(" | "), /overlaps/);
  });
}

void test("CodeView malformed type names retain the bounded record kind and later records", async () => {
  const bytes = legacySymbol(0x1504, "X", 22);
  bytes[22] = 0xff;
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([
    ...legacyU32(4), ...bytes, 2, 0, 0x77, 0x77], warnings));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x1504 }, { type: 0x7777 }]);
  assert.match(warnings.join(" | "), /type record/);
});

void test("CodeView type streams retain structural records and names from sized type leaves", async () => {
  const records = [...legacySymbol(5, "MyStruct", 16), 2, 0, 0x77, 0x77];
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), ...records], warnings));

  assert.deepEqual(parsed, { kind: "types", records: [
    { type: 5, name: "MyStruct", index: 0x1000, shape: { kind: "aggregate", memberCount: 0,
      properties: 0, fieldList: 0, derivedTypes: 0, vtableShape: 0, size: "0" } },
    { type: 0x7777, index: 0x1001 }] });
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

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x1504, name: "😀" }, { type: 7, name: "Enum" }]);
});

void test("CodeView global type offsets use record-base for NB09 and subsection-base before it", async () => {
  const records = legacySymbol(5, "MyStruct", 16);
  const nb09 = [1, 0, 0, 0, ...legacyU32(2), ...legacyU32(0), ...legacyU32(0), ...records];
  const nb08 = [1, 0, 0, 0, ...legacyU32(1), ...legacyU32(12), ...records];
  const parsed = await readLegacyCodeViewGlobalTypes(legacyReader(nb09));

  assert.equal(parsed.records.length, 2);
  assert.notEqual(parsed.records[0], parsed.records[1]);
  assert.deepEqual((await readLegacyCodeViewGlobalTypes(legacyReader(nb08), "NB08")).records, [parsed.records[0]]);
  assert.deepEqual((await readLegacyCodeViewGlobalTypes(legacyReader(nb08), "NB07")).records, [parsed.records[0]]);
  await assert.rejects(readLegacyCodeViewGlobalTypes(legacyReader([0, 0, 0, 0, 255, 255, 255, 255])), /offsets/);
});

void test("CodeView global types warn for invalid individual offsets without discarding later types", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewGlobalTypes(legacyReader([
    1, 0, 0, 0, ...legacyU32(2), ...legacyU32(999), ...legacyU32(0), 2, 0, 0x77, 0x77], warnings));

  assert.deepEqual(codeViewStoredTypeText(parsed.records), [{ type: 0x7777 }]);
  assert.match(warnings.join(" | "), /type 0:.*bounds/);
  assert.equal(parsed.records[0]?.index, 0x1001);
});

void test("CodeView callable relationships retain the original type namespace", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader(codeViewCallableStream(), warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [0x1000, 0x1001, 0x1002]);
  assert.deepEqual(parsed.records[0]?.shape, { kind: "arguments", types: [0x74, 0x41] });
  assert.deepEqual(parsed.records[1]?.shape, { kind: "procedure", returnType: 0x74,
    callingConvention: 7, attributes: 1, parameterCount: 2, argumentList: 0x1000 });
  assert.deepEqual(parsed.records[2]?.shape, { kind: "functionId", scopeId: 0, functionType: 0x1001 });
  assert.deepEqual(warnings, []);
});

for (const [leaf, next] of [[0x200, legacyU16(0x1010)], [0x1200, legacyU32(0x1010)]] as const) {
  void test(`CodeView LF_SKIP ${leaf} preserves nonconsecutive type indices`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1),
      ...codeViewTextRecord(leaf, 4, next), ...codeViewArguments()], warnings));
    assert.deepEqual(parsed.records.map(record => record.index), [0x1000, 0x1010]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView invalid skips and external imports do not invent type identities", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1200, 4, legacyU32(0x1000)), ...codeViewProcedure()], warnings));
  assert.equal(parsed.records[1]?.index, undefined);
  assert.match(warnings.join(" | "), /no valid forward type index/);
  const imported = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1515, 24, codeViewUtf8("external.pdb")), ...codeViewProcedure()]));
  assert.deepEqual(imported.records.map(record => record.index), [undefined, undefined]);
});

void test("CodeView a malformed callable body does not discard a following framed type", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1008, 4, []), ...codeViewArguments()], warnings));
  assert.deepEqual(parsed.records[0], { type: 0x1008, index: 0x1000 });
  assert.equal(parsed.records[1]?.shape?.kind, "arguments");
  assert.equal(parsed.records[1]?.index, 0x1001);
  assert.match(warnings.join(" | "), /bounds/);
});

void test("CodeView function IDs retain valid references when only their UTF-8 name is malformed", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1601, 4, [...legacyU32(0), ...legacyU32(0x1000), 0xff, 0])], warnings));
  assert.deepEqual(parsed.records[0], { type: 0x1601, index: 0x1000,
    shape: { kind: "functionId", scopeId: 0, functionType: 0x1000 } });
  assert.match(warnings.join(" | "), /type record/);
});

void test("CodeView type indices never wrap beyond their 32-bit namespace", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1200, 4, legacyU32(0xffffffff)),
    ...codeViewProcedure(), ...codeViewArguments()], warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [0x1000, 0xffffffff, undefined]);
  assert.match(warnings.join(" | "), /index space is exhausted/);
});

for (const record of [[1, 0, 2], [255, 255, 2], [1]]) {
  void test(`CodeView module types terminate safely on malformed record ${record}`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(1), ...record], warnings));

    assert.deepEqual(codeViewStoredTypeText(parsed.records), []);
    assert.match(warnings.join(" | "), /length|bounds/);
  });
}
