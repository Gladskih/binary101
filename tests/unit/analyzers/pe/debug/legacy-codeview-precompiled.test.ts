import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewTypeShape } from "../../../../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { readCodeViewPrecompiledType } from "../../../../../analyzers/pe/debug/legacy-codeview-precompiled.js";
import { readLegacyCodeViewModuleTypes } from "../../../../../analyzers/pe/debug/legacy-codeview-type-records.js";
import { legacyReader, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { codeViewArguments } from "../../../../fixtures/pe-codeview-callables.js";
import { codeViewPrecompiledRecord, createPeWithCodeViewPrecompiledTypes } from "../../../../fixtures/pe-codeview-precompiled.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { buildCodeViewBuildTables } from "../../../../../renderers/pe/codeview-build-tables.js";

for (const leaf of [0x13, 0x100e, 0x1509]) {
  void test(`CodeView precompiled import ${leaf} preserves its packed index widths and signature`, async () => {
    assert.deepEqual(await readCodeViewTypeShape(legacyReader(codeViewPrecompiledRecord(leaf)), leaf),
      { kind: "precompiled", start: 0x1000, count: 3, signature: 0x12345678 });
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4, [0])), leaf), /bounds/);
  });

  void test(`CodeView resumes local type numbering after precompiled import ${leaf}`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewPrecompiledRecord(leaf), ...codeViewArguments(), ...codeViewArguments([])], warnings));
    assert.deepEqual(parsed.records.map(record => record.index), [undefined, 0x1003, 0x1004]);
    assert.deepEqual(warnings, []);
  });
}

void test("CodeView a precompiled creator retains local identities after LF_ENDPRECOMP", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4), ...codeViewArguments(),
    ...codeViewTextRecord(0x14, 4, legacyU32(0x12345678)), ...codeViewArguments([])], warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [0x1000, 0x1001, 0x1002]);
  assert.deepEqual(parsed.records[1]?.shape, { kind: "endPrecompiled", signature: 0x12345678 });
  assert.deepEqual(warnings, []);
});

for (const leaf of [0x100e, 0x1509]) {
  void test(`CodeView wide import ${leaf} retains DWORD starts and counts after LF_SKIP`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewTextRecord(0x1200, 4, legacyU32(0x12345678)),
      ...codeViewPrecompiledRecord(leaf, 0x12345678, 0x10001), ...codeViewArguments()], warnings));
    assert.deepEqual(parsed.records.map(record => record.index), [0x1000, undefined, 0x12355679]);
    assert.deepEqual(parsed.records[1]?.shape,
      { kind: "precompiled", start: 0x12345678, count: 0x10001, signature: 0x12345678 });
    assert.deepEqual(warnings, []);
  });
}

for (const start of [0xfff, 0x1001]) {
  void test(`CodeView inconsistent precompiled start ${start} cannot invent subsequent local identities`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewPrecompiledRecord(0x1509, start), ...codeViewArguments()], warnings));
    assert.deepEqual(parsed.records.map(record => record.index), [undefined, undefined]);
    assert.match(warnings.join(" | "), /precompiled.*start/i);
  });
}

void test("CodeView zero-length imports preserve the next unused index", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewPrecompiledRecord(0x1509, 0x1000, 0), ...codeViewArguments()], warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [undefined, 0x1000]);
  assert.deepEqual(warnings, []);
});

void test("CodeView a precompiled import can leave exactly the last valid local index", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewPrecompiledRecord(0x1509, 0x1000, 0xffffefff), ...codeViewArguments(),
    ...codeViewArguments([])], warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [undefined, 0xffffffff, undefined]);
  assert.deepEqual(warnings, ["CodeView type index space is exhausted; later indices are unresolved."]);
});

for (const count of [0xfffff000, 0xfffff001, 0xffffffff]) {
  void test(`CodeView precompiled import count ${count} cannot wrap local type indices`, async () => {
    const warnings: string[] = [];
    const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
      ...codeViewPrecompiledRecord(0x1509, 0x1000, count), ...codeViewArguments()], warnings));
    assert.deepEqual(parsed.records.map(record => record.index), [undefined, undefined]);
    assert.match(warnings.join(" | "), /precompiled.*32-bit type index space/);
  });
}

void test("CodeView malformed import headers leave indices unresolved without hiding later framed types", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1509, 4, [0]), ...codeViewArguments()], warnings));
  assert.equal(parsed.records.length, 2);
  assert.equal(parsed.records[1]?.index, undefined);
  assert.match(warnings.join(" | "), /type record:.*bounds/);
  assert.match(warnings.join(" | "), /precompiled.*starting type index/);
});

void test("CodeView invalid import text cannot discard the valid stored range", async () => {
  const warnings: string[] = [];
  const imported = codeViewPrecompiledRecord();
  imported[imported.length - 2] = 0xff; // Invalid UTF-8; record framing and fixed fields remain intact.
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...imported, ...codeViewArguments()], warnings));
  assert.equal(parsed.records[1]?.index, 0x1003);
  assert.equal(parsed.records[0]?.strings, undefined);
  assert.match(warnings.join(" | "), /type record/);
});

void test("CodeView an unknown namespace cannot be restored by an unverified later PCH marker", async () => {
  const warnings: string[] = [];
  const parsed = await readLegacyCodeViewModuleTypes(legacyReader([...legacyU32(4),
    ...codeViewTextRecord(0x1200, 4, legacyU32(0)), ...codeViewPrecompiledRecord(),
    ...codeViewArguments()], warnings));
  assert.deepEqual(parsed.records.map(record => record.index), [0x1000, undefined, undefined]);
});

void test("CodeView precompiled readers leave unknown leaves untouched and bound the creator signature", async () => {
  assert.equal(await readCodeViewPrecompiledType(legacyReader([]), 0xffff), undefined);
  assert.deepEqual(await readCodeViewPrecompiledType(legacyReader(codeViewTextRecord(0x14, 4,
    legacyU32(0xffffffff))), 0x14), { kind: "endPrecompiled", signature: 0xffffffff });
  await assert.rejects(readCodeViewPrecompiledType(legacyReader(codeViewTextRecord(0x14, 4, [0])), 0x14), /bounds/);
});

void test("PE debug integration resolves local type source names following a precompiled import", async () => {
  const file = createPeWithCodeViewPrecompiledTypes();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const info = debug.entries[0]?.legacyCodeView;
  assert.ok(info);
  assert.equal(debug.warning, null);
  assert.deepEqual(buildCodeViewBuildTables(info).find(table => table.key === "typeSources")?.rows,
    [["1", "1", "PchLocal", "PchConsumer.cpp", "2"]]);
});
