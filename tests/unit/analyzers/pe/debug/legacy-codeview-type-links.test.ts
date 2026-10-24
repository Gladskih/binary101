import assert from "node:assert/strict";
import { test } from "node:test";
import { readCodeViewTypeShape } from "../../../../../analyzers/pe/debug/legacy-codeview-type-shapes.js";
import { legacyReader, legacyU16, legacyU32 } from "../../../../fixtures/pe-legacy-codeview.js";
import { codeViewTextRecord } from "../../../../fixtures/pe-codeview-type-strings.js";
import { createPeWithCodeViewBuildInfo } from "../../../../fixtures/pe-codeview-build.js";
import { parsePeHeaders } from "../../../../../analyzers/pe/core/index.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { buildCodeViewBuildTables } from "../../../../../renderers/pe/codeview-build-tables.js";

// Packed lfDerived, lfBuildInfo and lfUdt[Mod]SrcLine from Microsoft's cvinfo.h.
for (const [leaf, bytes, expected] of [
  [0x205, [...legacyU16(2), ...legacyU16(0x1000), ...legacyU16(7)], { kind: "derived", indices: [0x1000, 7] }],
  [0x1204, [...legacyU32(1), ...legacyU32(0x12345678)], { kind: "derived", indices: [0x12345678] }],
  [0x1603, [...legacyU16(2), ...legacyU32(0x1000), ...legacyU32(0x87654321)],
    { kind: "buildInfo", indices: [0x1000, 0x87654321] }],
  [0x1604, [...legacyU32(1), ...legacyU32(0x1001)], { kind: "stringList", indices: [0x1001] }],
  [0x1605, legacyU32(0x1002), { kind: "stringId", substrings: 0x1002 }],
  [0x1606, [...legacyU32(0x1000), ...legacyU32(0x1001), ...legacyU32(123)],
    { kind: "sourceLine", typeIndex: 0x1000, source: 0x1001, line: 123 }],
  [0x1607, [...legacyU32(0x12345678), ...legacyU32(0x87654321), ...legacyU32(0xffffffff), ...legacyU16(0xffff)],
    { kind: "sourceLine", typeIndex: 0x12345678, source: 0x87654321, line: 0xffffffff, module: 0xffff }]
] as const) {
  void test(`CodeView type links ${leaf} retain every stored reference and count width`, async () => {
    const warnings: string[] = [];
    assert.deepEqual(await readCodeViewTypeShape(
      legacyReader(codeViewTextRecord(leaf, 4, bytes), warnings), leaf), expected);
    assert.deepEqual(warnings, []);
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4,
      bytes.slice(0, -1))), leaf), /bounds/);
  });
}

for (const [leaf, bytes, kind] of [[0x205, legacyU16(0), "derived"], [0x1204, legacyU32(0), "derived"],
  [0x1603, legacyU16(0), "buildInfo"], [0x1604, legacyU32(0), "stringList"]] as const) {
  void test(`CodeView empty reference list ${leaf} remains an empty list`, async () => {
    assert.deepEqual((await readCodeViewTypeShape(legacyReader(codeViewTextRecord(leaf, 4, bytes)), leaf)),
      { kind, indices: [] });
  });
}

for (const count of [0x10000, 0xffffffff]) {
  void test(`CodeView DWORD reference count ${count} cannot narrow or overrun its record`, async () => {
    await assert.rejects(readCodeViewTypeShape(legacyReader(codeViewTextRecord(0x1204, 4,
      legacyU32(count))), 0x1204), /bounds/);
  });
}

void test("PE integration retains embedded build arguments and exact source line references", async () => {
  const file = createPeWithCodeViewBuildInfo();
  const core = await parsePeHeaders(file);
  assert.ok(core);
  const debug = await parseDebugDirectory(file, core.dataDirs, core.rvaToOff, core.coff.Machine);
  const info = debug.entries[0]?.legacyCodeView;
  assert.ok(info);
  assert.equal(debug.warning, null);
  assert.deepEqual(buildCodeViewBuildTables(info).find(table => table.key === "typeSources")?.rows, [
    ["1", "1", "Base", "<source>&amp;.cpp", "123"],
    ["1", "1", "<Derived>&amp;", "module 2 string-table offset #32 (external)", "456"]
  ]);
});
