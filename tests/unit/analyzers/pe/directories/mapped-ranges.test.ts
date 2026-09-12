import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLoadConfigDirectory32 } from "../../../../../analyzers/pe/load-config/index.js";
import { collectLoadConfigDiagnostics } from "../../../../../analyzers/pe/load-config/warnings.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { parseImportDirectory32 } from "../../../../../analyzers/pe/imports/index.js";
import { readDelayThunkFunctions32, readDelayThunkFunctions64 }
  from "../../../../../analyzers/pe/imports/delay-thunk-table.js";
import { parseDelayImports32 } from "../../../../../analyzers/pe/imports/delay.js";
import { parseDebugDirectory } from "../../../../../analyzers/pe/debug/directory.js";
import { parseClrDirectory } from "../../../../../analyzers/pe/clr/index.js";
import { parseBaseRelocations } from "../../../../../analyzers/pe/directories/reloc.js";
import { buildResourceTree } from "../../../../../analyzers/pe/resources/core.js";
import { createPeRvaFragments } from "../../../../helpers/pe-rva-fragments.js";

void test("import descriptor fields cross file fragments without inventing an import", async () => {
  // PE Import Directory Table: a complete all-zero 20-byte descriptor terminates the table.
  const fixture = createPeRvaFragments(0x1000, new Uint8Array(20), 3);
  const result = await parseImportDirectory32(fixture.reader,
    [{ name: "IMPORT", rva: 0x1000, size: 20 }], fixture.mapping);
  assert.deepEqual(result.entries, []);
  assert.equal(result.warning, undefined);
});

void test("delay descriptors cross file fragments without inventing an import", async () => {
  // PE Delay-Load Import Tables: an all-zero 32-byte descriptor terminates the table.
  const fixture = createPeRvaFragments(0x1000, new Uint8Array(32), 7);
  const result = await parseDelayImports32(fixture.reader,
    [{ name: "DELAY_IMPORT", rva: 0x1000, size: 32 }], fixture.mapping);
  assert.deepEqual(result?.entries, []);
  assert.equal(result?.warning, undefined);
});

void test("debug directory headers cross file fragments without corrupting the type", async () => {
  // PE Debug Directory: 28-byte IMAGE_DEBUG_DIRECTORY, Type at byte 12.
  const bytes = new Uint8Array(28);
  new DataView(bytes.buffer).setUint32(12, 16, true); // IMAGE_DEBUG_TYPE_REPRO
  const fixture = createPeRvaFragments(0x1000, bytes, 13);
  const result = await parseDebugDirectory(fixture.reader,
    [{ name: "DEBUG", rva: 0x1000, size: 28 }], fixture.mapping, 0x8664);
  assert.equal(result.entries[0]?.type, 16);
});

void test("CLR header fields cross file fragments", async () => {
  // ECMA-335 II.25.3.3: 72-byte CLI header, major runtime version at byte 4.
  const bytes = new Uint8Array(72);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 72, true);
  view.setUint16(4, 2, true);
  const fixture = createPeRvaFragments(0x1000, bytes, 5);
  const result = await parseClrDirectory(fixture.reader,
    [{ name: "CLR_RUNTIME", rva: 0x1000, size: 72 }], fixture.mapping);
  assert.equal(result?.MajorRuntimeVersion, 2);
});

void test("relocation headers and WORDs cross file fragments", async () => {
  const bytes = new Uint8Array(12);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x2000, true);
  view.setUint32(4, 12, true);
  view.setUint16(8, 0x3001, true); // HIGHLOW, offset 1; next WORD is ABSOLUTE padding.
  const fixture = createPeRvaFragments(0x1000, bytes, 9);
  const result = await parseBaseRelocations(fixture.reader,
    [{ name: "BASERELOC", rva: 0x1000, size: 12 }], fixture.mapping);
  assert.deepEqual(result?.blocks[0]?.entries, [{ type: 3, offset: 1 }, { type: 0, offset: 0 }]);
  assert.equal(result?.warnings, undefined);
});

void test("resource directory headers cross file fragments", async () => {
  // PE Resource Directory: 16-byte header with counts at bytes 12 and 14.
  const fixture = createPeRvaFragments(0x1000, new Uint8Array(16), 13);
  const result = await buildResourceTree(fixture.reader,
    [{ name: "RESOURCE", rva: 0x1000, size: 16 }], fixture.mapping);
  assert.equal(result?.directories?.[0]?.idEntries, 0);
  assert.deepEqual(result?.issues ?? [], []);
});

void test("debug directory continues from EOF into an earlier file fragment", async () => {
  const bytes = new Uint8Array(28);
  new DataView(bytes.buffer).setUint32(12, 16, true);
  const fixture = createPeRvaFragments(0x1000, bytes, 13, 64, 0);
  const result = await parseDebugDirectory(fixture.reader,
    [{ name: "DEBUG", rva: 0x1000, size: 28 }], fixture.mapping, 0x8664);
  assert.equal(result.entries[0]?.type, 16);
  assert.equal(result.warning, null);
});

void test("load-config diagnostics validate complete mapped tables across EOF", async () => {
  const bytes = new Uint8Array(256);
  const view = new DataView(bytes.buffer);
  // PE32 load-config: Size, GuardCFFunctionTable VA, GuardCFFunctionCount.
  view.setUint32(16, 0xc0, true);
  view.setUint32(16 + 0x50, 0x401000, true);
  view.setUint32(16 + 0x54, 2, true);
  const config = await parseLoadConfigDirectory32(new MockFile(bytes),
    [{ name: "LOAD_CONFIG", rva: 16, size: 0xc0 }], rva => rva);
  assert.ok(config);
  const fragments = createPeRvaFragments(0x1000, new Uint8Array(8), 4, 12, 0);
  const valid = collectLoadConfigDiagnostics(16, fragments.mapping, 0x400000n, 0x2000, config);
  const gap = collectLoadConfigDiagnostics(16,
    rva => rva === 0x1004 ? null : fragments.mapping(rva), 0x400000n, 0x2000, config);
  assert.doesNotMatch(valid.warnings.join(" "), /GuardCFFunctionTable/);
  assert.match(gap.warnings.join(" "), /GuardCFFunctionTable.*mapped file data/);
});

void test("delay thunk terminators can continue from EOF into earlier file data", async () => {
  const fixture = createPeRvaFragments(0x1000, new Uint8Array(8), 1, 64, 0);
  const warnings = new Set<string>();
  assert.deepEqual(await readDelayThunkFunctions32(fixture.reader,
    fixture.mapping, 0x1000, warnings, () => 1), { functions: [], terminated: true });
  assert.deepEqual(await readDelayThunkFunctions64(fixture.reader,
    fixture.mapping, 0x1000, warnings, () => 1), { functions: [], terminated: true });
  assert.equal(warnings.size, 0);
});
