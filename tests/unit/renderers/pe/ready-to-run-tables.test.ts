import assert from "node:assert/strict";
import { test } from "node:test";
import { createReadyToRunTableModels, getReadyToRunTableModel, renderReadyToRunData } from
  "../../../../renderers/pe/ready-to-run-tables.js";
import type { PeClrReadyToRun } from "../../../../analyzers/pe/clr/ready-to-run-types.js";
import type { PeClrHeader } from "../../../../analyzers/pe/clr/types.js";

const fixture = (): PeClrReadyToRun => ({
  status: "ready-to-run", signature: 0x00525452, majorVersion: 16, minorVersion: 0,
  flags: 0, sectionCount: 7, issues: [], sections: [
    { type: 100, name: "CompilerIdentifier", rva: 16, size: 4,
      decoded: { kind: "text", text: "<compiler>" } },
    { type: 101, name: "ImportSections", rva: 32, size: 20, decoded: {
      kind: "imports", imports: [{ rva: 128, size: 8, flags: 1, type: 2, entrySize: 4,
        signaturesRva: 144, auxiliaryDataRva: 160, entries: [
          { value: Uint8Array.of(0x12, 0x34, 0x56, 0x78), signatureRva: 176 },
          { value: Uint8Array.of(0, 0, 0, 0), signatureRva: null }]
      }] } },
    { type: 103, name: "MethodDefEntryPoints", rva: 64, size: 8, decoded: {
      kind: "methods", methods: [
        { methodRid: 1, runtimeFunctionIndex: 2, fixupOffset: 4 },
        { methodRid: 3, runtimeFunctionIndex: 5, fixupOffset: null }]
    } },
    { type: 115, name: "ComponentAssemblies", rva: 80, size: 16, decoded: {
      kind: "components", entries: [{ clrRva: 256, clrSize: 72,
        coreHeaderRva: 512, coreHeaderSize: 32 }]
    } },
    { type: 120, name: "HotColdMap", rva: 96, size: 8, decoded: {
      kind: "hot-cold", entries: [{ coldRuntimeFunction: 3, hotRuntimeFunction: 1 }]
    } },
    { type: 999, name: "<unknown>", rva: 112, size: 0 },
    { type: 101, name: "EmptyImports", rva: 112, size: 0, decoded: {kind:"imports",imports:[]} }
  ]
});

void test("exposes sections, import cells, method entry points and composite directories", () => {
  const models = createReadyToRunTableModels(fixture());

  assert.equal(models.length, 8);
  assert.deepEqual(models.map(table => table.id), [
    "pe-r2r-sections", "pe-r2r-1-imports", "pe-r2r-1-cells", "pe-r2r-2-methods",
    "pe-r2r-3-components", "pe-r2r-4-hot-cold", "pe-r2r-6-imports", "pe-r2r-6-cells"
  ]);
  assert.equal(models[0]?.rowCount, 7);
  assert.equal(models[0]?.rowAt(5)?.cells[1]?.html, "&lt;unknown>");
  assert.equal(models[1]?.rowAt(0)?.cells[1]?.html, "0x00000080");
  assert.equal(models[2]?.rowAt(0)?.cells[2]?.html, "0x00000080");
  assert.equal(models[2]?.rowAt(1)?.cells[2]?.html, "0x00000084");
  assert.equal(models[2]?.rowAt(0)?.cells[3]?.html, "12 34 56 78");
  assert.equal(models[2]?.rowAt(0)?.cells[4]?.html, "0x000000b0");
  assert.equal(models[2]?.rowAt(1)?.cells[4]?.html, "-");
  assert.equal(models[3]?.rowAt(0)?.cells[2]?.html, "0x00000044");
  assert.equal(models[3]?.rowAt(1)?.cells[2]?.html, "-");
  assert.equal(models[4]?.id, "pe-r2r-3-components");
  assert.equal(models[4]?.rowAt(0)?.cells[0]?.html, "0x00000100");
  assert.equal(models[5]?.rowAt(0)?.cells[0]?.html, "3");
  assert.equal(models[0]?.rowAt(-1), null);
  assert.equal(models[0]?.sortValueAt(-1, 100), "");
  assert.equal(models[3]?.sortValueAt(0, 0), "1");
  assert.equal(models[0]?.columns[0]?.className, "peNumeric");
  assert.equal(models[0]?.rowAt(0)?.cells[0]?.className, "peNumeric");
  assert.equal(models[0]?.rowAt(0)?.cells[1]?.className, "");
});

void test("routes pagination and escapes compiler text within valid definition lists", () => {
  const clr = { readyToRun: fixture() } as PeClrHeader;

  assert.equal(getReadyToRunTableModel(clr, "pe-r2r-2-methods")?.rowCount, 2);
  assert.equal(getReadyToRunTableModel(clr, "pe-r2r-unknown"), null);
  assert.equal(getReadyToRunTableModel(clr, "unknown"), null);
  assert.equal(getReadyToRunTableModel(null, "pe-r2r-sections"), null);
  assert.match(renderReadyToRunData(fixture()), /<dl><dt/);
  assert.match(renderReadyToRunData(fixture()), /&lt;compiler>/);
  assert.doesNotMatch(renderReadyToRunData(fixture()), /<compiler>/);
  assert.equal(renderReadyToRunData({ ...fixture(), sections: [] }), "");
  assert.match(renderReadyToRunData(fixture()), /<table[\s\S]*MethodDef RID/);
});

void test("labels every table and right-aligns numeric headers and cells", () => {
  const models = createReadyToRunTableModels(fixture());

  assert.deepEqual(models.slice(0, 6).map(table => table.columns.map(column => column.label)), [
    ["Type", "Name", "RVA", "Size"],
    ["Index", "Cells RVA", "Size", "Flags", "Type", "Entry size", "Signatures RVA", "Auxiliary RVA"],
    ["Import", "Cell", "RVA", "Bytes", "Signature RVA"],
    ["MethodDef RID", "Runtime function index", "Fixups RVA"],
    ["CLR RVA", "CLR size", "Core header RVA", "Core header size"],
    ["Cold runtime function", "Hot runtime function"]
  ]);
  assert.equal(models[0]?.columns[1]?.className, "");
  assert.equal(models[2]?.columns[3]?.className, "");
  assert.equal(models[2]?.rowAt(0)?.cells[3]?.className, "");
  assert.deepEqual(models[1]?.rowAt(0)?.cells.map(cell => cell.html),
    ["0", "0x00000080", "8", "0x0001", "2", "4", "0x00000090", "0x000000a0"]);
  assert.deepEqual(models[3]?.rowAt(0)?.cells.map(cell => cell.html), ["1", "2", "0x00000044"]);
  assert.deepEqual(models[4]?.rowAt(0)?.cells.map(cell => cell.html),
    ["0x00000100", "72", "0x00000200", "32"]);
  assert.deepEqual(models[5]?.rowAt(0)?.cells.map(cell => cell.html), ["3", "1"]);
});
