import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPortablePdbCustom, getPortablePdbCustomTableModel } from "../../../../renderers/pe/portable-pdb-custom.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import type { PortablePdbCustomRecord } from "../../../../analyzers/pe/debug/portable-pdb-types.js";
import { parsePortablePdb } from "../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../fixtures/portable-pdb.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";

const subject = async (records: PortablePdbCustomRecord[]) => {
  const pdb = (await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []))!;
  pdb.customRecords = records;
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb
  } }] };
  return { pe, pdb };
};

void test("Portable PDB custom tables keep Source Link mappings as escaped text", async () => {
  const { pe, pdb } = await subject([{ kind: "cc110556-a091-4d38-9fec-25ab9a351a6a", size: 32,
    parent: { tableId: 0, row: 1 }, data: { type: "sourceLink", documents: [
      { pattern: "<source.cs>", url: "https://example.invalid/<source.cs>" }
    ] } }]);
  const out: string[] = [];
  renderPortablePdbCustom(pdb, out, 0);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-custom-0")!;

  assert.match(out.join(""), /Source Link/);
  assert.match(out.join(""), /never fetched/);
  assert.match(out.join(""), /&lt;source.cs>/);
  assert.doesNotMatch(out.join(""), /<source.cs>|href=|https:\/\/example.invalid\/<source.cs>/);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html),
    ["&lt;source.cs>", "https://example.invalid/&lt;source.cs>"]);
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(0, 0), "<source.cs>");
  assert.equal(model.sortValueAt(0, 2), "");
  assert.equal(model.sortValueAt(1, 0), "");
});

void test("Portable PDB custom options retain names and values on every page", async () => {
  const { pe } = await subject([{ kind: "b5feec05-8cd0-4a83-96da-466284bb4bd8", size: 2048,
    parent: { tableId: 0, row: 1 }, data: { type: "options", options: Array.from({ length: 101 }, (_, index) =>
      ({ name: `option${index}`, value: `value${index}` })) } }]);
  const model = getPortablePdbCustomTableModel(pe, "pe-debug-entry-0-custom-0")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.html), ["option100", "value100"]);
  assert.equal(model.rowAt(101), null);
});

void test("Portable PDB custom summaries explain state data without address tables", async () => {
  const { pdb } = await subject([
    { kind: "unknown", size: null, parent: { tableId: -1, row: 0 } },
    { kind: null, size: 0, parent: { tableId: 0, row: 0 } },
    { kind: "6da9a61e-f8c7-4874-be62-68bc5630df71", size: 16, parent: { tableId: 6, row: 1 },
      data: { type: "hoistedScopes", scopes: 2, inactiveScopes: 1, totalIlBytes: 32 } },
    { kind: "83c563c4-b4f3-47d5-b824-ba5441477ea8", size: 1, parent: { tableId: 0x33, row: 1 },
      data: { type: "dynamicFlags", storedBits: 8, setBits: 2 } },
    { kind: "755f52a8-91c5-45be-b4b8-209571e552bd", size: 4, parent: { tableId: 6, row: 1 },
      data: { type: "encSlots", slots: 3, temporaries: 1, ordinalSlots: 1 } },
    { kind: "a643004c-0240-496f-a783-30d64f4979de", size: 4, parent: { tableId: 6, row: 1 },
      data: { type: "encLambdas", closures: 2, lambdas: 3 } },
    { kind: "8b78cd68-2ede-420b-980b-e15884b8aaa3", size: 4, parent: { tableId: 6, row: 1 },
      data: { type: "encStates", states: 3 } },
    { kind: "54fd2ac5-e925-401a-9c2a-f94f171072f8", size: 4, parent: { tableId: 6, row: 1 },
      data: { type: "asyncStepping", hasCatchHandler: true, awaits: 2 } },
    { kind: "9d40ace1-c703-4d0e-bf41-7243060a8fb5", size: 0, parent: { tableId: 6, row: 1 },
      data: { type: "primaryConstructor" } },
    { kind: "0e8a571b-6926-466e-b4ad-8ab04611f5fe", size: 16, parent: { tableId: 0x30, row: 1 },
      data: { type: "embeddedSource", source: { storage: "deflate", bytes: 64, lines: 3, encoding: "UTF-8" } } }
  ]);
  const out: string[] = [];
  renderPortablePdbCustom(pdb, out, 0);

  assert.match(out.join(""), /Hoisted local scopes/);
  assert.match(out.join(""), /2 scopes; 1 inactive; summed IL length 32 bytes/);
  assert.match(out.join(""), /2 set flags in 8 stored bits/);
  assert.match(out.join(""), /3 slots; 1 temporary; 1 with ordinals/);
  assert.match(out.join(""), /2 closures; 3 lambdas/);
  assert.match(out.join(""), /3 state entries/);
  assert.match(out.join(""), /2 awaits; catch handler present/);
  assert.match(out.join(""), /Primary constructor marker/);
  assert.match(out.join(""), /64 source bytes; 3 lines; UTF-8; deflate/);
  assert.match(out.join(""), /source.cs/);
  assert.doesNotMatch(out.join(""), /0x|Start RVA|Yield offset|Resume offset/);
});

void test("Portable PDB custom strings, references and document names remain readable", async () => {
  const { pe, pdb } = await subject([
    { kind: "ed9fdf71-8879-4747-8ed3-fe5ede3ce710", size: 4, parent: { tableId: 0x34, row: 1 },
      data: { type: "tupleNames", names: ["<item>", ""] } },
    { kind: "58b2eab6-209f-4e4e-a22c-b2d0f910c782", size: 4, parent: { tableId: 0, row: 1 },
      data: { type: "defaultNamespace", name: "<Namespace>" } },
    { kind: "7e4d4708-096e-4c5c-aeda-cb10ba6a740d", size: 64, parent: { tableId: 0, row: 1 },
      data: { type: "references", references: [{ fileName: "Library.dll", aliases: "global,example",
        flags: 3, fileSize: 4096, timeStamp: 0, mvid: null }] } },
    { kind: "932e74bc-dba9-4478-8d46-0f32a7bab3d3", size: 2, parent: { tableId: 2, row: 1 },
      data: { type: "typeDocuments", documents: [1, 9] } }
  ]);
  const out: string[] = [];
  renderPortablePdbCustom(pdb, out, 0);

  assert.match(out.join(""), /&lt;item>/);
  assert.match(out.join(""), /unnamed element/);
  assert.match(out.join(""), /&lt;Namespace>/);
  assert.match(out.join(""), /Library.dll/);
  assert.match(out.join(""), /global,example/);
  assert.match(out.join(""), /Assembly; embed interop types/);
  assert.match(out.join(""), /source.cs/);
  assert.match(out.join(""), /unreadable document/);
  assert.deepEqual(getPortablePdbCustomTableModel(pe, "pe-debug-entry-0-custom-2")?.rowAt(0)?.cells.map(cell => cell.html),
    ["Library.dll", "global,example", "Assembly; embed interop types", "4096"]);
});

void test("Portable PDB custom models handle absent and unsupported records", async () => {
  const { pe, pdb } = await subject([]);
  const out: string[] = [];
  renderPortablePdbCustom(pdb, out, 0);

  assert.equal(out.join(""), "");
  assert.equal(getPortablePdbCustomTableModel(pe, "other"), null);
  assert.equal(getPortablePdbCustomTableModel(pe, "pe-debug-entry-0-custom-0"), null);
  assert.equal(getPortablePdbCustomTableModel(createBasePe(), "pe-debug-entry-0-custom"), null);
});

void test("Portable PDB custom tables distinguish empty data and resolve metadata owners", async () => {
  const { pe, pdb } = await subject([
    { kind: "58b2eab6-209f-4e4e-a22c-b2d0f910c782", size: 0, parent: { tableId: 0, row: 1 },
      data: { type: "defaultNamespace", name: "" } },
    { kind: "0e8a571b-6926-466e-b4ad-8ab04611f5fe", size: 4, parent: { tableId: 6, row: 1 },
      data: { type: "embeddedSource", source: null } },
    { kind: "0e8a571b-6926-466e-b4ad-8ab04611f5fe", size: 8, parent: { tableId: 2, row: 1 },
      data: { type: "embeddedSource", source: { storage: "raw", bytes: 4, lines: null, encoding: null } } },
    { kind: "54fd2ac5-e925-401a-9c2a-f94f171072f8", size: 4, parent: { tableId: 6, row: 2 },
      data: { type: "asyncStepping", hasCatchHandler: false, awaits: 0 } },
    { kind: "7e4d4708-096e-4c5c-aeda-cb10ba6a740d", size: 0, parent: { tableId: 0, row: 1 },
      data: { type: "references", references: [] } },
    { kind: "7e4d4708-096e-4c5c-aeda-cb10ba6a740d", size: 32, parent: { tableId: 0, row: 1 },
      data: { type: "references", references: [{ fileName: "Module.netmodule", aliases: "", flags: 4,
        timeStamp: 0, fileSize: 64, mvid: null }] } }
  ]);
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.modules = [{ row: 1, name: "Example.dll", mvid: null }];
  const out: string[] = [];
  renderPortablePdbCustom(pdb, out, 0, metadata);
  const summary = getPortablePdbCustomTableModel(pe, "pe-debug-entry-0-custom")!;

  assert.match(out.join(""), /empty namespace/);
  assert.match(out.join(""), /not decoded; see diagnostics/);
  assert.match(out.join(""), /unknown lines; unknown encoding/);
  assert.match(out.join(""), /catch handler absent/);
  assert.match(out.join(""), /Demo.Buffer/);
  assert.match(out.join(""), /Copy/);
  assert.match(out.join(""), /Example.dll/);
  assert.match(out.join(""), /Netmodule; reserved flags present/);
  assert.equal(getPortablePdbCustomTableModel(pe, "pe-debug-entry-0-custom-1"), null);
  assert.equal(summary.rowAt(99), null);
  assert.equal(summary.sortValueAt(99, 0), "");
});
