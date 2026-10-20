import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPortablePdb, getPortablePdbTableModel } from "../../../../renderers/pe/portable-pdb.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { parsePortablePdb } from "../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../fixtures/portable-pdb.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("Portable PDB presents source and metadata statistics without hexadecimal tables", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  const out: string[] = [];
  renderPortablePdb(pdb!, out);

  assert.match(out.join(""), /Visible sequence points/);
  assert.match(out.join(""), /Hidden sequence points/);
  assert.match(out.join(""), /Source documents: C#/);
  assert.match(out.join(""), /StateMachineMethod/);
  assert.match(out.join(""), /LocalVariable/);
  assert.match(out.join(""), /Source Link/);
  assert.match(out.join(""), /<td>local<\/td>/);
  assert.match(out.join(""), /<td>constant<\/td>/);
  assert.match(out.join(""), /int32: 3/);
  assert.match(out.join(""), /never fetched/);
  assert.doesNotMatch(out.join(""), /0x|3f5162f8/);
});

void test("Portable PDB connects decoded custom records and escapes constant strings", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.locals = [{ kind: "constant", name: "text", signatureSize: 17,
    constant: { typeCode: 14, value: "<script>" } }];
  pdb!.customRecords = [
    { kind: "ed9fdf71-8879-4747-8ed3-fe5ede3ce710", size: 5, parent: { tableId: 0x33, row: 1 },
      data: { type: "tupleNames", names: ["element"] } },
    { kind: "0e8a571b-6926-466e-b4ad-8ab04611f5fe", size: 16, parent: { tableId: 0x30, row: 1 },
      data: { type: "embeddedSource", source: { storage: "raw", bytes: 12, lines: 2, encoding: "UTF-8" } } }
  ];
  const out: string[] = [];
  renderPortablePdb(pdb!, out);

  assert.match(out.join(""), /Tuple element names/);
  assert.match(out.join(""), /12 source bytes; 2 lines/);
  assert.match(out.join(""), /&lt;script>/);
  assert.doesNotMatch(out.join(""), /<script>/);
});

void test("Portable PDB distinguishes unknown custom records and escapes table names", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.customRecords = [{ kind: null, size: null, parent: { tableId: 0, row: 1 } },
    { kind: "unknown", size: 8, parent: { tableId: 0, row: 1 } }];
  pdb!.documents[0]!.language = "unknown";
  pdb!.tables[0]!.name = "<script>";
  const out: string[] = [];
  renderPortablePdb(pdb!, out);

  assert.match(out.join(""), /Other custom debug information/);
  assert.match(out.join(""), /Other or unspecified language/);
  assert.match(out.join(""), /&lt;script>/);
  assert.doesNotMatch(out.join(""), /<script>/);
});

void test("Portable PDB omits empty language and custom-record summaries", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.documents = [];
  pdb!.customRecords = [];
  pdb!.locals = [];
  const out: string[] = [];
  renderPortablePdb(pdb!, out);

  assert.doesNotMatch(out.join(""), /Source documents:|Custom debug information|Local symbol/);
});

void test("Portable PDB local symbols retain names across pages and explain unreadable metadata", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.locals = Array.from({ length: 100 }, (_, slot) => ({
    kind: "variable", name: `<local${slot}>`, slot, attributes: 1
  }));
  pdb!.locals.push({ kind: "constant", name: null, signatureSize: null, constant: null });
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb!
  } }] };
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-locals")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html), [
    "&lt;local0>", "Variable", "Slot 0; hidden from debugger"
  ]);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.html), [
    "(unreadable name)", "Constant", "Signature: unknown bytes"
  ]);
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(0, 0), "<local0>");
  assert.equal(model.sortValueAt(0, 1), "variable");
  assert.equal(model.sortValueAt(0, 2), "Slot 0; hidden from debugger");
  assert.equal(model.sortValueAt(0, 3), "");
  assert.equal(model.sortValueAt(100, 0), "");
  assert.equal(model.sortValueAt(101, 0), "");
});

void test("Portable PDB source names remain accessible on all pages", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.documents = Array.from({ length: 101 }, (_, index) => ({ ...pdb!.documents[0]!, name: `file${index}.cs` }));
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb!
  } }] };
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-documents")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.html), ["file100.cs", "C#", "SHA-256 (32 bytes)"]);
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(100, 0), "file100.cs");
  assert.equal(model.sortValueAt(100, 1), "C#");
  assert.equal(model.sortValueAt(100, 2), "8829d00f-11b8-4213-878b-770e8597ac16");
  assert.equal(model.sortValueAt(100, 3), "");
  assert.equal(model.sortValueAt(101, 0), "");
  assert.equal(getPortablePdbTableModel(pe, "other"), null);
  assert.equal(getPortablePdbTableModel(createBasePe(), "pe-debug-entry-0-documents"), null);
});

void test("Portable PDB source table explains unreadable names and unspecified language or checksum", async () => {
  const pdb = await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []);
  pdb!.documents = [{ name: null, language: null, hashAlgorithm: null, hashSize: null }];
  const out: string[] = [];
  renderPortablePdb(pdb!, out);

  assert.match(out.join(""), /unreadable name/);
  assert.match(out.join(""), /Other or unspecified/);
  assert.match(out.join(""), /unknown bytes/);
});
