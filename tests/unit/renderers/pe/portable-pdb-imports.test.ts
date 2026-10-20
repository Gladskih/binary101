import assert from "node:assert/strict";
import { test } from "node:test";
import { renderPortablePdbImports, getPortablePdbImportTableModel } from "../../../../renderers/pe/portable-pdb-imports.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { parsePortablePdb } from "../../../../analyzers/pe/debug/portable-pdb.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createPortablePdbRoot, createPortablePdbStreams } from "../../../fixtures/portable-pdb.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createClrMetadataTablesWithParameterNames } from "../../../fixtures/pe-clr-metadata-tables.js";

const subject = async () => {
  const pdb = (await parsePortablePdb(new MockFile(createPortablePdbRoot(createPortablePdbStreams())), []))!;
  pdb.imports = [];
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(17, 0, 128), embeddedPortablePdb: {
    signature: "MPDB", compressedSize: 8, uncompressedSize: 32, portablePdb: pdb
  } }] };
  return { pe, pdb };
};

void test("Portable PDB imports preserve namespace and alias strings on every page", async () => {
  const { pe, pdb } = await subject();
  pdb.imports = [{ parent: 0, imports: [] }, { parent: 1,
    imports: Array.from({ length: 101 }, (_, index) => ({ kind: 7, alias: `<alias${index}>`, targetNamespace: "System" })) }];
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-imports")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.html),
    ["Namespace alias", "System", "&lt;alias100>", "2 (parent 1)"]);
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(100, 1), "System");
  assert.equal(model.sortValueAt(100, 4), "");
  assert.equal(model.sortValueAt(101, 0), "");
});

void test("Portable PDB imports resolve type names from parsed CLR metadata", async () => {
  const { pdb } = await subject();
  pdb.imports = [{ parent: 0, imports: [
    { kind: 3, targetType: { tableId: 2, row: 1 } },
    { kind: 2, targetAssembly: 1, targetNamespace: "Example" },
    { kind: 5, alias: "external" },
    { kind: 4, targetNamespace: "https://example.invalid/<xml>", alias: "<prefix>" }
  ] }];
  const out: string[] = [];
  renderPortablePdbImports(pdb, out, 0, createClrMetadataTablesWithParameterNames());

  assert.match(out.join(""), /Demo.Buffer/);
  assert.match(out.join(""), /Example \(AssemblyRef #1\)/);
  assert.match(out.join(""), /Alias from parent scope/);
  assert.match(out.join(""), /&lt;xml>/);
  assert.match(out.join(""), /&lt;prefix>/);
});

void test("Portable PDB imports explain missing names and omit empty scope tables", async () => {
  const { pe, pdb } = await subject();
  const out: string[] = [];
  renderPortablePdbImports(pdb, out, 0);
  pdb.imports = [{ parent: 0, imports: [
    { kind: 1, targetNamespace: null }, { kind: 1, targetNamespace: "" },
    { kind: 6, alias: null, targetAssembly: 0 }, { kind: 3, targetType: { tableId: 1, row: 1 } },
    { kind: 9, targetType: { tableId: 0x1b, row: 2 } }, { kind: 999 }
  ] }];
  const model = getPortablePdbImportTableModel(pe, "pe-debug-entry-0-imports")!;

  assert.equal(out.join(""), "");
  assert.match(model.rowAt(0)?.cells[1]?.html ?? "", /unreadable/);
  assert.match(model.rowAt(1)?.cells[1]?.html ?? "", /global namespace/);
  assert.match(model.rowAt(2)?.cells[2]?.html ?? "", /unreadable alias/);
  assert.match(model.rowAt(3)?.cells[1]?.html ?? "", /TypeRef #1/);
  assert.match(model.rowAt(4)?.cells[1]?.html ?? "", /TypeSpec #2/);
  assert.match(model.rowAt(5)?.cells[0]?.html ?? "", /Unknown import/);
  assert.equal(getPortablePdbImportTableModel(pe, "other"), null);
  assert.equal(getPortablePdbImportTableModel(createBasePe(), "pe-debug-entry-0-imports"), null);
});

void test("Portable PDB imports show assembly names and unresolved type kinds consistently", async () => {
  const { pe, pdb } = await subject();
  pdb.imports = [{ parent: 0, imports: [{ kind: 6, alias: "assembly", targetAssembly: 1 },
    { kind: 3, targetType: { tableId: 2, row: 99 } }, { kind: 3, targetType: { tableId: -1, row: 1 } }] }];
  const metadata = createClrMetadataTablesWithParameterNames();
  metadata.assemblyRefs = [{ row: 1, name: "<Library>", culture: null, version: "1.0.0.0",
    flags: 0, publicKeyOrToken: null, hashValue: null }];
  const out: string[] = [];
  renderPortablePdbImports(pdb, out, 0, metadata);

  assert.match(out.join(""), /&lt;Library>/);
  assert.match(out.join(""), /TypeDef #99/);
  assert.match(out.join(""), /Type #1/);
  assert.equal(getPortablePdbImportTableModel(pe, "pe-debug-entry-1-imports"), null);
});
