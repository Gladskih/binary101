import assert from "node:assert/strict";
import { test } from "node:test";
import { renderItaniumRtti, getItaniumRttiTableModel } from
  "../../../../renderers/pe/itanium-rtti.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import type { ItaniumRttiAnalysis } from "../../../../analyzers/itanium-rtti/types.js";

void test("keeps encoded class names and RTTI base offsets in their labeled columns", () => {
  const analysis: ItaniumRttiAnalysis = { warnings: [], types: [
    { address: 0x1234, name: "4Type", kind: "vmi", flags: 3, bases: [
      { typeAddress: 0x5678, offset: -24, isVirtual: true, isPublic: false },
      { typeAddress: 0x9010, offset: 16, isVirtual: false, isPublic: true }
    ] },
    { address: 0x5678, name: "4Base", kind: "class", bases: [] }
  ] };
  const types = getItaniumRttiTableModel(analysis, "pe-itanium-types")!;
  const bases = getItaniumRttiTableModel(analysis, "pe-itanium-bases")!;

  assert.deepEqual(types.columns.map(column => column.label),
    ["RVA", "Encoded name", "Kind", "Hierarchy flags"]);
  assert.deepEqual(types.rowAt(0)!.cells.map(cell => cell.html), ["0x1234", "4Type", "vmi", "0x3"]);
  assert.equal(types.rowAt(1)!.cells[3]!.html, "—");
  assert.deepEqual(bases.columns.map(column => column.label),
    ["Type RVA", "Base RVA", "Access", "Offset kind", "Offset"]);
  assert.deepEqual(bases.rowAt(0)!.cells.map(cell => cell.html),
    ["0x1234", "0x5678", "Non-public", "Virtual: vtable slot", "-24"]);
  assert.deepEqual(bases.rowAt(1)!.cells.map(cell => cell.html),
    ["0x1234", "0x9010", "Public", "Object", "16"]);
  assert.equal(bases.columns[3]!.className, "");
  assert.equal(bases.columns[4]!.className, "peNumeric");
  assert.match(renderItaniumRtti(analysis), /<h4>Class types<\/h4>/);
  assert.match(renderItaniumRtti(analysis), /<h4>Direct bases<\/h4>/);
});

void test("omits absent RTTI and unrelated tables", () => {
  assert.equal(renderItaniumRtti(null), "");
  assert.equal(getItaniumRttiTableModel(undefined, "pe-itanium-types"), null);
  assert.equal(getItaniumRttiTableModel({ types: [], warnings: [] }, "other"), null);
});
void test("renders class names, bases and warnings without vtables or methods", async () => {
  const analysis = (await discoverItaniumRtti(createItaniumFixture().image))!;
  analysis.types[0]!.name = "<script>";
  analysis.types[0]!.bases.push({ typeAddress: 1, offset: 16, isPublic: false, isVirtual: false });
  analysis.warnings.push("<failure>");
  const html = renderItaniumRtti(analysis);
  assert.match(html, /Itanium C\+\+ RTTI/);
  assert.match(html, /&lt;script/);
  assert.match(html, /&lt;failure/);
  assert.match(html, /Virtual: vtable slot/);
  assert.match(html, /Non-public/);
  assert.match(html, /peNumeric/);
  assert.doesNotMatch(html, /<script>/);
  assert.doesNotMatch(html, /Function prefix|verified prefix/);
  assert.doesNotMatch(html, /Offset to top|Primary vtables|Address point RVA/);
  assert.equal(getItaniumRttiTableModel(analysis, "pe-itanium-vtables"), null);
});
void test("provides paginated rows, sort values and PE registry integration", async () => {
  const pe = createBasePe();
  pe.itaniumRtti = (await discoverItaniumRtti(createItaniumFixture().image))!;
  pe.itaniumRtti.types = Array.from({ length: 251 }, () => pe.itaniumRtti!.types[0]!);
  const model = getPePagedTableModel(pe, "pe-itanium-types")!;
  assert.equal(model.rowCount, 251);
  assert.ok(model.rowAt(0));
  assert.equal(model.rowAt(251), null);
  assert.equal(model.sortValueAt(0, 1), pe.itaniumRtti.types[0]!.name);
  assert.equal(model.sortValueAt(999, 0), "");
  assert.match(renderItaniumRtti(pe.itaniumRtti), /data-paged-sortable-table-id="pe-itanium-types"/);
});
