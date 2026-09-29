import assert from "node:assert/strict";
import { test } from "node:test";
import { renderItaniumRtti, getItaniumRttiTableModel } from
  "../../../../renderers/pe/itanium-rtti.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { discoverItaniumRtti } from "../../../../analyzers/itanium-rtti/discovery.js";
import { createItaniumFixture } from "../../../fixtures/itanium-rtti.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";

void test("omits absent RTTI and unrelated tables", () => {
  assert.equal(renderItaniumRtti(null), "");
  assert.equal(getItaniumRttiTableModel(undefined, "pe-itanium-types"), null);
  assert.equal(getItaniumRttiTableModel({ types: [], vtables: [], warnings: [] }, "other"), null);
});
void test("renders type, base, vtable and warning data safely", async () => {
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
