import assert from "node:assert/strict";
import { test } from "node:test";
import { renderLegacyCodeView, getLegacyCodeViewTableModel } from "../../../../renderers/pe/legacy-codeview.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createLegacyCodeViewInfo } from "../../../fixtures/pe-legacy-codeview-view.js";

const subject = () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(2, 0, 128), legacyCodeView: createLegacyCodeViewInfo() };
  pe.debug = { entry: null, entries: [entry] };
  return { pe, entry };
};

void test("legacy CodeView renders escaped readable tables and statistical summaries", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-legacy-module")!;

  assert.match(out.join(""), /Embedded CodeView format/);
  assert.match(out.join(""), /&lt;module>.obj/);
  assert.match(out.join(""), /&lt;public>/);
  assert.match(out.join(""), /Line\/address pairs/);
  assert.doesNotMatch(out.join(""), /<public>|RVA<\/th>|0x00000010/);
  assert.equal(model.rowAt(0)?.cells[2]?.html, "&lt;module>.obj");
  assert.equal(model.sortValueAt(0, 2), "<module>.obj");
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(1, 2), "");
  assert.equal(model.sortValueAt(0, 9), "");
});

void test("legacy CodeView names remain accessible beyond a page and across directory generations", () => {
  const { pe, entry } = subject();
  entry.legacyCodeView.directories[0]!.subsections.push({ type: 0x12a, module: 0xffff, offset: 0, size: 0,
    data: { kind: "symbols", records: Array.from({ length: 101 }, (_, index) => ({ type: 0x203, name: `name${index}` })) } });
  entry.legacyCodeView.directories.push({ flags: 0, subsections: [] });
  const out: string[] = [];
  renderLegacyCodeView(entry, 0, out);
  const model = getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-symbols")!;

  assert.equal(model.pageSize, 100);
  assert.equal(model.rowCount, 103);
  assert.equal(model.rowAt(102)?.cells[3]?.html, "name100");
  assert.match(out.join(""), /incremental-link records/);
});

void test("legacy CodeView omits absent and empty details and rejects unrelated table requests", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderLegacyCodeView(createDebugViewEntry(2, 0, 128), 0, out);

  assert.deepEqual(out, []);
  assert.equal(getLegacyCodeViewTableModel(pe, "other"), null);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-1-legacy-symbols"), null);
  assert.equal(getLegacyCodeViewTableModel(pe, "pe-debug-entry-0-legacy-other"), null);
  assert.equal(getLegacyCodeViewTableModel(createBasePe(), "pe-debug-entry-0-legacy-symbols"), null);
  entry.legacyCodeView.directories = [];
  renderLegacyCodeView(entry, 0, out);
  assert.doesNotMatch(out.join(""), /<table/);
});
