import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTd32, getTd32TableModel } from "../../../../renderers/pe/td32.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createTd32Info } from "../../../fixtures/pe-td32-view.js";

const subject = () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(0, 0, 128), td32: createTd32Info() };
  pe.debug = { entry: null, entries: [entry] };
  return { pe, entry };
};

void test("TD32 renders escaped readable names and exposes sortable numerical columns", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderTd32(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-td32-modules")!;

  assert.match(out.join(""), /Borland TD32 format/);
  assert.match(out.join(""), /&lt;unit>.pas/);
  assert.match(out.join(""), /&lt;compiler>/);
  assert.doesNotMatch(out.join(""), /<unit>|RVA<\/th>|0x00000010/);
  assert.equal(model.rowAt(0)?.cells[2]?.html, "&lt;unit>.pas");
  assert.equal(model.rowAt(0)?.cells[3]?.className, "peNumeric");
  assert.equal(model.sortValueAt(0, 2), "<unit>.pas");
  assert.equal(model.rowAt(1), null);
  assert.equal(model.sortValueAt(1, 2), "");
  assert.equal(model.sortValueAt(0, 99), "");
});

void test("TD32 pagination preserves every shared name beyond the first page", () => {
  const { pe, entry } = subject();
  entry.td32.directories[0]!.subsections[0]!.data = { kind: "names",
    names: Array.from({ length: 101 }, (_, index) => `type_name_${index}`) };
  const model = getTd32TableModel(pe, "pe-debug-entry-0-td32-names")!;

  assert.equal(model.pageSize, 100);
  assert.equal(model.rowCount, 101);
  assert.equal(model.rowAt(100)?.cells[2]?.html, "type_name_100");
});

void test("TD32 omits empty tables and does not claim unrelated or absent payloads", () => {
  const { pe, entry } = subject();
  const out: string[] = [];
  renderTd32(createDebugViewEntry(0, 0, 128), 0, out);

  assert.deepEqual(out, []);
  assert.equal(getTd32TableModel(pe, "other"), null);
  assert.equal(getTd32TableModel(pe, "pe-debug-entry-1-td32-names"), null);
  assert.equal(getTd32TableModel(pe, "pe-debug-entry-0-td32-absent"), null);
  assert.equal(getTd32TableModel(createBasePe(), "pe-debug-entry-0-td32-names"), null);
  entry.td32.directories = [];
  renderTd32(entry, 0, out);
  assert.doesNotMatch(out.join(""), /<table/);
});
