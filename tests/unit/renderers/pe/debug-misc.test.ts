import assert from "node:assert/strict";
import { test } from "node:test";
import { getMiscDebugTableModel, renderMiscDebug } from "../../../../renderers/pe/debug-misc.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("MISC retains every DBG file name, including records beyond the first page", () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(4, 0, 128), misc: { records: Array.from(
    { length: 101 }, (_, index) => ({ dataType: 1, length: 32, unicode: index !== 0,
      text: index === 0 ? "<file>.dbg" : `file${index}.dbg` })) } };
  pe.debug = { entry: null, entries: [entry] };
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-misc")!;
  const out: string[] = [];
  renderMiscDebug(entry, 0, out);

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.equal(model.rowAt(100)?.cells[0]?.html, "file100.dbg");
  assert.equal(model.rowAt(100)?.cells[1]?.html, "UTF-16LE");
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(100, 0), "file100.dbg");
  assert.equal(model.sortValueAt(100, 1), "true");
  assert.equal(model.sortValueAt(100, 2), "32");
  assert.equal(model.sortValueAt(100, 3), "");
  assert.equal(model.sortValueAt(101, 0), "");
  assert.match(out.join(""), /&lt;file>.dbg/);
  assert.match(out.join(""), /code page unspecified/);
  assert.doesNotMatch(out.join(""), /<file>|0x/);
});

void test("MISC explains unknown data types and encoding flags and omits empty tables", () => {
  const pe = createBasePe();
  const out: string[] = [];
  renderMiscDebug(createDebugViewEntry(4, 0, 0), 0, out);
  renderMiscDebug({ ...createDebugViewEntry(4, 0, 128), misc: { records: [] } }, 0, out);
  assert.deepEqual(out, []);
  assert.equal(getMiscDebugTableModel(pe, "other"), null);
  assert.equal(getMiscDebugTableModel(pe, "pe-debug-entry-0-misc"), null);
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(4, 0, 128), misc: { records: [
    { dataType: 2, length: 12, unicode: null, text: "" },
    { dataType: 1, length: 12, unicode: false, text: "" }
  ] } }] };
  const model = getMiscDebugTableModel(pe, "pe-debug-entry-0-misc")!;
  assert.equal(model.rowAt(0)?.cells[0]?.html, "Unsupported MISC type 2");
  assert.equal(model.rowAt(0)?.cells[1]?.html, "Unsupported flag");
  assert.equal(model.rowAt(1)?.cells[0]?.html, "(empty)");
});
