import assert from "node:assert/strict";
import { test } from "node:test";
import { renderDebug } from "../../../../renderers/pe/debug-view.js";
import { getOmapTableModel, renderOmap } from "../../../../renderers/pe/omap.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { renderPagedSortableTableRows } from "../../../../renderers/paged-sortable-table.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { parseDebugDirectory } from "../../../../analyzers/pe/debug/directory.js";
import { createDebugDirectorySubject } from "../../../fixtures/pe-debug-payload-subject.js";
import { createOmapPayload } from "../../../fixtures/pe-omap.js";

const createOmapPe = (type = 7, count = 1) => {
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{
    ...createDebugViewEntry(type, 0, 128, count * 8),
    omap: { records: Array.from({ length: count }, (_, index) => ({
      rva: index + 1, rvaTo: index + 2
    })) }
  }] };
  return pe;
};

void test("renderDebug includes decoded OMAP details for both directions", async () => {
  const subject = createDebugDirectorySubject([7, 8].map(type => ({
    type, payload: createOmapPayload([[1, 2], [3, 0], [2, 4]])
  })));
  const pe = createBasePe();
  const debug = await parseDebugDirectory(subject.file, subject.dataDirs, value => value, 0);
  assert.ok(debug.warning);
  pe.debug = { ...debug, warning: debug.warning };
  const out: string[] = [];

  renderDebug(pe, out);

  assert.match(out.join(""), /Entry #1: OMAP_TO_SRC/);
  assert.match(out.join(""), /Entry #2: OMAP_FROM_SRC/);
  assert.match(out.join(""), /Address map with 3 records/);
  assert.match(out.join(""), /Image RVA \(rva\)/);
  assert.match(out.join(""), /Source RVA \(rva\)/);
  assert.match(out.join(""), /Source RVA \(rvaTo\)/);
  assert.match(out.join(""), /0x00000001/);
  assert.match(out.join(""), /0x00000002/);
  assert.match(out.join(""), /zero rvaTo indicates an unmapped region/);
  assert.match(out.join(""), /Source means the original image layout before optimization/);
  assert.match(out.join(""), /In an ordered table, a record applies until the next input RVA/);
  assert.match(out.join(""), /translate by adding the offset from rva to rvaTo/);
  assert.match(out.join(""), /OMAP input RVAs are not strictly increasing/);
  assert.equal(pe.debug.entries?.[0]?.rawPayload, undefined);
  assert.equal(pe.debug.entries?.[1]?.omap?.records.length, 3);
});

void test("OMAP table pages through every record and sorts numeric fields", () => {
  const pe = createOmapPe(8, 101);
  const out: string[] = [];
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-omap")!;

  renderDebug(pe, out);

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.columns.map(column => column.label),
    ["#", "Source RVA (rva)", "Image RVA (rvaTo)"]);
  assert.deepEqual(model.columns.map(column => column.className),
    ["peNumeric", "peNumeric", "peNumeric"]);
  assert.match(out.join(""), /data-paged-sortable-table-id="pe-debug-entry-0-omap"/);
  assert.doesNotMatch(out.join(""), /0x00000066/);
  assert.match(renderPagedSortableTableRows(model, {
    pageIndex: 1, sortColumnIndex: null, sortDirection: null
  }), /0x00000066/);
  assert.equal(model.sortValueAt(100, 0), "101");
  assert.equal(model.sortValueAt(100, 1), "101");
  assert.equal(model.sortValueAt(100, 2), "102");
  assert.equal(model.sortValueAt(100, 3), "");
  assert.equal(model.sortValueAt(101, 0), "");
  assert.equal(model.rowAt(101), null);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.html),
    ["101", "0x00000065", "0x00000066"]);
  assert.deepEqual(model.rowAt(100)?.cells.map(cell => cell.className),
    ["peNumeric", "peNumeric", "peNumeric"]);
});

void test("OMAP renderer handles absent and empty tables", () => {
  const out: string[] = [];

  renderOmap(createDebugViewEntry(7, 0, 0, 0), 0, out);

  assert.deepEqual(out, []);
  renderOmap({ ...createDebugViewEntry(7, 0, 0, 0), omap: { records: [] } }, 0, out);
  assert.match(out.join(""), /No complete OMAP records/);
  assert.doesNotMatch(out.join(""), /<table/);
});

void test("OMAP table lookup rejects unknown or missing entries", () => {
  const pe = createOmapPe();

  assert.equal(getOmapTableModel(pe, "pe-debug-entry-0-omap-extra"), null);
  assert.equal(getOmapTableModel(pe, "extra-pe-debug-entry-0-omap"), null);
  assert.equal(getOmapTableModel(pe, "pe-debug-entry-1-omap"), null);
  assert.equal(getOmapTableModel(createBasePe(), "pe-debug-entry-0-omap"), null);
  pe.debug = { entry: null, entries: [createDebugViewEntry(7, 0, 0, 0)] };
  assert.equal(getOmapTableModel(pe, "pe-debug-entry-0-omap"), null);
});

void test("OMAP paging identifies double-digit debug entry indexes", () => {
  const pe = createOmapPe();
  pe.debug!.entries = Array.from({ length: 11 }, () => pe.debug!.entries![0]!);

  const model = getOmapTableModel(pe, "pe-debug-entry-10-omap");

  assert.equal(model?.rowCount, 1);
  assert.deepEqual(model?.columns.map(column => column.label),
    ["#", "Image RVA (rva)", "Source RVA (rvaTo)"]);
});
