import assert from "node:assert/strict";
import { test } from "node:test";
import { getPogoTableModel, renderPogoRegions } from "../../../../renderers/pe/pogo.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";

void test("POGO retains every name and size with pagination and escaping", () => {
  const pe = createBasePe();
  const entry = { ...createDebugViewEntry(13, 0, 128), pogo: {
    signature: 0, signatureName: "ZERO", entries: Array.from({ length: 101 }, (_, index) => ({
      startRva: index * 16, size: index, name: index === 0 ? "<name>" : `.text$${index}`
    }))
  } };
  pe.debug = { entry: null, entries: [entry] };
  const out: string[] = [];
  renderPogoRegions(entry, 0, out);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-pogo")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.deepEqual(model.columns.map(column => column.label), ["Region name", "Size"]);
  assert.equal(model.rowAt(100)?.cells[0]?.html, ".text$100");
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(100, 0), ".text$100");
  assert.equal(model.sortValueAt(100, 1), "100");
  assert.equal(model.sortValueAt(100, 2), "");
  assert.equal(model.sortValueAt(101, 0), "");
  assert.match(out.join(""), /&lt;name>/);
  assert.doesNotMatch(out.join(""), /<name>|Start RVA|0x/);
});

void test("POGO table lookup handles empty, missing and unrelated payloads", () => {
  const pe = createBasePe();
  const out: string[] = [];
  const empty = { ...createDebugViewEntry(13, 0, 128), pogo: {
    signature: 0, signatureName: "ZERO", entries: []
  } };
  renderPogoRegions(createDebugViewEntry(13, 0, 0), 0, out);
  renderPogoRegions(empty, 0, out);

  assert.deepEqual(out, []);
  assert.equal(getPogoTableModel(pe, "other"), null);
  assert.equal(getPogoTableModel(pe, "pe-debug-entry-0-pogo"), null);
  pe.debug = { entry: null, entries: [empty, createDebugViewEntry(13, 0, 0)] };
  assert.equal(getPogoTableModel(pe, "pe-debug-entry-0-pogo")?.rowCount, 0);
  assert.equal(getPogoTableModel(pe, "pe-debug-entry-1-pogo"), null);
});

void test("POGO preserves unnamed regions rather than silently discarding them", () => {
  const pe = createBasePe();
  pe.debug = { entry: null, entries: [{ ...createDebugViewEntry(13, 0, 128), pogo: {
    signature: 0, signatureName: "ZERO", entries: [{ startRva: 0, size: 0, name: "" }]
  } }] };

  assert.equal(getPogoTableModel(pe, "pe-debug-entry-0-pogo")?.rowAt(0)?.cells[0]?.html, "(unnamed)");
});
