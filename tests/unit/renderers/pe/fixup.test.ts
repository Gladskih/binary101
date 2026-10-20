import assert from "node:assert/strict";
import { test } from "node:test";
import { renderFixupStatistics, getFixupTableModel } from "../../../../renderers/pe/fixup.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { createBasePe, createPeSection } from "../../../fixtures/pe-renderer-headers-fixture.js";
import { createDebugViewEntry } from "../../../fixtures/pe-debug-view-subject.js";
import type { PeFixupRecord } from "../../../../analyzers/pe/debug/fixup.js";

const subject = (records: PeFixupRecord[]) => {
  const pe = createBasePe();
  pe.coff.Machine = 0x8664;
  pe.sections = [createPeSection(".text", { virtualAddress: 0x1000 }),
    createPeSection("<data>", { virtualAddress: 0x2000 })];
  const entry = { ...createDebugViewEntry(6, 0, 128, records.length * 12), fixup: { records } };
  pe.debug = { entry: null, entries: [entry] };
  return { pe, entry };
};

void test("FIXUP presents relocation and named-section statistics without address rows", () => {
  const { pe, entry } = subject([
    { type: 1, extra: 0, rva: 0x1000, targetRva: 0x2000 },
    { type: 4, extra: 0x8000, rva: 0x1004, targetRva: 0x2000 },
    { type: 4, extra: 0, rva: 0x1004, targetRva: 0x1000 }
  ]);
  const out: string[] = [];
  renderFixupStatistics(pe, entry, 0, out);

  assert.match(out.join(""), /Fixup records/);
  assert.match(out.join(""), /Distinct source locations/);
  assert.match(out.join(""), /Records with extra linker metadata/);
  assert.match(out.join(""), /AMD64_REL32/);
  assert.match(out.join(""), /AMD64_ADDR64/);
  assert.match(out.join(""), /&lt;data>/);
  assert.doesNotMatch(out.join(""), /<data>|RVA<\/th>|0x000010|0x000020/);
  const model = getPePagedTableModel(pe, "pe-debug-entry-0-fixup-sections")!;
  assert.deepEqual(model.rowAt(0)?.cells.map(cell => cell.html), [".text", "&lt;data>", "2"]);
  assert.equal(model.rowAt(2), null);
  assert.equal(model.sortValueAt(0, 2), "2");
  assert.equal(model.sortValueAt(0, 3), "");
  assert.equal(model.sortValueAt(2, 0), "");
});

void test("FIXUP kind statistics remain paginated and include every recorded type", () => {
  const { pe } = subject(Array.from({ length: 101 }, (_, index) => ({
    type: index, extra: 0, rva: 0x1000, targetRva: 0x2000
  })));
  const model = getFixupTableModel(pe, "pe-debug-entry-0-fixup-types")!;

  assert.equal(model.rowCount, 101);
  assert.equal(model.pageSize, 100);
  assert.equal(model.rowAt(100)?.cells[1]?.html, "1");
  assert.equal(model.rowAt(101), null);
  assert.equal(model.sortValueAt(0, 0), "IMAGE_REL_AMD64_ABSOLUTE");
  assert.equal(model.sortValueAt(0, 1), "1");
  assert.equal(model.sortValueAt(0, 2), "");
  assert.equal(model.sortValueAt(101, 0), "");
});

void test("FIXUP handles absent, empty and out-of-section data without empty tables", () => {
  const { pe, entry } = subject([]);
  const out: string[] = [];
  renderFixupStatistics(pe, entry, 0, out);
  const omitted: string[] = [];
  renderFixupStatistics(pe, createDebugViewEntry(6, 0, 128), 0, omitted);
  entry.fixup.records = [{ type: 4, extra: 0, rva: 0, targetRva: 0 }];

  assert.equal(omitted.join(""), "");
  assert.doesNotMatch(out.join(""), /<table/);
  assert.match(getFixupTableModel(pe, "pe-debug-entry-0-fixup-sections")?.rowAt(0)?.cells[0]?.html ?? "", /outside sections/);
  assert.equal(getFixupTableModel(pe, "other"), null);
  assert.equal(getFixupTableModel(createBasePe(), "pe-debug-entry-0-fixup-types"), null);
});
