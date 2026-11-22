import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfRelocationTableModel, getElfRelocationSummaryModel, renderElfRelocations } from
  "../../../../renderers/elf/relocations.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture, relocationTable } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocation } from "../../../../analyzers/elf/relocation-types.js";

const entry = (fields: Partial<ElfRelocation> = {}): ElfRelocation => ({
  tableIndex: 0, recordOffset: 64, offset: 8n, type: 1, symbolIndex: 1,
  symbol: { name: "<target>", value: 4n, sectionIndex: 1 }, addend: -4n,
  target: { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n }, ...fields
});

void test("renders escaped aggregate cells, numeric sort values and visible warnings", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable()], entries: [entry()], issues: ["<bad offset>"] };
  const out: string[] = [];
  renderElfRelocations(elf, out);
  const model = getElfPagedTableModel(elf, "elf-relocations")!;
  assert.match(out.join(""), /R_X86_64_64/);
  assert.match(out.join(""), /&lt;target>/);
  assert.match(out.join(""), /&lt;bad offset>/);
  assert.match(out.join(""), /incomplete or contains anomalies/);
  assert.doesNotMatch(out.join(""), /<target>/);
  assert.equal(model.sortValueAt(0, 2), "1");
  assert.equal(model.sortValueAt(0, 3), "1");
  assert.equal(model.rowAt(0)?.cells[3]?.html, "100.0%");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.equal(model.sortValueAt(99, 0), "");
  assert.equal(model.sortValueAt(99, 3), "");
  assert.equal(model.rowAt(99), null);
  assert.equal(model.columns[0]?.label, "Relocation type");
  assert.equal(model.columns[2]?.label, "Decoded relocations");
  assert.match(out.join(""), /Decoded relocations: 1 across/);
  assert.match(out.join(""), /A RELR word can expand to multiple relocation sites/);
  assert.equal(getElfPagedTableModel(elf, "elf-relocations-targets")?.rowCount, 1);
  assert.equal(getElfRelocationSummaryModel(elf, "unknown"), null);
});

void test("large record sets aggregate before rendering and symbol distributions paginate", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable()],
    entries: Array.from({ length: 201 }, (_, index) => entry({ symbolIndex: index + 1,
      symbol: { name: `target${index}`, value: 0n, sectionIndex: 0 } })), issues: [] };
  const out: string[] = [];
  renderElfRelocations(elf, out);
  assert.match(out.join(""), /data-paged-sortable-table-id="elf-relocations-symbols"/);
  assert.equal(createElfRelocationTableModel(elf).rowCount, 1);
  assert.equal(createElfRelocationTableModel(elf).rowAt(0)?.cells[2]?.html, "201");
  assert.equal(getElfRelocationSummaryModel(elf, "elf-relocations-symbols")?.rowCount, 201);
  const records = getElfPagedTableModel(elf, "elf-relocation-records")!;
  assert.equal(records.rowCount, 201);
  assert.equal(records.rowAt(200)?.cells[4]?.html, "201");
  assert.equal(records.rowAt(0)?.cells[1]?.html, "0x40");
  assert.equal(records.sortValueAt(0, 6), "-4");
  assert.equal(records.rowAt(0)?.cells[9]?.html, "0x208");
});

void test("absent relocations render nothing; warnings without entries remain visible", () => {
  const { elf } = relocationFixture();
  const out: string[] = [];
  renderElfRelocations(elf, out);
  assert.deepEqual(out, []);
  assert.equal(createElfRelocationTableModel(elf).rowCount, 0);
  assert.equal(createElfRelocationTableModel(elf).rowAt(0), null);
  assert.equal(getElfRelocationSummaryModel(elf, "elf-relocations"), null);
  elf.relocations = { tables: [], entries: [], issues: ["malformed"] };
  renderElfRelocations(elf, out);
  assert.match(out.join(""), /malformed/);
  assert.doesNotMatch(out.join(""), /<table/);
});

void test("describes loader operations and keeps original file operands with records", () => {
  const { elf } = relocationFixture(32);
  elf.header.type = 3; // ET_DYN.
  elf.relocations = { tables: [relocationTable({ encoding: "REL", sources: ["DT_REL"] })],
    entries: [entry({ type: 8, symbolIndex: 0, symbol: null, addend: null, storedAddend: 4096n }),
      entry({ type: 7, target: null, addend: null })],
    issues: ["Relocation target range (4-byte write) is outside PT_LOAD memory.", "Partial table."] };
  const out: string[] = [];
  renderElfRelocations(elf, out);
  const html = out.join("");
  const records = getElfPagedTableModel(elf, "elf-relocation-records")!;
  assert.match(html, /difference between the runtime and link-time load addresses/);
  assert.match(html, /Procedure Linkage Table \(PLT\) slot/);
  assert.match(html, /Target unavailable/);
  assert.match(html, /<details><summary[^>]*>Analysis is incomplete or contains anomalies \(2\)/);
  assert.equal(records.rowAt(0)?.cells[6]?.html, "4096 (file)");
  assert.equal(records.sortValueAt(0, 6), "4096");
  assert.equal(records.columns[6]?.label, "Addend");
});
