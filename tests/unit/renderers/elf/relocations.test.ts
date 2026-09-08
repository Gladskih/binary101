import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfRelocationTableModel, renderElfRelocations } from
  "../../../../renderers/elf/relocations.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture, relocationTable } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocation } from "../../../../analyzers/elf/relocation-types.js";

const entry = (fields: Partial<ElfRelocation> = {}): ElfRelocation => ({
  tableIndex: 0, recordOffset: 64, offset: 8n, type: 1, symbolIndex: 1,
  symbol: { name: "<target>", value: 4n, sectionIndex: 1 }, addend: -4n,
  target: { sectionIndex: 1, sectionOffset: 8n, fileOffset: 520n }, ...fields
});

void test("renders concise escaped cells, precise sort values and relocation warnings", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable({ sources: ["<rela>"] })],
    entries: [entry()], issues: ["<bad offset>"] };
  const out: string[] = [];

  renderElfRelocations(elf, out);
  const model = getElfPagedTableModel(elf, "elf-relocations")!;

  assert.match(out.join(""), /R_X86_64_64/);
  assert.match(out.join(""), /&lt;target>/);
  assert.match(out.join(""), /&lt;bad offset>/);
  assert.doesNotMatch(out.join(""), /<target>|<rela>/);
  assert.equal(model.sortValueAt(0, 2), "8");
  assert.equal(model.sortValueAt(0, 5), "-4");
  assert.equal(model.sortValueAt(0, 7), "520");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.equal(model.sortValueAt(99, 0), "");
  assert.equal(model.rowAt(99), null);
  assert.equal(model.columns[2]?.label, "Section offset");
});

void test("RELR, unknown symbols, unmapped and zero-fill targets remain distinct", () => {
  const { elf } = relocationFixture();
  elf.header.type = 3;
  elf.relocations = { tables: [relocationTable({ encoding: "RELR" })], entries: [
    entry({ type: null, symbolIndex: null, symbol: null, addend: null, target: null }),
    entry({ symbolIndex: 0, target: { sectionIndex: null, sectionOffset: null, fileOffset: null } }),
    entry({ symbol: null, target: { sectionIndex: 99, sectionOffset: 0n, fileOffset: null } })
  ], issues: [] };

  const model = createElfRelocationTableModel(elf);

  assert.equal(model.columns[2]?.label, "Virtual address");
  assert.equal(model.sortValueAt(0, 3), "Relative (RELR)");
  assert.equal(model.sortValueAt(0, 4), "—");
  assert.equal(model.sortValueAt(0, 5), "Implicit");
  assert.equal(model.sortValueAt(0, 6), "Unmapped");
  assert.equal(model.sortValueAt(1, 4), "0 (no symbol)");
  assert.equal(model.sortValueAt(1, 6), "PT_LOAD");
  assert.match(model.sortValueAt(2, 4), /unresolved/);
  assert.match(model.sortValueAt(2, 6), /#99/);
});

void test("PLT overlap and large tables support pagination without rendering all rows", () => {
  const { elf } = relocationFixture();
  elf.relocations = { tables: [relocationTable(), relocationTable({ sources: ["DT_JMPREL"] })],
    entries: Array.from({ length: 201 }, () => entry()), issues: [] };
  const out: string[] = [];

  renderElfRelocations(elf, out);

  assert.match(out.join(""), /data-paged-sortable-table-id="elf-relocations"/);
  assert.match(out.join(""), /test \(PLT\)/);
  assert.equal((out.join("").match(/>#1 &lt;target></g) ?? []).length, 100);
});

void test("absent relocations render nothing; warnings without entries remain visible", () => {
  const { elf } = relocationFixture();
  const out: string[] = [];

  renderElfRelocations(elf, out);
  assert.deepEqual(out, []);
  assert.equal(createElfRelocationTableModel(elf).rowCount, 0);
  assert.equal(createElfRelocationTableModel(elf).rowAt(0), null);
  elf.relocations = { tables: [], entries: [], issues: ["malformed"] };
  renderElfRelocations(elf, out);
  assert.match(out.join(""), /malformed/);
  assert.doesNotMatch(out.join(""), /<table/);
});
