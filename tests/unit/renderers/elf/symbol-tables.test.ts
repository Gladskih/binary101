import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfSymbolTableModel, renderElfSymbolTables } from
  "../../../../renderers/elf/symbol-tables.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { parseElfSymbolTables } from "../../../../analyzers/elf/symbol-tables.js";

void test("renders static symbols and supports paging and sorting", async () => {
  const fixture = relocationFixture();
  fixture.elf.symbolTables = await parseElfSymbolTables(fixture.file(), fixture.elf);
  const model = createElfSymbolTableModel(fixture.elf.symbolTables[0]!);
  assert.equal(model.rowCount, 2);
  assert.equal(model.rowAt(1)?.cells[1]?.html, "target");
  assert.equal(model.sortValueAt(1, 5), "0x4");
  assert.equal(model.rowAt(99), null);
  assert.equal(model.sortValueAt(99, 0), "");
  assert.equal(getElfPagedTableModel(fixture.elf, "elf-symbols-2")?.rowCount, 2);
  const out: string[] = [];
  renderElfSymbolTables(fixture.elf, out);
  assert.match(out.join(""), /target/);
  assert.match(out.join(""), /Symbols:/);
});

void test("renders unknown symbol encodings and escapes names and warnings", () => {
  const fixture = relocationFixture();
  fixture.elf.symbolTables = [{ sectionIndex: 2, entries: [{ name: "<symbol>", value: 0n,
    size: 0n, info: 255, other: 3, sectionIndex: 65521 }], issues: ["<warning>"] }];
  const model = createElfSymbolTableModel(fixture.elf.symbolTables[0]!);
  assert.equal(model.rowAt(0)?.cells[1]?.html, "&lt;symbol>");
  assert.equal(model.sortValueAt(0, 2), "15");
  assert.equal(model.sortValueAt(0, 3), "15");
  assert.equal(model.sortValueAt(0, 7), "ABS");
  const out: string[] = [];
  renderElfSymbolTables(fixture.elf, out);
  assert.match(out.join(""), /&lt;warning>/);
});

void test("omits absent static symbols", () => {
  const out: string[] = [];
  renderElfSymbolTables(relocationFixture().elf, out);
  assert.deepEqual(out, []);
});
