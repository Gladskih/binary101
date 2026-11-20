import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfSymbolTableModel, renderElfSymbolTables } from
  "../../../../renderers/elf/symbol-tables.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
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

void test("resolves section symbols and escapes section names", () => {
  const model = createElfSymbolTableModel({ sectionIndex: 2, issues: [], entries: [
    // STT_SECTION=3 uses its section's name when st_name is empty (gABI 5).
    { name: "", value: 0n, size: 0n, info: 3, other: 0, sectionIndex: 1 }
  ] }, [relocationSection(1, { name: "<text>" })]);
  assert.equal(model.rowAt(0)?.cells[1]?.html, "&lt;text>");
  assert.equal(model.sortValueAt(0, 7), "1 (<text>)");
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

void test("distinguishes an extended section index from a reserved st_shndx value", async () => {
  const fixture = relocationFixture();
  // SHN_XINDEX selects a 32-bit word. 0xfff1 there names a real section, not SHN_ABS.
  fixture.view.setUint16(286, 0xffff, true);
  fixture.view.setUint32(604, 0xfff1, true);
  fixture.elf.sections.push(relocationSection(4, { type: 18, link: 2,
    offset: 600n, size: 8n, entsize: 4n }), relocationSection(0xfff1, { name: ".extended" }));
  const [table] = await parseElfSymbolTables(fixture.file(), fixture.elf);
  const model = createElfSymbolTableModel(table!, fixture.elf.sections);

  assert.equal(model.rowAt(1)?.cells[7]?.html, "65521 (.extended)");
});

void test("omits absent static symbols", () => {
  const out: string[] = [];
  renderElfSymbolTables(relocationFixture().elf, out);
  assert.deepEqual(out, []);
});
