import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfMacroTableModel, renderDwarfMacros } from "../../../../renderers/dwarf/macros.js";
import { getDwarfPagedTableModel } from "../../../../renderers/dwarf/paged-tables.js";
import { createDwarfMacroFixture } from "../../../fixtures/dwarf-macro-fixture.js";
import { createDwarfPackageFixture } from "../../../fixtures/dwarf-split-fixture.js";

void test("macro tables show definitions and includes without raw import addresses", async () => {
  const fixture = createDwarfMacroFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const macro = dwarf.macros![0]!;
  const model = createDwarfMacroTableModel(dwarf, macro);

  assert.match(renderDwarfMacros(dwarf), /LIMIT 42/);
  assert.match(renderDwarfMacros(dwarf), /SHARED\(x\) \(\(x\) \+ 1\)/);
  assert.equal(model.rowAt(1)?.cells[0]?.html, "define");
  assert.equal(model.rowAt(1)?.cells[2]?.html, "unresolved file 1:7");
  assert.equal(model.rowAt(999), null);
  assert.equal(model.sortValueAt(1, 1), "LIMIT 42");
  assert.equal(model.sortValueAt(999, 1), "");
  assert.equal(getDwarfPagedTableModel(dwarf, model.id)?.rowCount, 5);
  assert.equal(renderDwarfMacros({ ...dwarf, macros: [] }), "");
});

void test("macro tables escape text and distinguish imports, vendor data, and compiler definitions", async () => {
  const fixture = createDwarfMacroFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const macro = dwarf.macros![0]!;
  macro.entries = [
    { offset: 0, opcode: 1, operands: [{ kind: "unsigned", value: 0n }, { kind: "string", value: "<script>" }] },
    { offset: 1, opcode: 7, operands: [{ kind: "unsigned", value: 0n }] },
    { offset: 2, opcode: 10, operands: [{ kind: "unsigned", value: 99n }] },
    { offset: 3, opcode: 255, operands: [{ kind: "flag", value: true },
      { kind: "block", value: Uint8Array.of(1) }] },
    { offset: 4, opcode: 8, operands: [{ kind: "unsigned", value: 2n },
      { kind: "string-offset", sectionName: "supplementary .debug_str", value: 7n }] }
  ];

  const html = renderDwarfMacros(dwarf);

  assert.match(html, /&lt;script>/);
  assert.match(html, /compiler \/ command line/);
  assert.match(html, /5 directives in shared sequence/);
  assert.match(html, /external debug file required/);
  assert.match(html, /1-byte vendor data/);
  assert.match(html, /unresolved macro text/);
});

void test("DWP macro definitions use the owning contribution's original source file", async () => {
  const fixture = createDwarfPackageFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const first = createDwarfMacroTableModel(dwarf, dwarf.macros![0]!);
  const second = createDwarfMacroTableModel(dwarf, dwarf.macros![1]!);
  assert.match(first.rowAt(1)!.cells[2]!.html, /src\/main.c/);
  assert.match(second.rowAt(1)!.cells[2]!.html, /src\/other.c/);
  assert.equal(second.rowAt(1)!.cells[1]!.html, "COUNT 42");
});
