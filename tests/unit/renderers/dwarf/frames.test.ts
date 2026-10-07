import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfFrameFixture } from "../../../fixtures/dwarf-frame-fixture.js";
import { createDwarfFrameTableModel, createDwarfFrameRuleTableModel,
  getDwarfFrameTableModel, renderDwarfFrames } from "../../../../renderers/dwarf/frames.js";
import { getDwarfPagedTableModel } from "../../../../renderers/dwarf/paged-tables.js";

void test("frame tables associate recovery regions with names and show byte positions", async () => {
  const fixture = createDwarfFrameFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const table = createDwarfFrameTableModel(dwarf);
  const rules = createDwarfFrameRuleTableModel(dwarf, dwarf.frames!.fdes[0]!);

  assert.equal(table.rowCount, 1);
  assert.equal(table.rowAt(0)?.cells[0]?.html, "calculate");
  assert.equal(table.rowAt(0)?.cells[1]?.html, "16");
  assert.match(rules.rowAt(0)!.cells[1]!.html, /register 4 \+ 4 bytes/);
  assert.match(rules.rowAt(0)!.cells[2]!.html, /register 8: memory at frame address/);
  assert.equal(rules.rowAt(1)?.cells[0]?.html, "+4 bytes");
  assert.equal(table.rowAt(99), null);
  assert.equal(rules.rowAt(99), null);
  assert.equal(table.sortValueAt(99, 0), "");
  assert.equal(rules.sortValueAt(99, 0), "");
  assert.equal(getDwarfFrameTableModel(dwarf, rules.id)?.rowCount, 2);
  assert.equal(getDwarfPagedTableModel(dwarf, table.id)?.rowCount, 1);
  assert.match(renderDwarfFrames(dwarf), /Stack and caller recovery/);
  assert.doesNotMatch(renderDwarfFrames(dwarf), /0x1000|CIE offset|FDE offset/);
});

void test("frame models handle absent encodings and empty analyses", async () => {
  const fixture = createDwarfFrameFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  dwarf.frames!.cies[0]!.encoding = null;
  dwarf.units = [];

  assert.match(createDwarfFrameTableModel(dwarf).rowAt(0)!.cells[0]!.html, /Unresolved function/);
  assert.match(createDwarfFrameTableModel(dwarf).rowAt(0)!.cells[2]!.html, /Unresolved return register/);
  assert.equal(createDwarfFrameRuleTableModel(dwarf, dwarf.frames!.fdes[0]!).rowCount, 0);
  assert.equal(getDwarfFrameTableModel(dwarf, "other"), null);
  delete dwarf.frames;
  assert.equal(renderDwarfFrames(dwarf), "");
  assert.equal(createDwarfFrameTableModel(dwarf).rowCount, 0);
});
