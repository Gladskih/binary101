import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { createDwarfNameIndexFixture } from "../../../fixtures/dwarf-name-index-fixture.js";
import {
  createDwarfPublicNameTableModel, createDwarfNameIndexTableModel, getDwarfLookupTableModel, renderDwarfLookups
} from "../../../../renderers/dwarf/lookups.js";
import { getDwarfPagedTableModel } from "../../../../renderers/dwarf/paged-tables.js";

void test("lookup tables resolve names to kinds/source units and disclose unresolved references", async () => {
  const fixture = createDwarfNameIndexFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const table = dwarf.nameIndexes![0]!;
  const model = createDwarfNameIndexTableModel(dwarf, table);

  assert.equal(model.rowAt(0)?.cells[0]?.html, "calculate");
  assert.equal(model.rowAt(0)?.cells[1]?.html, "subprogram");
  assert.equal(model.rowAt(0)?.cells[2]?.html, "main.c");
  assert.equal(model.rowAt(999), null);
  assert.equal(model.sortValueAt(999, 0), "");
  assert.equal(getDwarfLookupTableModel(dwarf, model.id)?.rowCount, 1);
  assert.equal(getDwarfPagedTableModel(dwarf, model.id)?.rowCount, 1);
  assert.match(renderDwarfLookups(dwarf), /Debugger name index/);
  table.names[0]!.name = { kind: "string-offset", sectionName: ".debug_str", value: 99n };
  assert.match(renderDwarfLookups(dwarf), /unresolved indexed name/);
  dwarf.units = [];
  assert.match(renderDwarfLookups(dwarf), /unresolved unit/);
  assert.equal(getDwarfLookupTableModel(dwarf, "other"), null);
});

void test("public-name and coverage tables expose human facts and escape recorded source names", async () => {
  const fixture = createDwarfNameIndexFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const unit = dwarf.units[0]!;
  const die = unit.dies[2]!;
  const table = { sectionName: ".debug_pubnames", offset: 0, format: 32 as const,
    unitOffset: 0n, unitLength: 0n, entries: [
      { dieOffset: BigInt(die.offset), name: "<compute>", descriptor: null },
      { dieOffset: 999n, name: "missing", descriptor: null }
    ] };
  dwarf.publicNames = [table, { ...table, sectionName: ".debug_pubtypes", entries: [] }];
  dwarf.addressLookup = [{ offset: 0, format: 32, unitOffset: 0n, addressSize: 8,
    segmentSize: 0, ranges: [{ segment: null, start: 0x1000n, length: 7n }] }];
  const model = createDwarfPublicNameTableModel(dwarf, table);

  assert.equal(model.rowAt(0)?.cells[0]?.html, "&lt;compute>");
  assert.equal(model.rowAt(1)?.cells[1]?.html, "unresolved DIE");
  assert.match(renderDwarfLookups(dwarf), /Compilation-unit coverage/);
  assert.ok(!renderDwarfLookups(dwarf).includes("0x1000"));
  assert.equal(getDwarfLookupTableModel(dwarf, model.id)?.rowCount, 2);
  dwarf.units = [];
  assert.match(renderDwarfLookups(dwarf), /unresolved compilation unit/);
  assert.equal(renderDwarfLookups({ ...dwarf, publicNames: [], nameIndexes: [], addressLookup: [] }), "");
});
