import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeDwarf } from "../../../../analyzers/dwarf/index.js";
import { getDwarfPagedTableModel } from "../../../../renderers/dwarf/paged-tables.js";
import { renderDwarfEntities } from "../../../../renderers/dwarf/entities.js";
import { renderDwarfSourceLines } from "../../../../renderers/dwarf/source-lines.js";
import { renderPagedSortableTableRows } from "../../../../renderers/paged-sortable-table.js";
import { createDwarfSemanticFixture } from "../../../fixtures/dwarf-semantic-fixture.js";
import { parsePe } from "../../../../analyzers/pe/index.js";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { getPePagedTableModel } from "../../../../renderers/pe/paged-tables.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { createPeSemanticDwarfFile } from "../../../fixtures/pe-dwarf-file.js";
import { createElfSemanticDwarfFile } from "../../../fixtures/elf-dwarf-file.js";

void test("entity pages retain every record and render later pages without constructing the full table", async () => {
  const fixture = createDwarfSemanticFixture(201);
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const model = getDwarfPagedTableModel(dwarf, "dwarf-entities")!;

  assert.equal(model.rowCount, 203);
  assert.equal(model.rowAt(202)?.cells[1]?.html, "calculate::input200");
  assert.equal(model.rowAt(-1), null);
  assert.equal(model.sortValueAt(202, 1), "calculate::input200");
  assert.equal(model.sortValueAt(999, 1), "");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.ok(!renderDwarfEntities(dwarf).includes("calculate::input200"));
  assert.match(renderPagedSortableTableRows(model, {
    pageIndex: 2, sortColumnIndex: null, sortDirection: null
  }), /calculate::input200/);
});

void test("source mapping pages retain all rows and omit sequence terminators", async () => {
  const fixture = createDwarfSemanticFixture();
  const dwarf = await analyzeDwarf(fixture.file, fixture.sections, true);
  const program = dwarf.linePrograms[0]!;
  program.rows = Array.from({ length: 201 }, (_, index) => ({
    ...program.rows[0]!, line: BigInt(index + 1)
  }));
  const model = getDwarfPagedTableModel(dwarf, "dwarf-lines-0")!;

  assert.equal(model.rowCount, 201);
  assert.equal(model.rowAt(200)?.cells[1]?.html, "201");
  assert.equal(model.rowAt(999), null);
  assert.equal(model.sortValueAt(200, 1), "201");
  assert.equal(model.sortValueAt(999, 1), "");
  assert.equal(model.sortValueAt(0, 99), "");
  assert.ok(!renderDwarfSourceLines(dwarf).includes(">201</td>"));
  assert.equal(getDwarfPagedTableModel(dwarf, "dwarf-lines-99"), null);
  assert.equal(getDwarfPagedTableModel(dwarf, "other"), null);
  assert.equal(getDwarfPagedTableModel(undefined, "dwarf-entities"), null);
});

void test("PE and ELF paging resolvers expose the complete lazily rendered DWARF tables", async () => {
  const pe = await parsePe(createPeSemanticDwarfFile(201));
  const elf = await parseElf(createElfSemanticDwarfFile(201));

  assert.equal(getPePagedTableModel(pe!, "dwarf-entities")?.rowCount, 203);
  assert.equal(getElfPagedTableModel(elf!, "dwarf-entities")?.rowCount, 203);
  assert.equal(getPePagedTableModel(pe!, "dwarf-lines-0")?.rowCount, 2);
  assert.equal(getElfPagedTableModel(elf!, "dwarf-lines-0")?.rowCount, 2);
});
