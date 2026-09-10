import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfCoreTableModel, createElfCoreMappingModel,
  renderElfCoreNotes } from "../../../../renderers/elf/core-notes.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import type { ElfCoreNote } from "../../../../analyzers/elf/core-note-types.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

const core: ElfCoreNote = {
  fields: [{ name: "Executable", value: "<binary>" }],
  registers: [{ name: "rip", value: 4096n }], auxv: [{ tag: 6n, value: 4096n }],
  mappings: [{ start: 4096n, end: 8192n, pageOffset: 1n, path: "<path>" }],
  issues: ["<notice>"]
};

void test("renders core metadata, registers and mappings with escaped values", () => {
  const elf = relocationFixture().elf;
  elf.notes = { issues: [], entries: [{ source: "PT_NOTE", name: "CORE", type: 1,
    typeName: "NT_PRSTATUS", description: null, value: null, descSize: 0, core }] };
  const out: string[] = [];
  renderElfCoreNotes(elf, out);
  assert.match(out.join(""), /&lt;binary>/);
  assert.match(out.join(""), /&lt;path>/);
  assert.match(out.join(""), /&lt;notice>/);
  assert.equal(getElfPagedTableModel(elf, "elf-core-0")?.rowCount, 3);
  assert.equal(getElfPagedTableModel(elf, "elf-core-mappings-0")?.rowCount, 1);
  assert.equal(getElfPagedTableModel(elf, "missing"), null);
});

void test("provides bounded page models and numeric cell alignment", () => {
  const model = createElfCoreTableModel(core, 0);
  assert.equal(model.sortValueAt(1, 1), "0x1000");
  assert.equal(model.sortValueAt(2, 0), "Auxiliary tag 6");
  assert.equal(model.sortValueAt(10, 0), "");
  assert.equal(model.rowAt(-1), null);
  const mappings = createElfCoreMappingModel(core, 0);
  assert.equal(mappings.sortValueAt(0, 2), "1");
  assert.equal(mappings.sortValueAt(9, 0), "");
  assert.equal(mappings.rowAt(9), null);
  assert.equal(mappings.rowAt(0)?.cells[0]?.className, "peNumeric");
});

void test("handles absent optional data and unknown note types", () => {
  const elf = relocationFixture().elf;
  const out: string[] = [];
  renderElfCoreNotes(elf, out);
  assert.deepEqual(out, []);
  const empty = { fields: [], issues: [] };
  assert.equal(createElfCoreTableModel(empty, 0).rowCount, 0);
  assert.equal(createElfCoreMappingModel(empty, 0).rowCount, 0);
  elf.notes = { issues: [], entries: [{ source: "PT_NOTE", name: "CORE", type: 123,
    typeName: null, description: null, value: null, descSize: 0, core: empty },
  { source: "PT_NOTE", name: "GNU", type: 3, typeName: null,
    description: null, value: null, descSize: 0 }] };
  renderElfCoreNotes(elf, out);
  assert.match(out.join(""), /Core note 0x7b/);
  assert.equal(getElfPagedTableModel(elf, "missing"), null);
});
