import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfLsda, createElfLsdaTableModel, getElfLsdaTableModel } from "../../../../renderers/elf/lsda.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { lsdaFixture } from "../../../fixtures/elf-lsda.js";

void test("renders separate call-site, action, type and specification tables", () => {
  const elf = relocationFixture().elf;
  const { result } = lsdaFixture([]);
  result.landingPadBase = { address: 8192n, indirect: false };
  result.callSites = [{ start: 1n, length: 2n, landingPad: 3n, action: 1n }];
  result.actions = [{ offset: 8, typeFilter: 1n, nextOffset: 0n }];
  result.types = [{ index: 1n, pointer: { address: 4096n, indirect: true } },
    { index: 2n, pointer: null }, { index: 3n, pointer: { address: 0n, indirect: false } }];
  result.specifications = [{ filter: -1n, typeIndices: [1n] }];
  result.issues = ["<issue>"];
  elf.lsdas = [result];
  const out: string[] = [];
  renderElfLsda(elf, out);
  assert.match(out.join(""), /&lt;issue>/);
  assert.match(out.join(""), /Indirect at 0x1000/);
  assert.match(out.join(""), /Unavailable/);
  assert.match(out.join(""), /0x2000/);
  const model = createElfLsdaTableModel(result, "sites");
  assert.equal(model.sortValueAt(0, 1), "2");
  assert.equal(model.sortValueAt(1, 0), "");
  assert.equal(model.rowAt(1), null);
  assert.equal(getElfPagedTableModel(elf, "elf-lsda-4096-sites")?.rowCount, 1);
  assert.equal(getElfLsdaTableModel(elf, "missing"), null);
});

void test("handles missing and empty LSDA descriptors", () => {
  const elf = relocationFixture().elf;
  const out: string[] = [];
  renderElfLsda(elf, out);
  assert.deepEqual(out, []);
  assert.equal(getElfLsdaTableModel(elf, "missing"), null);
  elf.lsdas = [lsdaFixture([]).result];
  renderElfLsda(elf, out);
  assert.doesNotMatch(out.join(""), /<table/);
});
