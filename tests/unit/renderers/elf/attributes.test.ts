import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfAttributeTableModel, renderElfAttributes } from "../../../../renderers/elf/attributes.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("renders attribute scopes, compatibility tuples and unknown tags", () => {
  const elf = relocationFixture().elf;
  elf.attributes = [{ sectionIndex: 4, issues: ["<issue>"], vendors: [{ name: "aeabi", scopes: [{
    tag: 2n, indices: [3n], attributes: [{ tag: 32n, value: { flag: 1n, vendor: "<vendor>" } },
      { tag: 999n, value: "<value>" }]
  }] }] }];
  const model = createElfAttributeTableModel(elf.attributes[0]!);
  assert.equal(model.rowCount, 2);
  assert.equal(model.sortValueAt(0, 5), "1: <vendor>");
  assert.equal(model.sortValueAt(1, 4), "Unknown tag");
  assert.equal(model.sortValueAt(10, 0), "");
  assert.equal(model.rowAt(10), null);
  assert.equal(getElfPagedTableModel(elf, "elf-attributes-4")?.rowCount, 2);
  const out: string[] = [];
  renderElfAttributes(elf, out);
  assert.match(out.join(""), /&lt;vendor>/);
  assert.match(out.join(""), /&lt;issue>/);
  assert.match(out.join(""), /&lt;value>/);
});

void test("renders nothing without attribute sections", () => {
  const out: string[] = [];
  renderElfAttributes(relocationFixture().elf, out);
  assert.deepEqual(out, []);
});
