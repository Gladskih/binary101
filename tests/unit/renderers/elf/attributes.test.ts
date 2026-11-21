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

void test("explains AArch64 comprehension, value encoding and feature coverage", () => {
  const { elf } = relocationFixture();
  elf.attributes = [{ sectionIndex: 4, issues: [], vendors: [{
    name: "aeabi_feature_and_bits", scopes: [], aarch64: { comprehension: 1, parameterType: 0,
      attributes: [{ tag: 0n, value: 1n }, { tag: 2n, value: 0n }, { tag: 32n, value: 19n }] }
  }] }];
  const out: string[] = [];
  renderElfAttributes(elf, out);
  const html = out.join("");
  assert.match(html, /optional subsection/);
  assert.match(html, /ULEB128/);
  assert.match(html, /All executable sections/);
  assert.match(html, /Not universal or unspecified/);
  assert.match(html, /Unknown tag/);
});
