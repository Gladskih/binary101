import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfMips, createElfMipsOptionModel } from "../../../../renderers/elf/mips.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("renders MIPS flags, register masks, paged options and warnings", () => {
  const elf = relocationFixture().elf;
  elf.mips = [{ source: "<source>", issues: ["<notice>"], registerInfo: {
    gprMask: 3, cprMasks: [1, 2, 3, 4], gpValue: 4096n
  }, options: [{ kind: 1, section: 2, info: 3, registerInfo: {
    gprMask: 4, cprMasks: [5, 6, 7, 8], gpValue: 8192n
  } }, { kind: 9, section: 0, info: 0 }], abiFlags: { version: 0, isaLevel: 32,
    isaRevision: 2, gprSize: 1, cpr1Size: 1, cpr2Size: 0, fpAbi: 1,
    isaExtension: 0, ases: 0, flags1: 0, flags2: 0 } }];
  const out: string[] = [];
  renderElfMips(elf, out);
  assert.match(out.join(""), /&lt;source>/);
  assert.match(out.join(""), /&lt;notice>/);
  assert.match(out.join(""), /0x1000/);
  const model = createElfMipsOptionModel(elf.mips[0]!, 0);
  assert.equal(model.sortValueAt(0, 5), "2000");
  assert.equal(model.sortValueAt(1, 5), "-");
  assert.equal(model.sortValueAt(1, 100), "");
  assert.equal(model.sortValueAt(100, 0), "");
  assert.equal(model.rowAt(100), null);
  assert.equal(getElfPagedTableModel(elf, "elf-mips-options-0")?.rowCount, 2);
});

void test("handles absent MIPS metadata and empty records", () => {
  const elf = relocationFixture().elf;
  const out: string[] = [];
  renderElfMips(elf, out);
  assert.deepEqual(out, []);
  elf.mips = [{ source: "source", issues: [] }];
  renderElfMips(elf, out);
  assert.equal(createElfMipsOptionModel(elf.mips[0]!, 0).rowCount, 0);
});
