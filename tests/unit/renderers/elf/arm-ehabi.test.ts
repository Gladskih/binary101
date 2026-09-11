import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElfArmEhabi, createElfArmEhabiModel } from "../../../../renderers/elf/arm-ehabi.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import { getElfPagedTableModel } from "../../../../renderers/elf/paged-tables.js";

void test("renders EHABI programs, descriptor scopes and escaped notices", () => {
  const elf = relocationFixture().elf;
  const out: string[] = [];
  renderElfArmEhabi(elf, out);
  assert.deepEqual(out, []);
  elf.armEhabi = [{ source: "<section>", issues: ["<notice>"], entries: [
    { offset: 64, functionAddress: 4096n, data: 1, tableAddress: 8192n, personality: 1,
      instructions: [{ offset: 0, text: "<instruction>" }], issues: ["<entry>"], descriptors: [
        { kind: "catch", start: 2, length: 4, types: [0xffffffff], referenceCatch: true, landingPad: 4100n }
      ] }, { offset: 72, functionAddress: null, data: 1, instructions: [], issues: [] }
  ] }];
  renderElfArmEhabi(elf, out);
  assert.match(out.join(""), /&lt;instruction>/);
  assert.match(out.join(""), /&lt;notice>/);
  assert.match(out.join(""), /&lt;entry>/);
  assert.match(out.join(""), /0xffffffff/);
  const model = createElfArmEhabiModel(elf.armEhabi[0]!, 0);
  assert.equal(model.rowAt(2), null);
  assert.equal(model.sortValueAt(0, 0), "64");
  assert.equal(model.sortValueAt(2, 0), "");
  assert.equal(getElfPagedTableModel(elf, "elf-arm-ehabi-0")?.rowCount, 2);
  const scopes = getElfPagedTableModel(elf, "elf-arm-scopes-0")!;
  assert.equal(scopes.rowAt(1), null);
  assert.equal(scopes.sortValueAt(0, 1), "catch");
  assert.equal(scopes.sortValueAt(1, 0), "");
});
