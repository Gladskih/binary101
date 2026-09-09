import assert from "node:assert/strict";
import { test } from "node:test";
import { describeElfGnuProperty, renderElfGnuProperties } from
  "../../../../renderers/elf/gnu-properties.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";

void test("describes x86 ISA requirements and control flow compatibility", () => {
  assert.match(describeElfGnuProperty({ type: 0xc0008002, value: 5n }, 62), /x86-64-v3/);
  assert.match(describeElfGnuProperty({ type: 0xc0000002, value: 3n }, 62), /IBT.*SHSTK/);
  assert.match(describeElfGnuProperty({ type: 0xc0010002, value: 2n }, 3), /used/);
});

void test("describes AArch64 features only for that architecture", () => {
  assert.match(describeElfGnuProperty({ type: 0xc0000000, value: 7n }, 183), /BTI.*PAC.*GCS/);
  assert.doesNotMatch(describeElfGnuProperty({ type: 0xc0000000, value: 7n }, 62), /BTI/);
});

void test("retains unknown bits and raw data", () => {
  assert.match(describeElfGnuProperty({ type: 0xc0000002, value: 128n }, 62), /0x80/);
  assert.match(describeElfGnuProperty({ type: 1, value: 8192n }, 62), /8192/);
  assert.match(describeElfGnuProperty({ type: 2, value: 0n }, 62), /copy/);
  assert.match(describeElfGnuProperty({ type: 123, value: "abcdef" }, 62), /abcdef/);
});

void test("renders GNU properties as a table", () => {
  const fixture = relocationFixture();
  fixture.elf.notes = { entries: [{ source: "<note>", name: "GNU", type: 5,
    typeName: null, description: null, value: null, descSize: 16,
    properties: [{ type: 0xc0000002, value: 3n }] }], issues: [] };
  const out: string[] = [];
  renderElfGnuProperties(fixture.elf, out);
  assert.match(out.join(""), /<table/);
  assert.match(out.join(""), /&lt;note>/);
  assert.match(out.join(""), /SHSTK/);
});

void test("omits the table when no properties exist", () => {
  const out: string[] = [];
  renderElfGnuProperties(relocationFixture().elf, out);
  assert.deepEqual(out, []);
});
