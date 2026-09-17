import assert from "node:assert/strict";
import { test } from "node:test";
import { createElfDynamicIndexReader } from "../../../../analyzers/elf/dynamic-symbol-indices.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import type { ElfSectionHeader } from "../../../../analyzers/elf/types.js";

const indexFixture = (fields: Partial<ElfSectionHeader> = {}) => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.elf.sections.push(relocationSection(4, { type: 18, link: 2,
    offset: 640n, size: 8n, entsize: 4n, ...fields }));
  fixture.view.setUint32(644, 0x10000, true);
  return fixture;
};

// SHN_XINDEX, SHN_LORESERVE and DT_SYMTAB_SHNDX: gABI 3/5/8.
// https://gabi.xinuos.com/elf/05-symtab.html
for (const value of [0xff00, 0xffff, 0x10000, 0xffffffff]) {
  void test(`resolves extended index ${value}`, async () => {
    const fixture = indexFixture();
    fixture.view.setUint32(644, value, true);
    const issues: string[] = [];
    const read = createElfDynamicIndexReader(fixture.file(), fixture.elf, 256, [], issues);
    assert.equal(await read(1, 0xffff), value);
    assert.equal(await read(1, 1), 1);
    assert.deepEqual(issues, []);
  });
}

for (const fields of [{ type: 1 }, { link: 1 }, { size: 7n }, { entsize: 8n },
  { offset: 1020n }]) {
  void test(`rejects invalid extended index table ${Object.keys(fields)}`, async () => {
    const fixture = indexFixture(fields);
    const issues: string[] = [];
    const read = createElfDynamicIndexReader(fixture.file(), fixture.elf, 256, [], issues);
    assert.equal(await read(1, 0xffff), null);
    assert.match(issues.join(" "), /SHN_XINDEX/);
  });
}

void test("rejects a nonextended value in the extension table", async () => {
  const fixture = indexFixture();
  fixture.view.setUint32(644, 0xfeff, true);
  const issues: string[] = [];
  assert.equal(await createElfDynamicIndexReader(fixture.file(), fixture.elf, 256, [],
    issues)(1, 0xffff), null);
  assert.match(issues.join(" "), /SHN_XINDEX/);
});

void test("reads DT_SYMTAB_SHNDX through a bounded load mapping", async () => {
  const fixture = indexFixture();
  fixture.elf.sections = [];
  fixture.elf.programHeaders = [{ index: 0, type: 1, typeName: null, offset: 640n,
    vaddr: 0n, paddr: 0n, filesz: 8n, memsz: 8n, flags: 4, flagNames: [], align: 4n }];
  const issues: string[] = [];
  const read = createElfDynamicIndexReader(fixture.file(), fixture.elf, 256,
    [{ tag: 5, value: 0x1000n }, { tag: 34, value: 0n }], issues);
  assert.equal(await read(1, 0xffff), 0x10000);
  assert.deepEqual(issues, []);
  assert.equal(await read(2, 0xffff), null);
  assert.match(issues.join(" "), /SHN_XINDEX/);
});
for (const [type, offset, tag] of [[2, 256, 34], [11, 257, 34], [11, 256, 35]]) {
  void test(`selects only the matching dynamic index source ${type}/${offset}/${tag}`, async () => {
    const fixture = indexFixture();
    fixture.elf.sections[2]!.type = type!;
    fixture.elf.sections[4]!.type = 1;
    const issues: string[] = [];
    assert.equal(await createElfDynamicIndexReader(fixture.file(), fixture.elf, offset!,
      [{ tag: tag!, value: 640n }], issues)(1, 0xffff), null);
    assert.match(issues.join(" "), /SHN_XINDEX/);
  });
}

for (const [type, offset] of [[2, 256], [11, 257]] as const) {
  void test(`does not use extension tables linked to unrelated symbols ${type}/${offset}`, async () => {
    const fixture = indexFixture();
    fixture.elf.sections[2]!.type = type;
    const issues: string[] = [];
    assert.equal(await createElfDynamicIndexReader(fixture.file(), fixture.elf, offset,
      [], issues)(1, 0xffff), null);
    assert.match(issues.join(" "), /SHN_XINDEX/);
  });
}
