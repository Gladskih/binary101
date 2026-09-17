import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
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

for (const [bits, order, shndxOffset] of [
  [32, "little", 286], [32, "big", 286], [64, "little", 286], [64, "big", 286]
] as const) {
  void test(`resolves ELF${bits} ${order} dynamic SHN_XINDEX`, async () => {
    const fixture = relocationFixture(bits, order);
    fixture.elf.sections[2]!.type = 11;
    fixture.bytes[284] = 0x12;
    fixture.view.setUint16(shndxOffset, 0xffff, fixture.elf.littleEndian);
    fixture.elf.sections.push({ ...fixture.elf.sections[3]!, index: 4, type: 18,
      link: 2, offset: 640n, size: 8n, entsize: 4n });
    // gABI 5.5: SHN_XINDEX -> corresponding Elf32_Word in SHT_SYMTAB_SHNDX.
    // https://gabi.xinuos.com/elf/05-symtab.html
    fixture.view.setUint32(644, 0x10000, fixture.elf.littleEndian);

    const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

    assert.equal(result?.exportSymbols[0]?.shndx, 0x10000);
    assert.deepEqual(result?.issues, []);
  });
}

void test("warns and omits dynamic exports with unresolved SHN_XINDEX", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11;
  fixture.bytes[284] = 0x12;
  fixture.view.setUint16(286, 0xffff, true);

  const result = await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf });

  assert.deepEqual(result?.exportSymbols, []);
  assert.match(result!.issues.join(" "), /SHN_XINDEX/);
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
