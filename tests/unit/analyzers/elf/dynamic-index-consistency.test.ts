import assert from "node:assert/strict";
import { test } from "node:test";
import { validateElfDynamicConsistency } from "../../../../analyzers/elf/dynamic-consistency.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";

const indexFixture = (bits: 32 | 64 = 64, locations = [0x1200n]) => {
  const fixture = dynamicRelocationFixture(bits);
  fixture.tags.delete(39); // DT_SYMTABSZ is optional when the table extent is known independently.
  fixture.installTags();
  const [load, dynamic] = fixture.elf.programHeaders;
  dynamic!.filesz += BigInt(locations.length * bits / 4);
  dynamic!.memsz = dynamic!.filesz;
  const symbols = fixture.elf.sections[2]!;
  symbols.type = 11;
  const indices = relocationSection(4, { type: 18, flags: 2n, link: symbols.index,
    offset: 0x200n, addr: 0x1200n, size: 8n, entsize: 4n });
  fixture.elf.sections.push(indices);
  const entries = [...fixture.tags].map(([tag, value]) => ({ tag, value }));
  entries.push(...locations.map(value => ({ tag: 34, value })));
  const image = { ...fixture.elf, file: fixture.file() };
  return { image, symbols, indices, load: load!, inspect: () =>
    validateElfDynamicConsistency(image, { entries, terminated: true }) };
};

for (const [bits, size, stride, locations, warning] of [
  [64, 8n, 4n, [0x1200n], null], [32, 8n, 4n, [0x1200n], null],
  [64, 4n, 4n, [0x1200n], /one 4-byte word/], [64, 8n, 8n, [0x1200n], /one 4-byte word/],
  [64, 8n, 4n, [0x1300n], /disagrees with the location or extent/],
  [64, 8n, 4n, [], null], [64, 8n, 4n, [0x1200n, 0x1300n], /Conflicting DT_SYMTAB_SHNDX/]
] as const) {
  void test(`cross-validates ELF${bits} symbol indexes with size=${size}, stride=${stride} and tags=${locations}`, () => {
    const fixture = indexFixture(bits, [...locations]);
    Object.assign(fixture.indices, { size, entsize: stride });

    assert.deepEqual(fixture.inspect().map(issue => warning?.test(issue)), warning ? [true] : []);
  });
}

for (const fields of [{ flags: 0x800n }, { link: 1 }, { type: 1 }]) {
  void test(`restricts the index cross-check to a linked, uncompressed SHT_SYMTAB_SHNDX (${Object.keys(fields)})`, () => {
    const fixture = indexFixture(64, [0x1300n]);
    Object.assign(fixture.indices, fields);

    assert.deepEqual(fixture.inspect(), []);
  });
}

void test("checks the declared address even when a differently mapped index table starts at the right file offset", () => {
  const fixture = indexFixture();
  fixture.indices.addr += 4n;

  assert.match(fixture.inspect().join(" "), /DT_SYMTAB_SHNDX disagrees/);
});

void test("uses physical identity when the index section does not declare an allocated address", () => {
  const fixture = indexFixture();
  Object.assign(fixture.indices, { flags: 0n, addr: 0n });

  assert.deepEqual(fixture.inspect(), []);
});

void test("avoids a second mapping diagnostic when the dynamic symbol section exceeds the file", () => {
  const fixture = indexFixture();
  fixture.symbols.size = BigInt(fixture.image.file.size + 1);

  assert.deepEqual(fixture.inspect(), []);
});
