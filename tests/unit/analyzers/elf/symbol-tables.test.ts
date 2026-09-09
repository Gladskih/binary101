import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElfSymbolTables } from "../../../../analyzers/elf/symbol-tables.js";
import { relocationFixture, relocationSection } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocationSymbol } from "../../../../analyzers/elf/relocation-types.js";

for (const bits of [32, 64] as const) {
  for (const order of ["little", "big"] as const) {
    void test(`reads all static symbols in ELF${bits} ${order}`, async () => {
      const fixture = relocationFixture(bits, order);
      const result = await parseElfSymbolTables(fixture.file(), fixture.elf);
      assert.equal(result[0]?.sectionIndex, 2);
      assert.equal(result[0]?.entries.length, 2);
      assert.equal(result[0]?.entries[1]?.name, "target");
      assert.equal(result[0]?.entries[1]?.value, 4n);
      assert.equal(result[0]?.entries[1]?.sectionIndex, 1);
      assert.deepEqual(result[0]?.issues, []);
    });
  }
}

void test("reads extended section indices and shares symbols with relocations", async () => {
  const fixture = relocationFixture();
  fixture.view.setUint16(286, 0xffff, true); // Elf64_Sym.st_shndx = SHN_XINDEX.
  fixture.elf.sections.push(relocationSection(4, { type: 18, link: 2,
    offset: 600n, size: 8n, entsize: 4n }));
  fixture.view.setUint32(604, 65536, true);
  const cache = new Map<number, ElfRelocationSymbol>();
  const result = await parseElfSymbolTables(fixture.file(), fixture.elf, cache);
  assert.equal(result[0]?.entries[1]?.sectionIndex, 65536);
  assert.deepEqual(cache.get(280), { name: "target", value: 4n, sectionIndex: 65536 });
});

void test("warns about invalid entry sizes", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.entsize = 1n;
  const result = await parseElfSymbolTables(fixture.file(), fixture.elf);
  assert.deepEqual(result[0]?.entries, []);
  assert.match(result[0]!.issues.join(" "), /entry size/);
});

void test("warns about truncated symbol tables", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.size = 10000n;
  const result = await parseElfSymbolTables(fixture.file(), fixture.elf);
  assert.deepEqual(result[0]?.entries, []);
  assert.match(result[0]!.issues.join(" "), /outside/);
});

void test("warns about missing strings and extended indices", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.link = 99;
  fixture.view.setUint16(286, 0xffff, true);
  const result = await parseElfSymbolTables(fixture.file(), fixture.elf);
  assert.equal(result[0]?.entries[1]?.name, "");
  assert.match(result[0]!.issues.join(" "), /string/);
  assert.match(result[0]!.issues.join(" "), /SHN_XINDEX/);
});

void test("warns on out of bounds names and partial trailing records", async () => {
  const fixture = relocationFixture();
  fixture.view.setUint32(280, 99, true);
  fixture.elf.sections[2]!.size = 49n;
  const result = await parseElfSymbolTables(fixture.file(), fixture.elf);
  assert.equal(result[0]?.entries.length, 2);
  assert.match(result[0]!.issues.join(" "), /aligned/);
  assert.match(result[0]!.issues.join(" "), /string/);
});
