import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import { createElfRelocationSymbolReader } from "../../../../analyzers/elf/relocation-symbols.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection, relocationTable } from "../../../fixtures/elf-relocations.js";

void test("reuses an already decoded symbol across section and dynamic table aliases", async context => {
  const fixture = dynamicRelocationFixture();
  const symbol = { name: "target", value: 4n, sectionIndex: 1 };
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const readBytes = context.mock.fn(reader.read);
  const symbols = fixture.elf.sections[2]!;
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader({ ...reader, read: readBytes },
    fixture.elf, fixture.tags, issues,
    new Map([[Number(symbols.offset + symbols.entsize), symbol]]));

  assert.equal(await read(relocationTable(), 1), symbol);
  assert.equal(await read(relocationTable({ symbolTableIndex: null }), 1), symbol);
  assert.equal(readBytes.mock.callCount(), 0);
  assert.deepEqual(issues, []);
});

void test("resolves static symbols and caches the same physical entry", async () => {
  const fixture = dynamicRelocationFixture();
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, []);

  const symbol = await read(relocationTable(), 1);
  const alias = await read(relocationTable({ symbolTableIndex: null }), 1);

  assert.deepEqual(symbol, { name: "target", value: 4n, sectionIndex: 1 });
  assert.equal(alias, symbol);
});

void test("resolves sectionless ELF32 symbols from dynamic tags", async () => {
  const fixture = dynamicRelocationFixture(32, "big");
  fixture.elf.sections = [];
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);

  assert.deepEqual(await read(relocationTable({ symbolTableIndex: null }), 1),
    { name: "target", value: 4n, sectionIndex: 1 });
  assert.deepEqual(issues, []);
});

for (const fields of [{ type: 1 }, { size: 24n }, { entsize: 23n }, { offset: 1024n }]) {
  void test(`invalid symbol table ${String(Object.keys(fields))}`, async () => {
    const fixture = dynamicRelocationFixture();
    Object.assign(fixture.elf.sections[2]!, fields);
    const issues: string[] = [];
    const read = createElfRelocationSymbolReader(
      createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);

    assert.equal(await read(relocationTable(), 1), null);
    assert.match(issues.join(" "), /outside/);
  });
}

void test("invalid names preserve the symbol value and raise warnings", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.view.setUint32(280, 8, true); // st_name equals string table size: out of bounds.
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);

  assert.equal((await read(relocationTable(), 1))?.name, "");
  fixture.elf.sections[2]!.link = 99;
  assert.equal((await read(relocationTable(), 0))?.name, "");
  assert.match(issues.join(" "), /string table offset/);
});

void test("SHN_XINDEX follows the linked SHT_SYMTAB_SHNDX with bounds checks", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.view.setUint16(286, 0xffff, true); // gABI SHN_XINDEX.
  fixture.elf.sections.push(relocationSection(4, {
    type: 18, offset: 448n, size: 8n, entsize: 4n, link: 2
  }));
  fixture.view.setUint32(452, 70000, true);
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];

  assert.equal((await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(
    relocationTable(), 1))?.sectionIndex, 70000);
  fixture.elf.sections[4]!.size = 4n;
  assert.equal((await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(
    relocationTable(), 1))?.sectionIndex, 0xffff);
  assert.match(issues.join(" "), /SHN_XINDEX/);
});

void test("dynamic symbol address and size tags are required and bounded", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(11, 16n);
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  const table = relocationTable({ symbolTableIndex: null });

  assert.equal(await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(table, 1), null);
  fixture.tags.delete(6);
  assert.equal(await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(table, 1), null);
  fixture.tags.set(6, 0x13f8n).set(11, 24n);
  assert.equal(await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(table, 1), null);
  fixture.tags.set(6, 0x1100n).delete(5);
  assert.equal((await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues)(table, 1))?.name, "");
});

void test("negative and unsafe symbol indices never read neighboring bytes", async () => {
  const fixture = dynamicRelocationFixture();
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, []);

  assert.equal(await read(relocationTable(), -1), null);
  assert.equal(await read(relocationTable(), Number.MAX_SAFE_INTEGER), null);
  assert.equal(await read(relocationTable(), Number.NaN), null);
});

void test("a dynamic symbol must not overlap DT_STRTAB", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(5, 0x111fn);
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, []);

  assert.equal(await read(relocationTable({ symbolTableIndex: null }), 1), null);
});

void test("a short symbol read returns a warning and caches the failed read", async () => {
  const fixture = dynamicRelocationFixture();
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader({ ...reader,
    read: async () => new DataView(new ArrayBuffer(0)) }, fixture.elf, fixture.tags, issues);

  assert.equal(await read(relocationTable(), 1), null);
  assert.equal(await read(relocationTable(), 1), null);
  assert.equal(issues.length, 1);
  assert.match(issues.join(" "), /truncated/);
});

void test("dynamic relocation symbols cannot read past DT_SYMTABSZ into neighboring data", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.set(39, 24n); // gABI DT_SYMTABSZ: only the null Elf64_Sym is in the table.
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);
  assert.equal(await read(relocationTable({ symbolTableIndex: null }), 1), null);
  assert.match(issues.join(" "), /outside/);
});

void test("sectionless relocation symbols use DT_SYMTAB_SHNDX", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.elf.sections = [];
  fixture.tags.set(34, 0x11c0n); // DT_SYMTAB_SHNDX points at two Elf32_Word entries.
  fixture.view.setUint16(286, 0xffff, true);
  fixture.view.setUint32(452, 70000, true);
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);
  assert.equal((await read(relocationTable({ symbolTableIndex: null }), 1))?.sectionIndex, 70000);
  assert.deepEqual(issues, []);
});

void test("a missing dynamic symbol boundary is visible and reported once", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.delete(39);
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(
    createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, issues);
  assert.ok(await read(relocationTable({ symbolTableIndex: null }), 1));
  assert.ok(await read(relocationTable({ symbolTableIndex: null }), 1));
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /no established size/);
});

void test("dynamic references honor a matching DYNSYM section or a previously parsed hash-derived count", async () => {
  const fixture = dynamicRelocationFixture();
  fixture.tags.delete(39);
  Object.assign(fixture.elf.sections[2]!, { type: 11, addr: 0x1100n });
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  const issues: string[] = [];
  const read = createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, issues);
  assert.ok(await read(relocationTable({ symbolTableIndex: null }), 1));
  assert.equal(await read(relocationTable({ symbolTableIndex: null }), 2), null);
  fixture.elf.sections = [];
  fixture.elf.dynSymbols = { total: 2, importSymbols: [], exportSymbols: [], issues: [] };
  const fromHashes = createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, []);
  assert.ok(await fromHashes(relocationTable({ symbolTableIndex: null }), 1));
  assert.equal(await fromHashes(relocationTable({ symbolTableIndex: null }), 2), null);
});

for (const size of [-1n, 25n]) {
  void test(`invalid DT_SYMTABSZ ${size} never enables a neighboring symbol read`, async () => {
    const fixture = dynamicRelocationFixture();
    fixture.tags.set(39, size);
    const read = createElfRelocationSymbolReader(
      createFileRangeReader(fixture.file(), 0, fixture.bytes.length), fixture.elf, fixture.tags, []);
    assert.equal(await read(relocationTable({ symbolTableIndex: null }), 1), null);
  });
}

void test("invalid DYNSYM stride and nonextended SHNDX values are rejected", async () => {
  const fixture = dynamicRelocationFixture();
  Object.assign(fixture.elf.sections[2]!, { type: 11, addr: 0x1100n, entsize: 1n });
  const reader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  assert.equal(await createElfRelocationSymbolReader(reader, fixture.elf, fixture.tags, [])(
    relocationTable({ symbolTableIndex: null }), 1), null);
  fixture.elf.sections = [];
  fixture.tags.set(34, 0x11c0n);
  fixture.view.setUint16(286, 0xffff, true);
  fixture.view.setUint32(452, 1, true); // Extended indices must be >= SHN_LORESERVE.
  const issues: string[] = [];
  const changedReader = createFileRangeReader(fixture.file(), 0, fixture.bytes.length);
  assert.equal((await createElfRelocationSymbolReader(changedReader, fixture.elf, fixture.tags, issues)(
    relocationTable({ symbolTableIndex: null }), 1))?.sectionIndex, 0xffff);
  assert.match(issues.join(" "), /SHN_XINDEX/);
});
