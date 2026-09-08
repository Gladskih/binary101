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
