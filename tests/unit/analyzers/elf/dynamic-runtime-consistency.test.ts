import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";

const runtimeFixture = async () => {
  const { file, expected } = createElfMetadataFile();
  const elf = expectDefined(await parseElf(file));
  const segment = expectDefined(elf.programHeaders.find(({ type }) => type === 2));
  const section = expectDefined(elf.sections.find(({ type }) => type === 6));
  const bytes = await file.arrayBuffer();
  const view = new DataView(bytes);
  // ELF64 header field layouts, gABI 2.1, 3.2 and 7.1.
  const programHeader = (index: number) => Number(elf.header.phoff) + index * elf.header.phentsize;
  const sectionHeader = Number(elf.header.shoff) + section.index * elf.header.shentsize;
  const entry = (index: number) => Number(segment.offset) + index * 16; // sizeof(Elf64_Dyn), gABI 8.3.
  const stripSections = () => {
    view.setBigUint64(40, 0n, true); // e_shoff.
    view.setUint16(60, 0, true); // e_shnum.
    view.setUint16(62, 0, true); // e_shstrndx.
  };
  return { elf, segment, expected, view, programHeader, sectionHeader, entry, stripSections,
    parse: async () => expectDefined(await parseElf(new File([bytes], file.name))) };
};

for (const type of [3, 11]) { // SHT_STRTAB and SHT_DYNSYM, gABI 3.3.
  void test(`decodes a sectionless dynamic table of type ${type} across PT_LOAD boundaries`, async () => {
    const fixture = await runtimeFixture();
    const table = expectDefined(fixture.elf.sections.find(section => section.type === type &&
      (section.flags & 2n) !== 0n));
    const load = expectDefined(fixture.elf.programHeaders.find(segment => segment.type === 1));
    const spare = expectDefined(fixture.elf.programHeaders.find(segment => segment.type === 4));
    const split = table.offset + table.size / 2n;
    const second = fixture.programHeader(spare.index);
    const first = fixture.programHeader(load.index);
    const remainder = load.filesz - split;
    // Replace PT_NOTE with the second load and keep one file-to-virtual translation.
    fixture.view.setUint32(second, 1, true);
    fixture.view.setBigUint64(second + 8, split, true);
    fixture.view.setBigUint64(second + 16, load.vaddr + split, true);
    fixture.view.setBigUint64(second + 32, remainder, true);
    fixture.view.setBigUint64(second + 40, remainder, true);
    fixture.view.setBigUint64(first + 32, split, true);
    fixture.view.setBigUint64(first + 40, split, true);
    fixture.stripSections();

    const parsed = await fixture.parse();

    assert.equal(parsed.dynamic?.consistencyIssues, undefined);
    assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
    assert.equal(parsed.dynSymbols?.importSymbols[0]?.name, fixture.expected.importSymbol);
    assert.equal(parsed.dynSymbols?.exportSymbols[0]?.name, fixture.expected.exportSymbol);
  });
}

for (const mode of ["with sections", "without sections"]) {
  for (const [stride, warning] of [
    [24n, null], [null, /missing required DT_SYMENT/], [8n, /DT_SYMENT.*8.*24/]
  ] as const) {
    void test(`validates DT_SYMENT ${stride} ${mode}`, async () => {
      const fixture = await runtimeFixture();
      if (mode === "without sections") fixture.stripSections();
      const offset = fixture.entry(13); // DT_SYMENT in createElfMetadataFile.
      if (stride === null) fixture.view.setBigUint64(offset, 21n, true); // Replace it with DT_DEBUG.
      else fixture.view.setBigUint64(offset + 8, stride, true);

      const parsed = await fixture.parse();

      const issues = parsed.dynSymbols?.issues ?? [];
      assert.deepEqual(issues.map(issue => warning?.test(issue)), warning ? [true] : []);
      assert.equal(parsed.dynSymbols?.importSymbols[0]?.name,
        stride === 24n || mode === "with sections" ? fixture.expected.importSymbol : undefined);
      assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
    });
  }
}

void test("checks observed DT_SYMENT values even before DT_NULL and allows identical repeats", async () => {
  const fixture = await runtimeFixture();
  fixture.view.setBigUint64(fixture.entry(15), 11n, true); // Replace DT_NULL with a second DT_SYMENT.
  fixture.view.setBigUint64(fixture.entry(15) + 8, 24n, true);
  assert.deepEqual((await fixture.parse()).dynSymbols?.issues, []);
  fixture.view.setBigUint64(fixture.entry(15) + 8, 8n, true);

  const parsed = await fixture.parse();

  assert.equal(parsed.dynamic?.terminated, false);
  assert.deepEqual(parsed.dynSymbols?.issues, ["Conflicting DT_SYMENT values."]);
});

void test("an incomplete dynamic table cannot establish absence of required tags", async () => {
  const fixture = await runtimeFixture();
  // Stop before DT_SYMTAB, DT_SYMENT and DT_NULL, leaving the complete SHT_DYNSYM available.
  fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 32, 12n * 16n, true);

  const parsed = await fixture.parse();

  assert.equal(parsed.dynamic?.terminated, false);
  assert.doesNotMatch(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /missing required/);
  assert.deepEqual(parsed.dynSymbols?.issues, []);
});

void test("a caller passing entries without a terminator status cannot establish missing DT_SYMENT", async () => {
  const { file } = createElfMetadataFile();
  const elf = expectDefined(await parseElf(file));

  const symbols = await parseElfDynamicSymbols({ file, ...elf }, []);

  assert.deepEqual(symbols?.issues, []);
});

for (const mode of ["with sections", "without sections"]) {
  void test(`compares PT_DYNAMIC's file and memory locations ${mode}`, async () => {
    const fixture = await runtimeFixture();
    if (mode === "without sections") fixture.stripSections();
    // Move p_vaddr beyond all load segments. Move sh_addr too, keeping the two headers consistent.
    const address = fixture.segment.vaddr + BigInt(fixture.view.byteLength);
    fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 16, address, true);
    fixture.view.setBigUint64(fixture.sectionHeader + 16, address, true);

    const parsed = await fixture.parse();

    assert.deepEqual(parsed.dynamic?.consistencyIssues,
      [`PT_DYNAMIC #${fixture.segment.index}: the dynamic table lacks file-backed PT_LOAD coverage at p_vaddr.`]);
    assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
  });
}

void test("matches PT_DYNAMIC bytes at p_vaddr even when mapped from a different file offset", async () => {
  const fixture = await runtimeFixture();
  const address = fixture.segment.vaddr + 16n;
  fixture.stripSections();
  fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 16, address, true);

  const parsed = await fixture.parse();

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /PT_DYNAMIC.*file-backed PT_LOAD/);
});

void test("checks that PT_DYNAMIC's memory size includes DT_NULL without section headers", async () => {
  const fixture = await runtimeFixture();
  fixture.stripSections();
  fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 40, fixture.segment.memsz - 16n, true);

  const parsed = await fixture.parse();

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /PT_DYNAMIC.*p_memsz.*dynamic table/);
  assert.equal(parsed.dynamic?.terminated, true);
});

void test("reports a short p_memsz once when both the section and the observed table exceed it", async () => {
  const fixture = await runtimeFixture();
  fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 40, fixture.segment.memsz - 16n, true);

  const parsed = await fixture.parse();

  assert.deepEqual(parsed.dynamic?.consistencyIssues,
    [`PT_DYNAMIC #${fixture.segment.index}: p_memsz does not contain all of the dynamic table.`]);
});

void test("DT_SYMTAB and its matching section still need a file-backed memory mapping", async () => {
  const fixture = await runtimeFixture();
  const symbols = expectDefined(fixture.elf.sections.find(({ type }) => type === 11));
  const address = symbols.addr + BigInt(fixture.view.byteLength);
  const { shoff, shentsize } = fixture.elf.header;
  fixture.view.setBigUint64(fixture.entry(12) + 8, address, true);
  fixture.view.setBigUint64(Number(shoff) + symbols.index * shentsize + 16, address, true);

  const parsed = await fixture.parse();

  assert.deepEqual(parsed.dynamic?.consistencyIssues, ["DT_SYMTAB is outside a file-backed PT_LOAD range."]);
});

void test("file-backed coverage must include DT_NULL, even if its address belongs to zero-fill memory", async () => {
  const fixture = await runtimeFixture();
  const load = expectDefined(fixture.elf.programHeaders.find(({ type }) => type === 1));
  fixture.view.setBigUint64(fixture.programHeader(load.index) + 32,
    fixture.segment.offset + fixture.segment.filesz - 16n, true);

  const parsed = await fixture.parse();

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /PT_DYNAMIC.*file-backed PT_LOAD/);
  assert.equal(parsed.dynamic?.terminated, true);
});

void test("padding after DT_NULL does not require file-backed memory", async () => {
  const fixture = await runtimeFixture();
  const load = expectDefined(fixture.elf.programHeaders.find(({ type }) => type === 1));
  fixture.view.setBigUint64(fixture.programHeader(load.index) + 32,
    fixture.segment.offset + fixture.segment.filesz, true);
  fixture.view.setBigUint64(fixture.programHeader(fixture.segment.index) + 32, fixture.segment.filesz + 16n, true);

  const parsed = await fixture.parse();

  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.equal(parsed.dynamic?.terminated, true);
});

for (const [index, tag] of [[0, "DT_STRTAB"], [1, "DT_STRSZ"], [12, "DT_SYMTAB"]] as const) {
  void test(`checks presence of ${tag} even with a usable section table`, async () => {
    const fixture = await runtimeFixture();
    fixture.view.setBigUint64(fixture.entry(index), 21n, true); // Replace it with DT_DEBUG.

    const parsed = await fixture.parse();

    assert.deepEqual(parsed.dynamic?.consistencyIssues, [`ELF dynamic table is missing required ${tag}.`]);
    assert.deepEqual(parsed.dynamic?.issues, []);
    assert.equal(parsed.dynSymbols?.importSymbols[0]?.name, fixture.expected.importSymbol);
  });
}

void test("compares DT_SYMTABSZ with the section describing the same dynamic symbol table", async () => {
  const fixture = await runtimeFixture();
  const size = fixture.view.getBigUint64(fixture.entry(14) + 8, true);
  fixture.view.setBigUint64(fixture.entry(14) + 8, size - 24n, true);

  const parsed = await fixture.parse();

  assert.deepEqual(parsed.dynamic?.consistencyIssues, [
    `DT_SYMTABSZ (${size - 24n} bytes) disagrees with SHT_DYNSYM #3 sh_size (${size} bytes).`
  ]);
  assert.equal(parsed.dynSymbols?.importSymbols[0]?.name, fixture.expected.importSymbol);
});

void test("a section-backed dynamic symbol table does not need a DT_SYMTABSZ cross-check when the tag is absent", async () => {
  const fixture = await runtimeFixture();
  fixture.view.setBigUint64(fixture.entry(14), 21n, true); // Replace DT_SYMTABSZ with DT_DEBUG.

  const parsed = await fixture.parse();

  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.deepEqual(parsed.dynSymbols?.issues, []);
});
