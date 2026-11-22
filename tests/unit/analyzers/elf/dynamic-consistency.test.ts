import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import {
  elfDynamicStringRange, elfRuntimeStringsForSectionSymbols, validateElfDynamicConsistency
} from "../../../../analyzers/elf/dynamic-consistency.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { dynamicRelocationFixture } from "../../../fixtures/elf-dynamic-relocations.js";
import { relocationSection } from "../../../fixtures/elf-relocations.js";
// gABI 8.3: DT_STRTAB=5, DT_SYMTAB=6, DT_STRSZ=10. Offsets come from the fixture.
const mappedTables = (bits: 32 | 64 = 64) => {
  const fixture = dynamicRelocationFixture(bits);
  fixture.installTags();
  const image = { ...fixture.elf, file: fixture.file() };
  const entries = [...fixture.tags].map(([tag, value]) => ({ tag, value }));
  return { image, entries, symbolOffset: Number(image.sections[2]!.offset),
    strings: { offset: Number(image.sections[3]!.offset), size: Number(image.sections[3]!.size) } };
};
void test("bounds ELF32 dynamic records by the eight-byte Elf32_Dyn stride", () => {
  const { image, entries } = mappedTables(32);
  const [load, dynamic] = image.programHeaders;
  load!.filesz = dynamic!.offset + dynamic!.filesz;

  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), []);
});
void test("selects the nonempty PT_DYNAMIC for the table actually parsed", () => {
  const { image, entries } = mappedTables();
  const dynamic = image.programHeaders[1]!;
  image.programHeaders.unshift({ ...dynamic, filesz: 0n, memsz: 0n });

  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), []);
});

for (const [allocated, expected] of [[0n, []], [2n, [
  "PT_DYNAMIC #1 p_memsz does not contain all of SHT_DYNAMIC #4."
]]] as const) {
  void test(`checks the memory extent of SHT_DYNAMIC padding only for SHF_ALLOC=${allocated}`, () => {
    const { image, entries } = mappedTables();
    const dynamic = image.programHeaders[1]!;
    dynamic.filesz += 16n; // p_memsz covers the observed array including DT_NULL exactly.
    image.sections.push(relocationSection(4, { type: 6, flags: allocated,
      offset: dynamic.offset, addr: dynamic.vaddr, size: dynamic.filesz }));

    assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), expected);
  });
}

void test("does not use the compressed byte size as the size of the dynamic symbol table", () => {
  const { image, entries } = mappedTables();
  const symbols = image.sections[2]!;
  symbols.type = 11;
  symbols.flags = 0x800n; // SHF_COMPRESSED, gABI 3.4.
  symbols.size -= 1n;

  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), []);
});

void test("requires the full SHT_DYNSYM byte range to map at DT_SYMTAB", () => {
  const { image, entries } = mappedTables();
  const symbols = image.sections[2]!;
  symbols.type = 11;
  const [load, dynamic] = image.programHeaders;
  load!.filesz = symbols.offset + symbols.entsize;
  image.programHeaders.push({ ...load!, index: 2, offset: dynamic!.offset, vaddr: dynamic!.vaddr,
    filesz: dynamic!.filesz, memsz: dynamic!.filesz });

  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), [
    "DT_SYMTAB does not map the full SHT_DYNSYM #2 range through PT_LOAD."
  ]);
});


void test("an identical repeated string tag preserves the verified range", () => {
  const { image, entries, strings } = mappedTables();
  const size = { tag: 10, value: BigInt(strings.size) };

  assert.deepEqual(elfDynamicStringRange(image, [...entries, size]), strings);
});

void test("rejects a conflicting DT_STRTAB even when DT_STRSZ is consistent", () => {
  const { image, entries } = mappedTables();
  const issues: string[] = [];

  assert.equal(elfDynamicStringRange(image, [...entries, { tag: 5, value: 1n }], issues), null);
  assert.deepEqual(issues, ["Conflicting DT_STRTAB or DT_STRSZ values."]);
});

void test("handles a missing string size or compressed section at the mapped offset", () => {
  const { image, entries } = mappedTables();
  const missingSize: string[] = [];
  const compressed: string[] = [];
  image.sections[3]!.flags = 0x800n; // SHF_COMPRESSED, gABI 3.4.

  assert.equal(elfDynamicStringRange(image, entries.filter(entry => entry.tag !== 10), missingSize), null);
  assert.equal(elfDynamicStringRange(image, entries, compressed), null);
  assert.equal(elfDynamicStringRange(image, entries), null);
  assert.deepEqual(missingSize, []);
  assert.deepEqual(compressed, ["DT_STRTAB points into a compressed string table."]);
});

void test("uses runtime strings only for an identified or uncontradicted symbol section", () => {
  const { image, entries, symbolOffset, strings } = mappedTables();
  const absent = entries.filter(entry => entry.tag !== 6);

  assert.deepEqual(elfRuntimeStringsForSectionSymbols(image, absent, symbolOffset), strings);
  assert.equal(elfRuntimeStringsForSectionSymbols(image, [...entries, { tag: 6, value: 1n }], symbolOffset), null);
  assert.equal(elfRuntimeStringsForSectionSymbols(image, [...absent, { tag: 6, value: 1n }], symbolOffset), null);
  image.programHeaders.pop(); // Keep PT_LOAD, removing PT_DYNAMIC.
  assert.equal(elfRuntimeStringsForSectionSymbols(image, entries, symbolOffset), null);
  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), []);
});

void test("rejects conflicting symbol tags even when PT_LOAD starts at virtual address zero", () => {
  const { image, entries, symbolOffset } = mappedTables();
  const load = image.programHeaders[0]!;
  const address = load.vaddr;
  load.vaddr = 0n;
  const zeroBasedTags = entries.map(entry =>
    entry.tag === 5 || entry.tag === 6 ? { ...entry, value: entry.value - address } : entry);

  assert.equal(elfRuntimeStringsForSectionSymbols(image,
    [...zeroBasedTags, { tag: 6, value: 0n }], symbolOffset), null);
});

void test("uses a section's file identity even when its memory address is unavailable", () => {
  const { image, entries } = mappedTables();
  const symbols = image.sections[2]!;
  symbols.type = 11; // SHT_DYNSYM without SHF_ALLOC.
  symbols.offset += 24n;
  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }),
    [`DT_SYMTAB disagrees with the location of SHT_DYNSYM #${symbols.index}.`]);
});

void test("compares the virtual address of an allocated symbol section without a file mapping", () => {
  const { image, entries } = mappedTables();
  Object.assign(image.sections[2]!, { type: 11, flags: 2n }); // SHT_DYNSYM, SHF_ALLOC.
  image.programHeaders.shift(); // Keep PT_DYNAMIC, removing PT_LOAD.

  assert.deepEqual(validateElfDynamicConsistency(image, { entries, terminated: true }), [
    "PT_DYNAMIC #1: the dynamic table lacks file-backed PT_LOAD coverage at p_vaddr.",
    "DT_SYMTAB disagrees with the location of SHT_DYNSYM #2."
  ]);
});

void test("checks only linked SHT_STRTAB sections and only meaningful string addresses", () => {
  const { image, entries } = mappedTables();
  const symbols = image.sections[2]!;
  symbols.type = 11; // SHT_DYNSYM.
  image.sections.push(relocationSection(4, { type: 3, flags: 2n, size: 1n }));
  const table = { entries, terminated: true };

  assert.deepEqual(validateElfDynamicConsistency(image, table), []);
  image.sections[3]!.type = 1; // Linked section is not SHT_STRTAB.
  image.sections[3]!.size += 1n;
  assert.deepEqual(validateElfDynamicConsistency(image, table), []);
  image.sections[3]!.type = 3;
  image.sections[3]!.size -= 1n;
  image.sections[3]!.flags = 2n;
  assert.deepEqual(validateElfDynamicConsistency(image,
    { ...table, entries: entries.filter(entry => entry.tag !== 5) }),
  ["ELF dynamic table is missing required DT_STRTAB."]);
});

void test("only trusts the string link of an SHT_DYNAMIC covering the same records", () => {
  const { image, entries } = mappedTables();
  const segment = image.programHeaders[1]!;
  const dynamic = relocationSection(4, { type: 6, flags: 2n, link: 3,
    offset: segment.offset, addr: segment.vaddr, size: segment.filesz });
  image.sections.push(dynamic);
  image.sections[3]!.size += 1n;
  const table = { entries, terminated: true };

  assert.deepEqual(validateElfDynamicConsistency(image, table),
    ["DT_STRSZ (8 bytes) disagrees with linked string section #3 sh_size (9 bytes)."]);
  dynamic.offset += 1n;
  assert.deepEqual(validateElfDynamicConsistency(image, table),
    ["PT_DYNAMIC #1 p_offset disagrees with SHT_DYNAMIC #4 sh_offset."]);
});

const dynamicFixture = async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = expectDefined(await parseElf(file));
  const dynamic = expectDefined(parsed.sections.find(section => section.type === 6)); // SHT_DYNAMIC
  const bytes = await file.arrayBuffer();
  return { parsed, dynamic, expected, view: new DataView(bytes),
    file: () => new File([bytes], file.name) };
};

void test("uses DT_STRSZ to bound runtime symbol names and reports conflicting section size", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // Fixture's second Elf64_Dyn entry is DT_STRSZ, d_val at +8.
  const size = strings.size - BigInt(fixture.expected.exportSymbol.length + 1);
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 16 + 8, size, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.deepEqual(parsed.dynamic?.consistencyIssues,
    [`DT_STRSZ (${size} bytes) disagrees with linked string section #${strings.index} sh_size (${strings.size} bytes).`]);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
  assert.equal(parsed.dynSymbols?.exportSymbols.length, 0);
  assert.equal(parsed.dynSymbols?.importSymbols[0]?.name, fixture.expected.importSymbol);
});

void test("warns when DT_STRTAB points past the start of its linked string section", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // The first entry is DT_STRTAB; file offset and VA advance together in the fixture's PT_LOAD.
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 8, strings.addr + 1n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  const issues = parsed.dynamic?.consistencyIssues?.join(" ") ?? "";
  assert.match(issues, /DT_STRTAB.*sh_addr/);
  assert.match(issues, /DT_STRTAB.*different file offset/);
});

void test("keeps section symbol names when DT_SYMTAB points at a different table", async () => {
  const fixture = await dynamicFixture();
  const strings = fixture.parsed.sections[fixture.dynamic.link]!;
  // Redirect DT_SYMTAB (the fixture's 13th Elf64_Dyn) to an unrelated table.
  const entry = Number(fixture.dynamic.offset) + 12 * 16;
  fixture.view.setBigUint64(entry + 8, strings.addr, true);
  fixture.view.setBigUint64(Number(fixture.dynamic.offset) + 16 + 8, strings.size - 8n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /DT_SYMTAB.*SHT_DYNSYM/);
  assert.equal(parsed.dynSymbols?.exportSymbols[0]?.name, fixture.expected.exportSymbol);
});

void test("rejects competing DT_STRSZ values instead of choosing one arbitrarily", async () => {
  const fixture = await dynamicFixture();
  // Replace DT_INIT with a duplicate DT_STRSZ carrying a conflicting value.
  const entry = Number(fixture.dynamic.offset) + 6 * 16;
  fixture.view.setBigInt64(entry, 10n, true);
  fixture.view.setBigUint64(entry + 8, 1n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.deepEqual(parsed.dynamic?.issues, ["Conflicting DT_STRTAB or DT_STRSZ values."]);
  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
});

void test("reports a section that ends before the dynamic segment's terminator", async () => {
  const fixture = await dynamicFixture();
  // Elf64_Shdr.sh_size at +32; omit the final DT_NULL record from the section only.
  const offset = Number(fixture.parsed.header.shoff) + fixture.dynamic.index * 64 + 32;
  fixture.view.setBigUint64(offset, fixture.dynamic.size - 16n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", /DT_NULL beyond.*sh_size/);
  assert.equal(parsed.dynamic?.terminated, true);
});

for (const [fieldOffset, fieldName] of [
  [8, "p_offset"], [16, "p_vaddr"], [32, "p_filesz"], [40, "p_memsz"]
] as const) {
  void test(`reports when PT_DYNAMIC ${fieldName} disagrees with SHT_DYNAMIC`, async () => {
    const fixture = await dynamicFixture();
    const program = expectDefined(fixture.parsed.programHeaders.find(header => header.type === 2));
    // Elf64_Phdr offsets from gABI 7.1.
    const offset = Number(fixture.parsed.header.phoff) + program.index * 56 + fieldOffset;
    const original = fixture.view.getBigUint64(offset, true);
    fixture.view.setBigUint64(offset, original - 16n, true);

    const parsed = expectDefined(await parseElf(fixture.file()));

    assert.match(parsed.dynamic?.consistencyIssues?.join(" ") ?? "", new RegExp(`PT_DYNAMIC.*${fieldName}`));
  });
}

void test("accepts padding after a complete section in the PT_DYNAMIC segment", async () => {
  const fixture = await dynamicFixture();
  const program = expectDefined(fixture.parsed.programHeaders.find(header => header.type === 2));
  const offset = Number(fixture.parsed.header.phoff) + program.index * 56;
  // A full entry of padding after DT_NULL does not affect the dynamic data.
  fixture.view.setBigUint64(offset + 32, program.filesz + 16n, true);
  fixture.view.setBigUint64(offset + 40, program.memsz + 16n, true);

  const parsed = expectDefined(await parseElf(fixture.file()));

  assert.equal(parsed.dynamic?.consistencyIssues, undefined);
  assert.deepEqual(parsed.dynamic?.needed, fixture.expected.needed);
});
