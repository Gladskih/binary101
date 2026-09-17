"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  parseProgramHeadersWithGuards,
  parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts
} from "../../../../analyzers/elf/header-tables.js";
import type { ElfHeader } from "../../../../analyzers/elf/types.js";
import { MockFile } from "../../../helpers/mock-file.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { parseElf } from "../../../../analyzers/elf/index.js";

const baseHeader = (partial: Partial<ElfHeader>): ElfHeader => ({
  type: 2,
  typeName: "Executable",
  machine: 0x3e,
  machineName: "x86-64",
  entry: 0n,
  phoff: 0n,
  shoff: 0n,
  flags: 0,
  ehsize: 64,
  phentsize: 56,
  phnum: 0,
  shentsize: 64,
  shnum: 0,
  shstrndx: 0,
  ...partial
});

void test("resolveExtendedHeaderCounts reads values from section header #0", async () => {
  const bytes = new Uint8Array(256).fill(0);
  const sectionZero = new DataView(bytes.buffer, 64, 64);
  sectionZero.setBigUint64(32, 7n, true); // real shnum
  sectionZero.setUint32(40, 3, true); // real shstrndx
  sectionZero.setUint32(44, 5, true); // real phnum
  const file = new MockFile(bytes, "ext.elf", "application/x-elf");

  const issues: string[] = [];
  const resolved = await resolveExtendedHeaderCounts(
    file,
    baseHeader({ phnum: 0xffff, shoff: 64n, shnum: 0, shstrndx: 0xffff }),
    true,
    true,
    issues,
    64
  );

  assert.equal(resolved.phnum, 5);
  assert.equal(resolved.shnum, 7);
  assert.equal(resolved.shstrndx, 3);
  assert.deepEqual(issues, []);
});

void test("resolveExtendedHeaderCounts reports missing section table for extended numbering", async () => {
  const file = new MockFile(new Uint8Array(64), "ext-missing.elf", "application/x-elf");
  const issues: string[] = [];
  const resolved = await resolveExtendedHeaderCounts(
    file,
    baseHeader({ phnum: 0xffff, shoff: 0n, shnum: 0, shstrndx: 0xffff }),
    true,
    true,
    issues,
    64
  );

  assert.equal(resolved.phnum, 0);
  assert.equal(resolved.shnum, 0);
  assert.equal(resolved.shstrndx, 0);
  assert.ok(issues.some(issue => issue.includes("requires section header #0")));
});

void test("parseProgramHeadersWithGuards rejects undersized entries", async () => {
  const file = new MockFile(new Uint8Array(256), "ph-small.elf", "application/x-elf");
  const issues: string[] = [];
  const entries = await parseProgramHeadersWithGuards(
    file,
    baseHeader({ phoff: 64n, phnum: 1, phentsize: 16 }),
    true,
    true,
    issues
  );

  assert.deepEqual(entries, []);
  assert.ok(issues.some(issue => issue.includes("Program header entry size (16)")));
});

void test("parseProgramHeadersWithGuards parses available program headers", async () => {
  const bytes = new Uint8Array(256).fill(0);
  new DataView(bytes.buffer).setUint32(64, 1, true);
  const file = new MockFile(bytes, "ph-ok.elf", "application/x-elf");
  const entries = await parseProgramHeadersWithGuards(
    file,
    baseHeader({ phoff: 64n, phnum: 1, phentsize: 56 }),
    true,
    true,
    []
  );

  assert.equal(entries.length, 1);
  assert.equal(entries[0]?.type, 1);
});

void test("parseSectionHeadersWithNames resolves section names from string table", async () => {
  const headerSize = 64;
  const tableOffset = headerSize;
  const entrySize = 64;
  const strings = new TextEncoder().encode("\0.sec0\0.shstrtab\0");
  const stringsOffset = tableOffset + entrySize * 2;
  const bytes = new Uint8Array(stringsOffset + strings.length).fill(0);
  const dv = new DataView(bytes.buffer);
  const section0 = tableOffset;
  const section1 = tableOffset + entrySize;
  dv.setUint32(section0 + 0, 1, true); // ".sec0"
  dv.setUint32(section0 + 4, 1, true);
  dv.setUint32(section1 + 0, 7, true); // ".shstrtab"
  dv.setUint32(section1 + 4, 3, true);
  dv.setBigUint64(section1 + 24, BigInt(stringsOffset), true);
  dv.setBigUint64(section1 + 32, BigInt(strings.length), true);
  bytes.set(strings, stringsOffset);
  const file = new MockFile(bytes, "sections.elf", "application/x-elf");

  const sections = await parseSectionHeadersWithNames(
    file,
    baseHeader({ shoff: BigInt(tableOffset), shnum: 2, shentsize: 64, shstrndx: 1 }),
    true,
    true,
    [],
    64
  );

  assert.equal(sections.length, 2);
  assert.equal(sections[0]?.name, ".sec0");
  assert.equal(sections[1]?.name, ".shstrtab");
});

void test("parseSectionHeadersWithNames rejects undersized section entries", async () => {
  const file = new MockFile(new Uint8Array(256), "sections-small.elf", "application/x-elf");
  const issues: string[] = [];
  const sections = await parseSectionHeadersWithNames(
    file,
    baseHeader({ shoff: 64n, shnum: 1, shentsize: 16 }),
    true,
    true,
    issues,
    64
  );

  assert.deepEqual(sections, []);
  assert.ok(issues.some(issue => issue.includes("Section header entry size (16)")));
});

// gABI 2/3: e_shnum >= SHN_LORESERVE (0xff00) must use the zero escape value.
// https://gabi.xinuos.com/elf/02-eheader.html
for (const shnum of [0xff00, 0xfffe, 0xffff]) {
  void test(`rejects reserved e_shnum ${shnum} without interpreting section zero`, async () => {
    const bytes = new Uint8Array(128);
    new DataView(bytes.buffer).setBigUint64(64 + 32, 7n, true);
    const issues: string[] = [];

    const result = await resolveExtendedHeaderCounts(new File([bytes], "count.elf"),
      baseHeader({ shoff: 64n, shnum }), true, true, issues, 64);

    assert.equal(result.shnum, 0);
    assert.match(issues.join(" "), /e_shnum.*reserved/);
  });
}

void test("resolves extended section counts at SHN_LORESERVE", async () => {
  const bytes = new Uint8Array(128);
  new DataView(bytes.buffer).setBigUint64(64 + 32, 0xff00n, true);
  const issues: string[] = [];

  const result = await resolveExtendedHeaderCounts(new File([bytes], "extended.elf"),
    baseHeader({ shoff: 64n, shnum: 0 }), true, true, issues, 64);

  assert.equal(result.shnum, 0xff00);
  assert.deepEqual(issues, []);
});

void test("accepts SHN_UNDEF when section names are absent", async () => {
  const bytes = await createElfFile().arrayBuffer();
  // Elf64_Ehdr.e_shstrndx at 62; SHN_UNDEF=0 (gABI 2).
  new DataView(bytes).setUint16(62, 0, true);

  const result = await parseElf(new File([bytes], "unnamed.elf"));

  assert.deepEqual(result?.issues, []);
  assert.equal(result?.sections[1]?.name, undefined);
});

void test("reports an out-of-range section name table index", async () => {
  const bytes = await createElfFile().arrayBuffer();
  new DataView(bytes).setUint16(62, 2, true); // Fixture has two section headers.

  const result = await parseElf(new File([bytes], "bad-index.elf"));

  assert.match(result!.issues.join(" "), /Section name table header is missing/);
});

void test("rejects a section name table of the wrong type", async () => {
  const bytes = await createElfFile().arrayBuffer();
  // Fixture's second Elf64_Shdr.sh_type: SHT_PROGBITS instead of SHT_STRTAB.
  new DataView(bytes).setUint32(120 + 64 + 4, 1, true);

  const result = await parseElf(new File([bytes], "bad-type.elf"));

  assert.match(result!.issues.join(" "), /Section name table.*SHT_STRTAB/);
  assert.equal(result?.sections[1]?.name, undefined);
});

void test("validates load segment semantics after parsing headers", async () => {
  const bytes = await createElfFile().arrayBuffer();
  // Elf64_Phdr.p_memsz and p_align, gABI 7.1; fixture header starts at 64.
  new DataView(bytes).setBigUint64(64 + 40, 1n, true);
  new DataView(bytes).setBigUint64(64 + 48, 3n, true);

  const result = await parseElf(new File([bytes], "bad-load.elf"));

  assert.match(result!.issues.join(" "), /p_filesz.*p_memsz/);
  assert.match(result!.issues.join(" "), /p_align/);
  assert.equal(result?.programHeaders.length, 1);
});

void test("does not read section zero when no extended field is present", async () => {
  const issues: string[] = [];
  const header = baseHeader({ shoff: 64n, shnum: 2, shstrndx: 1 });

  const result = await resolveExtendedHeaderCounts(new File([], "unused.elf"),
    header, true, true, issues, 64);

  assert.deepEqual(result, header);
  assert.deepEqual(issues, []);
});

void test("preserves ordinary e_shnum while resolving PN_XNUM", async () => {
  const bytes = new Uint8Array(128);
  new DataView(bytes.buffer).setBigUint64(64 + 32, 7n, true);
  new DataView(bytes.buffer).setUint32(64 + 44, 5, true);
  const issues: string[] = [];

  const result = await resolveExtendedHeaderCounts(new File([bytes], "phnum.elf"),
    baseHeader({ shoff: 64n, shnum: 2, phnum: 0xffff }), true, true, issues, 64);

  assert.equal(result.shnum, 2);
  assert.equal(result.phnum, 5);
  assert.deepEqual(issues, []);
});

for (const [size, offset, diagnostic] of [
  [64, 64n, /outside the file/], [127, 64n, /truncated/],
  [128, 1n << 60n, /Section header offset.*too large/]
] as const) {
  void test(`bounds-checks section zero: ${diagnostic}`, async () => {
    const issues: string[] = [];

    const result = await resolveExtendedHeaderCounts(new File([new Uint8Array(size)], "short.elf"),
      baseHeader({ shoff: offset, phnum: 0xffff, shstrndx: 0xffff }), true, true, issues, 64);

    assert.equal(result.shnum, 0);
    assert.equal(result.phnum, 0);
    assert.equal(result.shstrndx, 0);
    assert.match(issues.join(" "), diagnostic);
  });
}

void test("accepts absent section tables without attempting extended numbering", async () => {
  const issues: string[] = [];
  const header = baseHeader({ shoff: 0n, shnum: 0 });

  const result = await resolveExtendedHeaderCounts(new File([], "sectionless.elf"),
    header, true, true, issues, 64);

  assert.deepEqual(result, header);
  assert.deepEqual(issues, []);
});
void test("reports unterminated section names", async () => {
  const bytes = new Uint8Array(await createElfFile().arrayBuffer());
  bytes[bytes.length - 1] = 65;

  const result = await parseElf(new File([bytes], "unterminated"));

  assert.equal(result?.sections[1]?.name, "");
  assert.match(result!.issues.join(" "), /unterminated|NUL/);
});

void test("reports out-of-range section name offsets", async () => {
  const bytes = await createElfFile().arrayBuffer();
  // Fixture second Elf64_Shdr.sh_name, gABI 3.2.
  new DataView(bytes).setUint32(184, 1000, true);

  const result = await parseElf(new File([bytes], "bad-name"));

  assert.equal(result?.sections[1]?.name, "");
  assert.match(result!.issues.join(" "), /reference|offset/);
});


