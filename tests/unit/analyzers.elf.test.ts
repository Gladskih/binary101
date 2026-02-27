"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

type ElfHeaderOptions = {
  phoff?: bigint;
  shoff?: bigint;
  ehsize?: number;
  phentsize?: number;
  phnum?: number;
  shnum?: number;
  shentsize?: number;
  shstrndx?: number;
  headerVersion?: number;
  identVersion?: number;
};

const writeElfHeader = (
  bytes: Uint8Array,
  {
    phoff = 0n,
    shoff = 0n,
    ehsize = 0x40,
    phentsize = 0x38,
    phnum = 0,
    shnum = 0,
    shentsize = 64,
    shstrndx = 0,
    headerVersion = 1,
    identVersion = 1
  }: ElfHeaderOptions = {}
): void => {
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x7f454c46); // \x7FELF
  dv.setUint8(4, 2); // 64-bit
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, identVersion); // ident version
  dv.setUint16(0x10, 2, true); // type: executable
  dv.setUint16(0x12, 0x3e, true); // machine: x86-64
  dv.setUint32(0x14, headerVersion, true);
  dv.setBigUint64(0x18, 0n, true); // entry
  dv.setBigUint64(0x20, phoff, true);
  dv.setBigUint64(0x28, shoff, true);
  dv.setUint32(0x30, 0, true); // flags
  dv.setUint16(0x34, ehsize, true);
  dv.setUint16(0x36, phentsize, true);
  dv.setUint16(0x38, phnum, true);
  dv.setUint16(0x3a, shentsize, true);
  dv.setUint16(0x3c, shnum, true);
  dv.setUint16(0x3e, shstrndx, true);
};

void test("parseElf returns null for non-ELF files", async () => {
  const file = new MockFile(new Uint8Array([0, 1, 2, 3]));
  const parsed = await parseElf(file);
  assert.strictEqual(parsed, null);
});

void test("parseElf notes program headers that sit outside the file", async () => {
  const bytes = new Uint8Array(64).fill(0);
  writeElfHeader(bytes, { phoff: 200n, phnum: 1, shnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-invalid.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.deepStrictEqual(definedParsed.programHeaders, []);
  assert.ok(definedParsed.issues.some(msg => msg.includes("Program header table falls outside the file.")));
});

void test("parseElf surfaces version mismatches and truncated section name table", async () => {
  const bytes = new Uint8Array(160).fill(0);
  // Section table starts after the ELF header, one entry pointing to a truncated name table.
  writeElfHeader(bytes, {
    phoff: 0n,
    phnum: 0,
    shoff: 64n,
    shnum: 1,
    shentsize: 64,
    shstrndx: 0,
    headerVersion: 2,
    identVersion: 2
  });
  const sectionOffset = 64;
  const dv = new DataView(bytes.buffer);
  dv.setUint32(sectionOffset + 0, 0, true); // nameOff
  dv.setUint32(sectionOffset + 4, 1, true); // type
  dv.setBigUint64(sectionOffset + 24, 120n, true); // offset to names
  dv.setBigUint64(sectionOffset + 32, 50n, true); // size of names (truncated)

  const parsed = await parseElf(new MockFile(bytes, "elf-truncated.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.strictEqual(definedParsed.sections.length, 1);
  const section = expectDefined(definedParsed.sections[0]);
  assert.strictEqual(section.name, "");
  assert.ok(definedParsed.issues.some(msg => msg.includes("Unexpected ELF version")));
  assert.ok(definedParsed.issues.some(msg => msg.includes("Section name table is truncated.")));
});

void test("parseElf reports truncated ELF64 headers instead of throwing", async () => {
  const bytes = new Uint8Array(0x34).fill(0);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0, 0x7f454c46, false);
  dv.setUint8(4, 2); // ELF64
  dv.setUint8(5, 1); // little endian
  dv.setUint8(6, 1); // ident version
  dv.setUint16(0x10, 2, true); // executable
  dv.setUint16(0x12, 0x3e, true); // x86-64
  dv.setUint32(0x14, 1, true); // header version

  const parsed = await parseElf(new MockFile(bytes, "elf64-short.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.programHeaders.length, 0);
  assert.equal(definedParsed.sections.length, 0);
  assert.ok(definedParsed.issues.some(msg => msg.includes("ELF64 header is truncated")));
});

void test("parseElf resolves PN_XNUM from section[0].sh_info", async () => {
  const headerSize = 64;
  const phentsize = 56;
  const shentsize = 64;
  const phnum = 1;
  const shnum = 1;
  const phoff = BigInt(headerSize);
  const shoff = BigInt(headerSize + phentsize * phnum);
  const bytes = new Uint8Array(headerSize + phentsize * phnum + shentsize * shnum).fill(0);
  writeElfHeader(bytes, {
    phoff,
    shoff,
    phentsize,
    phnum: 0xffff,
    shnum,
    shentsize,
    shstrndx: 0
  });
  const dv = new DataView(bytes.buffer);
  const phBase = headerSize;
  dv.setUint32(phBase + 0, 1, true); // PT_LOAD
  dv.setUint32(phBase + 4, 4, true); // R
  dv.setBigUint64(phBase + 8, 0n, true); // offset
  dv.setBigUint64(phBase + 16, 0x400000n, true); // vaddr
  dv.setBigUint64(phBase + 24, 0x400000n, true); // paddr
  dv.setBigUint64(phBase + 32, BigInt(bytes.length), true); // filesz
  dv.setBigUint64(phBase + 40, BigInt(bytes.length), true); // memsz
  dv.setBigUint64(phBase + 48, 0x1000n, true); // align
  const sh0Base = Number(shoff);
  dv.setUint32(sh0Base + 44, phnum, true); // sh_info carries real phnum when e_phnum == PN_XNUM

  const parsed = await parseElf(new MockFile(bytes, "elf-pnxnum.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.header.phnum, phnum);
  assert.equal(definedParsed.programHeaders.length, phnum);
});

void test("parseElf resolves extended section count and shstrndx from section[0]", async () => {
  const headerSize = 64;
  const shentsize = 64;
  const shoff = BigInt(headerSize);
  const shstrtabContent = new TextEncoder().encode("\0.shstrtab\0");
  const shstrtabOffset = headerSize + shentsize * 2;
  const bytes = new Uint8Array(shstrtabOffset + shstrtabContent.length).fill(0);
  writeElfHeader(bytes, {
    phoff: 0n,
    phnum: 0,
    shoff,
    shnum: 0,
    shentsize,
    shstrndx: 0xffff
  });
  const dv = new DataView(bytes.buffer);
  const sectionCount = 2;
  const shstrtabIndex = 1;
  const sh0Base = Number(shoff);
  dv.setBigUint64(sh0Base + 32, BigInt(sectionCount), true); // sh_size carries real shnum when e_shnum == 0
  dv.setUint32(sh0Base + 40, shstrtabIndex, true); // sh_link carries real shstrndx when e_shstrndx == SHN_XINDEX
  const sh1Base = sh0Base + shentsize;
  dv.setUint32(sh1Base + 0, 1, true); // nameOff -> ".shstrtab"
  dv.setUint32(sh1Base + 4, 3, true); // SHT_STRTAB
  dv.setBigUint64(sh1Base + 24, BigInt(shstrtabOffset), true);
  dv.setBigUint64(sh1Base + 32, BigInt(shstrtabContent.length), true);
  bytes.set(shstrtabContent, shstrtabOffset);

  const parsed = await parseElf(new MockFile(bytes, "elf-extended-shnum.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.header.shnum, sectionCount);
  assert.equal(definedParsed.header.shstrndx, shstrtabIndex);
  assert.equal(definedParsed.sections.length, sectionCount);
  assert.equal(definedParsed.sections[1]?.name, ".shstrtab");
});

void test("parseElf reports undersized e_ehsize and exits safely", async () => {
  const bytes = new Uint8Array(160).fill(0);
  writeElfHeader(bytes, { ehsize: 0x20, phoff: 64n, phnum: 1, shoff: 120n, shnum: 1 });
  const parsed = await parseElf(new MockFile(bytes, "elf-bad-ehsize.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.programHeaders.length, 0);
  assert.equal(definedParsed.sections.length, 0);
  assert.ok(definedParsed.issues.some(msg => msg.includes("e_ehsize (32) is smaller")));
});

void test("parseElf reports e_ehsize that exceeds file size", async () => {
  const bytes = new Uint8Array(96).fill(0);
  writeElfHeader(bytes, { ehsize: 512, phoff: 0n, phnum: 0, shoff: 0n, shnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-large-ehsize.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.ok(definedParsed.issues.some(msg => msg.includes("e_ehsize (512) exceeds file size")));
});

void test("parseElf rejects undersized program header entries", async () => {
  const bytes = new Uint8Array(160).fill(0);
  writeElfHeader(bytes, { phoff: 64n, phnum: 1, phentsize: 16, shoff: 0n, shnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-small-phentsize.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.programHeaders.length, 0);
  assert.ok(definedParsed.issues.some(msg => msg.includes("Program header entry size (16)")));
});

void test("parseElf rejects undersized section header entries", async () => {
  const bytes = new Uint8Array(160).fill(0);
  writeElfHeader(bytes, { shoff: 64n, shnum: 1, shentsize: 16, shstrndx: 0, phoff: 0n, phnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-small-shentsize.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.sections.length, 0);
  assert.ok(definedParsed.issues.some(msg => msg.includes("Section header entry size (16)")));
});

void test("parseElf reports section header tables outside the file", async () => {
  const bytes = new Uint8Array(96).fill(0);
  writeElfHeader(bytes, { shoff: 512n, shnum: 1, shentsize: 64, shstrndx: 0, phoff: 0n, phnum: 0 });
  const parsed = await parseElf(new MockFile(bytes, "elf-shoff-outside.bin", "application/x-elf"));
  const definedParsed = expectDefined(parsed);
  assert.equal(definedParsed.sections.length, 0);
  assert.ok(definedParsed.issues.some(msg => msg.includes("Section header table falls outside the file.")));
});
