"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfProgramHeader, ElfSectionHeader } from "../../analyzers/elf/types.js";
import { collectElfDisassemblySeedsFromSections } from "../../analyzers/elf/disassembly-seeds-sections.js";
import { MockFile } from "../helpers/mock-file.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 1,
    typeName: "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 1n,
    memsz: 1n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfProgramHeader;

const sec = (overrides: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 1,
    typeName: null,
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 0n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfSectionHeader;

void test("collectElfDisassemblySeedsFromSections reads pointers from SHT_INIT_ARRAY", async () => {
  const bytes = new Uint8Array([
    0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // 0x2000 (u64 LE)
  ]);
  const file = new MockFile(bytes, "init-array.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromSections({
    file,
    programHeaders: [],
    sections: [sec({ type: 14, name: ".init_array", offset: 0n, size: 8n, index: 1 })],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.vaddrs[0], 0x2000n);
});

void test("collectElfDisassemblySeedsFromSections reads STT_FUNC values from SHT_DYNSYM", async () => {
  const sym = new Uint8Array(24);
  const dv = new DataView(sym.buffer);
  dv.setUint8(4, 0x12); // STB_GLOBAL(1) << 4 | STT_FUNC(2)
  dv.setUint16(6, 1, true); // defined
  dv.setBigUint64(8, 0x2000n, true); // st_value
  const file = new MockFile(sym, "dynsym.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromSections({
    file,
    programHeaders: [ph({ flags: 0x1 })],
    sections: [sec({ type: 11, name: ".dynsym", offset: 0n, size: 24n, entsize: 24n, index: 1 })],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.vaddrs[0], 0x2000n);
});

void test("collectElfDisassemblySeedsFromSections warns on misaligned pointer arrays", async () => {
  const bytes = new Uint8Array(0x30);
  const dv = new DataView(bytes.buffer);
  dv.setUint32(0x10, 0x11223344, true);

  const file = new MockFile(bytes, "preinit-array.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromSections({
    file,
    programHeaders: [],
    sections: [sec({ type: 16, name: ".preinit_array", offset: 0x10n, size: 6n, index: 1 })],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.source, ".preinit_array (SHT_PREINIT_ARRAY)");
  assert.deepEqual(groups[0]?.vaddrs, [0x11223344n]);
  assert.ok(issues.some(issue => issue.includes("pointer size (4 bytes)")));
});

void test("collectElfDisassemblySeedsFromSections resolves symbols relative to section addrs when no PT_LOAD segments exist", async () => {
  const symBytes = new Uint8Array(24);
  const dv = new DataView(symBytes.buffer);
  dv.setUint8(4, 0x12); // STT_FUNC
  dv.setUint16(6, 1, true); // section #1
  dv.setBigUint64(8, 0x10n, true); // offset within section

  const file = new MockFile(symBytes, "dynsym-reloc.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromSections({
    file,
    programHeaders: [],
    sections: [
      sec({ index: 0 }),
      sec({ index: 1, name: ".text", type: 1, addr: 0x4000n }),
      sec({ index: 2, type: 11, name: ".dynsym", offset: 0n, size: 24n, entsize: 0n })
    ],
    is64: true,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.source, ".dynsym function symbols");
  assert.deepEqual(groups[0]?.vaddrs, [0x4010n]);
});

void test("collectElfDisassemblySeedsFromSections reads 32-bit STT_GNU_IFUNC symbols", async () => {
  const symBytes = new Uint8Array(16);
  const dv = new DataView(symBytes.buffer);
  dv.setUint32(4, 0x2000, true);
  dv.setUint8(12, 0x1a); // STB_GLOBAL(1) << 4 | STT_GNU_IFUNC(10)
  dv.setUint16(14, 1, true); // defined

  const file = new MockFile(symBytes, "symtab32.bin");
  const issues: string[] = [];
  const groups = await collectElfDisassemblySeedsFromSections({
    file,
    programHeaders: [ph({ flags: 0x1 })],
    sections: [sec({ type: 2, name: ".symtab", offset: 0n, size: 16n, entsize: 16n, index: 1 })],
    is64: false,
    littleEndian: true,
    issues
  });

  assert.equal(groups.length, 1);
  assert.equal(groups[0]?.source, ".symtab function symbols");
  assert.deepEqual(groups[0]?.vaddrs, [0x2000n]);
});

