"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElf } from "../../renderers/elf/index.js";
import type { ElfParseResult } from "../../analyzers/elf/types.js";

void test("renderElf (ELF) renders collapsible program/section tables with hints", () => {
  const elf = {
    ident: { classByte: 2, className: "ELF64", dataByte: 1, dataName: "LSB", osabi: 0, abiVersion: 0 },
    header: {
      type: 2,
      typeName: "Executable",
      machine: 62,
      machineName: "x86-64",
      entry: 0x401000n,
      phoff: 0x40n,
      shoff: 0x200n,
      flags: 0,
      ehsize: 64,
      phentsize: 56,
      phnum: 1,
      shentsize: 64,
      shnum: 3,
      shstrndx: 0
    },
    programHeaders: [
      {
        type: 1,
        typeName: "PT_LOAD",
        offset: 0n,
        vaddr: 0x400000n,
        paddr: 0n,
        filesz: 0x1000n,
        memsz: 0x1000n,
        flags: 5,
        flagNames: ["R", "X"],
        align: 0x1000n,
        index: 0
      }
    ],
    sections: [
      {
        nameOff: 0,
        type: 3,
        typeName: "SHT_STRTAB",
        flags: 0n,
        flagNames: [],
        addr: 0x400900n,
        offset: 0x900n,
        size: 0x80n,
        link: 0,
        info: 0,
        addralign: 0x1n,
        entsize: 0n,
        index: 1,
        name: ".dynstr"
      },
      {
        nameOff: 0,
        type: 11,
        typeName: "SHT_DYNSYM",
        flags: 0x2n,
        flagNames: ["ALLOC"],
        addr: 0x400980n,
        offset: 0x980n,
        size: 0x60n,
        link: 1,
        info: 2,
        addralign: 0x8n,
        entsize: 0x18n,
        index: 2,
        name: ".dynsym"
      },
      {
        nameOff: 0,
        type: 1,
        typeName: "SHT_PROGBITS",
        flags: 0x6n,
        flagNames: ["ALLOC", "EXECINSTR"],
        addr: 0x401000n,
        offset: 0x1000n,
        size: 0x200n,
        link: 0,
        info: 0,
        addralign: 0x10n,
        entsize: 0n,
        index: 3,
        name: ".text"
      }
    ],
    issues: [],
    is64: true,
    littleEndian: true,
    fileSize: 0
  } as unknown as ElfParseResult;

  const html = renderElf(elf);

  assert.ok(html.includes("Show program headers (1)"));
  assert.ok(html.includes("Show section headers (3)"));
  assert.ok(html.includes('class="tableWrap"'));
  assert.ok(html.includes('title="PT_LOAD - Loadable segment."'));
  assert.ok(html.includes('title="Executable code (instructions)."'));
  assert.ok(html.includes("<b>.text</b>"));
  assert.ok(html.includes("4 KB (4096 bytes)"));
  assert.ok(html.includes("Link"));
  assert.ok(html.includes("Info"));
  assert.ok(html.includes("EntSize"));
  assert.ok(html.includes("sh_link is section-type specific"));
  assert.ok(html.includes("sh_info meaning depends on section type"));
  assert.ok(html.includes("1 (.dynstr)"));
  assert.ok(html.includes("2 (symbol index after last local symbol)"));
  assert.ok(html.includes("24 bytes"));
});
