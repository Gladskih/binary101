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
      shnum: 1,
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
        index: 0,
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
  assert.ok(html.includes("Show section headers (1)"));
  assert.ok(html.includes('class="tableWrap"'));
  assert.ok(html.includes('title="PT_LOAD - Loadable segment."'));
  assert.ok(html.includes('title="Executable code (instructions)."'));
  assert.ok(html.includes("<b>.text</b>"));
  assert.ok(html.includes("4 KB (4096 bytes)"));
});

