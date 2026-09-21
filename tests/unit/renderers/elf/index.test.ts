"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderElf, renderHeader } from "../../../../renderers/elf/index.js";
import type { ElfParseResult } from "../../../../analyzers/elf/types.js";

const createRendererElfSubject = (): ElfParseResult =>
  ({
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
  }) as unknown as ElfParseResult;

void test("renderElf (ELF) renders collapsible program/section tables with hints", () => {
  const html = renderElf(createRendererElfSubject());

  assert.ok(html.includes("Program headers (1)"));
  assert.ok(html.includes("Section headers (3)"));
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
  assert.ok(!html.includes("Unknown ("));
});

void test("places the collapsed instruction panel before collapsed ELF metadata", () => {
  const html = renderElf(createRendererElfSubject());

  assert.ok(html.startsWith(`<section id="elfInstructionSetsPanel"><details class="analysisPanel">`));
  assert.ok(!html.includes(`<b>Identification</b>`));
  assert.match(html, /<dt data-accessible-tooltip title="[^"]+">Class<\/dt>/);
  assert.deepEqual(
    Array.from(html.slice(html.indexOf("<b>ELF header</b>"), html.indexOf("</dl>"))
      .matchAll(/<dt data-accessible-tooltip title="[^"]+">([^<]+)<\/dt>/g), match => match[1]),
    ["Class", "Data", "OS ABI", "ABI version", "Type", "Machine", "Entry",
      "Program headers", "Section headers", "Header size", "PH entry size", "SH entry size"]
  );
  assert.match(html, /<dt[^>]*>OS ABI<\/dt>/);
  assert.ok(html.includes(`<summary class="peSectionSummary"><b>ELF header</b></summary>`));
  assert.ok(!html.includes("Show program headers"));
  assert.ok(!html.includes("Show section headers"));
  assert.ok(!html.includes("<details open"));
  assert.ok(!html.includes("Big picture"));
});

// Assigned EI_OSABI values and the processor-specific range: gABI Appendix B.
// https://gabi.xinuos.com/elf/b-osabi.html
for (const [code, label] of [
  [0, "System V / unspecified"], [1, "HP-UX"], [2, "NetBSD"], [3, "GNU/Linux"],
  [6, "Solaris"], [7, "AIX"], [8, "IRIX"], [9, "FreeBSD"], [10, "Tru64"],
  [11, "Modesto"], [12, "OpenBSD"], [13, "OpenVMS"], [14, "NonStop"],
  [15, "AROS"], [16, "FenixOS"], [17, "CloudABI"], [63, "Unrecognized (63)"],
  [18, "OpenVOS"], [4, "Unrecognized (4)"], [64, "Architecture-specific (64)"],
  [255, "Architecture-specific (255)"]
] as const) {
  void test(`ELF header selects OS ABI ${label} separately from ABI version`, () => {
    const elf = createRendererElfSubject();
    elf.ident.osabi = code;
    elf.ident.abiVersion = 0;
    const out: string[] = [];

    renderHeader(elf, out);

    const html = out.join("");
    const osAbiHtml = /OS ABI<\/dt><dd>([\s\S]*?)<\/dd>/.exec(html)?.[1] ?? "";
    assert.equal(osAbiHtml.match(/class="opt sel"/g)?.length, 1);
    assert.match(osAbiHtml, new RegExp(`class="opt sel"[^>]*>${label.replace(/[()]/g, "\\$&")}<`));
    assert.match(osAbiHtml, /class="opt sel" data-accessible-tooltip/);
    assert.match(html, /<dt[^>]*>ABI version<\/dt><dd>0<\/dd>/);
  });
}

// gABI Appendix A assigns SPARC=2, S390=22, AVR=83 and AIECTRLCODE=269.
// 65535 is outside the registry. https://gabi.xinuos.com/elf/a-emachine.html
// Legacy Alpha/FR-V: https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf-em.h
for (const [code, label] of [[2, "SPARC"], [22, "S390"], [83, "AVR"],
  [257, "65816"], [258, "LOONGARCH"], [0x9026, "ALPHA (legacy/unofficial)"],
  [0x5441, "CYGNUS_FRV (legacy/unofficial)"],
  [269, "AIECTRLCODE"], [65535, "Unknown machine (65535)"]] as const) {
  void test(`ELF machine chips preserve machine ${code}`, () => {
    const elf = createRendererElfSubject();
    elf.header.machine = code;
    const out: string[] = [];

    renderHeader(elf, out);

    const machineHtml = /Machine<\/dt><dd>([\s\S]*?)<\/dd>/.exec(out.join(""))?.[1] ?? "";
    assert.equal(machineHtml.match(/class="opt sel"/g)?.length, 1);
    assert.ok(machineHtml.includes(`>${label}</span>`));
    assert.ok(machineHtml.indexOf('class="opt sel"') < machineHtml.indexOf("<details>"));
    assert.ok(machineHtml.includes("Other machine values"));
    assert.match(machineHtml, /class="opt sel" data-accessible-tooltip/);
    assert.match(machineHtml, /class="opt dim"[^>]*>x86-64<\/span>/);
    assert.ok(machineHtml.endsWith("</details>"));
  });
}

void test("ELF header preserves unknown class, data and object type codes", () => {
  const elf = createRendererElfSubject();
  // gABI reserves class/data 255 and e_type 5; retain the exact unrecognized codes.
  // https://gabi.xinuos.com/elf/02-eheader.html
  elf.ident.classByte = 255;
  elf.ident.dataByte = 255;
  elf.header.type = 5;
  const out: string[] = [];

  renderHeader(elf, out);

  const html = out.join("");
  assert.match(/Class<\/dt><dd>([\s\S]*?)<\/dd>/.exec(html)?.[1] ?? "",
    /class="opt sel" data-accessible-tooltip[^>]*>Unknown \(255\)<\/span>/);
  assert.match(/Data<\/dt><dd>([\s\S]*?)<\/dd>/.exec(html)?.[1] ?? "",
    /class="opt sel" data-accessible-tooltip[^>]*>Unknown \(255\)<\/span>/);
  assert.match(/Type<\/dt><dd>([\s\S]*?)<\/dd>/.exec(html)?.[1] ?? "",
    /class="opt sel" data-accessible-tooltip[^>]*>Unknown \(5\)<\/span>/);
});
