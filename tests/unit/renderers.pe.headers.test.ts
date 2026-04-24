"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../renderers/pe/headers.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";
import type { PeWindowsOptionalHeader } from "../../analyzers/pe/types.js";
import { createBasePe, createPeSection } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderHeaders covers known/unknown branches and exact linker versions", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE/COFF: 0x20b identifies IMAGE_OPTIONAL_HEADER64 (PE32+).
  pe.opt = { ...pe.opt, Magic: 0x20b } as PeWindowsOptionalHeader;
  const windowsOpt = pe.opt as PeWindowsOptionalHeader;
  windowsOpt.LinkerMajor = 14;
  windowsOpt.LinkerMinor = 2;
  windowsOpt.OSVersionMajor = 6;
  windowsOpt.OSVersionMinor = 1;
  // Microsoft PE/COFF: IMAGE_FILE_DLL marks a DLL image.
  pe.coff.Characteristics = 0x2000;
  pe.dirs = [{ index: 1, name: "IMPORT", rva: 0x1000, size: 0x10 }];
  pe.sections = [
    createPeSection(".text", {
      virtualSize: 0x100,
      entropy: 6.5,
      characteristics: 0x60000020
    }),
    createPeSection(".weird", {
      virtualSize: 0x20,
      virtualAddress: 0x2000,
      sizeOfRawData: 0x20,
      pointerToRawData: 0x600,
      characteristics: 0
    })
  ];
  pe.entrySection = { name: ".text", index: 0 };
  pe.dos.stub = { kind: "stub", note: "hello", strings: ["hi"] };
  pe.dos.rich = {
    xorKey: 0x12345678,
    checksum: 0,
    entries: [{ productId: 0x0091, buildNumber: 0x1c87, count: 3 }]
  };

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("64-bit"));
  assert.ok(html.includes("14.2 - VS2019 era"));
  assert.ok(html.includes("Windows 7"));
  assert.ok(html.includes("Portable Executable (PE) / COFF"));
  assert.ok(html.includes("DOS stub: stub - hello"));
  assert.ok(html.includes("Rich header"));
  assert.ok(html.includes("Tool and build names"));
  assert.match(html, /<summary[^>]*><b>PE\/COFF headers<\/b><\/summary>/);
  assert.match(html, /<h4[^>]*>PE signature<\/h4>/);
  assert.match(html, /<h4[^>]*>COFF file header<\/h4>/);
  assert.match(html, /<h4[^>]*>Optional header<\/h4>/);
  assert.match(html, /<summary[^>]*><b>Data directories<\/b> - 1 present, 1 entry<\/summary>/);
  assert.match(html, /<summary[^>]*><b>Section headers<\/b> - 2 sections<\/summary>/);
  assert.ok(html.includes("Signature"));
  assert.ok(html.includes("peChecksumValidateButton"));
  assert.ok(html.includes("peChecksumStatus"));
});

void test("renderHeaders handles fallbacks and missing optional parts", () => {
  const pe: PeParseResult = createBasePe();
  const windowsOpt = pe.opt as PeWindowsOptionalHeader;
  windowsOpt.LinkerMajor = 13;
  windowsOpt.LinkerMinor = 0;
  windowsOpt.OSVersionMajor = 11;
  windowsOpt.OSVersionMinor = 0;
  pe.entrySection = null;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("32-bit"));
  assert.ok(html.includes("13.0 - MSVC (pre-VS2015)"));
  assert.ok(html.includes("11.0 (11.0)"));
  assert.ok(html.includes("Portable Executable (PE) / COFF"));
  assert.ok(html.includes("Rich header: not present"));
});

void test("renderHeaders renders ROM-specific optional fields and omits Windows-only controls", () => {
  const basePe = createBasePe();
  const pe: PeParseResult = {
    ...basePe,
    coff: { ...basePe.coff, Machine: 0x0166 },
    // Microsoft PE/COFF: 0x107 identifies IMAGE_ROM_OPTIONAL_HEADER.
    opt: {
      Magic: 0x107,
      LinkerMajor: 2,
      LinkerMinor: 7,
      SizeOfCode: 0,
      SizeOfInitializedData: 0,
      SizeOfUninitializedData: 0,
      AddressOfEntryPoint: 0x1000,
      BaseOfCode: 0x1000,
      BaseOfData: 0x1100,
      rom: {
        BaseOfBss: 0x2000,
        GprMask: 0x00000003,
        CprMask: [0x11111111, 0x22222222, 0x33333333, 0x44444444],
        GpValue: 0x12345678
      }
    }
  };
  pe.entrySection = { name: ".text", index: 0 };
  pe.sections = [createPeSection(".text", { virtualSize: 0x200, pointerToRawData: 0x200 })];

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Portable Executable (PE) / COFF"));
  assert.ok(html.includes("IMAGE_ROM_OPTIONAL_HEADER"));
  assert.ok(html.includes("BaseOfBss"));
  assert.ok(html.includes("GprMask"));
  assert.ok(html.includes("CprMask"));
  assert.ok(html.includes("GpValue"));
  assert.ok(!html.includes("peChecksumValidateButton"));
  assert.ok(!html.includes("OperatingSystemVersion"));
  assert.ok(!html.includes("SizeOfImage"));
});

void test("renderHeaders keeps unrecognized or absent optional headers in a generic header-only view", () => {
  const basePe = createBasePe();
  const pe: PeParseResult = {
    ...basePe,
    opt: null,
    warnings: ["Optional header Magic 0x999 is not PE32, PE32+, or ROM."],
    sections: [createPeSection(".text", { sizeOfRawData: 0x100, pointerToRawData: 0x200 })]
  };

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("Portable Executable (PE) / COFF"));
  assert.ok(html.includes("Optional header fields are unavailable"));
  assert.ok(!html.includes("peChecksumValidateButton"));
});

void test("renderHeaders maps COFF characteristic bits to the correct semantic labels", () => {
  const pe: PeParseResult = createBasePe();
  pe.coff.Characteristics = 0x5000; // SYSTEM | UP_SYSTEM_ONLY

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>SYSTEM<\/span>/);
  assert.match(html, /<span class="opt dim"[^>]*>DLL<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>UP_SYSTEM_ONLY<\/span>/);
});

void test("renderHeaders maps the reserved and byte-order COFF characteristic bits at their official offsets", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE format, "Characteristics":
  // 0x0040 is reserved, 0x0080 is IMAGE_FILE_BYTES_REVERSED_LO,
  // and 0x0100 is IMAGE_FILE_32BIT_MACHINE.
  pe.coff.Characteristics = 0x01c0;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>RESERVED_0040<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>BYTES_REVERSED_LO<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>32BIT_MACHINE<\/span>/);
  assert.match(html, /<span class="opt dim"[^>]*>DEBUG_STRIPPED<\/span>/);
});

void test("renderHeaders names official section characteristics and decodes alignment as a subfield", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE format, "Section Flags":
  // IMAGE_SCN_ALIGN_* values occupy the 0x00f00000 alignment subfield rather than independent bits.
  pe.sections = [
    createPeSection(".obj", {
      characteristics: 0x00000200 | 0x00c00000 | 0x01000000
    })
  ];

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /LNK_INFO/);
  assert.match(html, /ALIGN_2048BYTES/);
  assert.match(html, /LNK_NRELOC_OVFL/);
  assert.doesNotMatch(html, /ALIGN_1024BYTES/);
  assert.doesNotMatch(html, /ALIGN_4096BYTES/);
});

void test("renderHeaders uses the official Microsoft subsystem labels", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE format, "Windows Subsystem": 8 = IMAGE_SUBSYSTEM_NATIVE_WINDOWS.
  (pe.opt as PeWindowsOptionalHeader).Subsystem = 8;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>Native Windows<\/span>/);
  assert.match(html, /Native Windows - Native Win9x driver \(0x0008\)/);
});

void test("renderHeaders surfaces clearer official labels where they help a learner", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE format, "Machine Types": 0x0200 = Intel Itanium processor family.
  pe.coff.Machine = 0x0200;
  // Microsoft PE format, "Windows Subsystem": 9 = IMAGE_SUBSYSTEM_WINDOWS_CE_GUI.
  (pe.opt as PeWindowsOptionalHeader).Subsystem = 9;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>Intel Itanium \(IA-64\)<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>Windows CE GUI<\/span>/);
  assert.match(html, /Intel Itanium \(IA-64\) - Intel Itanium processor family \(0x0200\)/);
});

void test("renderHeaders explains cryptic machine names such as Thumb", () => {
  const pe: PeParseResult = createBasePe();
  // Microsoft PE format, "Machine Types": 0x01C2 = IMAGE_FILE_MACHINE_THUMB.
  pe.coff.Machine = 0x01c2;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>Thumb<\/span>/);
  assert.match(html, /Thumb - ARM Thumb code: compact instructions often used to save space \(0x01c2\)/);
});
