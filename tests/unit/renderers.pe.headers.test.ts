"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../renderers/pe/headers.js";
import type { PeWindowsOptionalHeader } from "../../analyzers/pe/types.js";
import { createBasePe, createPeSection } from "../fixtures/pe-renderer-headers-fixture.js";

void test("renderHeaders covers known/unknown branches and exact linker versions", () => {
  const pe = createBasePe();
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
  assert.ok(html.includes("dynamic-link library"));
  assert.ok(html.includes("14.2 - VS2019 era"));
  assert.ok(html.includes("Windows 7"));
  assert.ok(html.includes("DOS stub: stub - hello"));
  assert.ok(html.includes("Rich header"));
  assert.ok(html.includes("Tool and build names"));
  assert.ok(html.includes("Show sections (2)"));
  assert.ok(html.includes("peChecksumValidateButton"));
  assert.ok(html.includes("peChecksumStatus"));
});

void test("renderHeaders handles fallbacks and missing optional parts", () => {
  const pe = createBasePe();
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
  assert.ok(html.includes("executable image"));
  assert.ok(html.includes("13.0 - MSVC (pre-VS2015)"));
  assert.ok(html.includes("11.0 (11.0)"));
  assert.ok(html.includes("Rich header: not present"));
});

void test("renderHeaders renders ROM-specific optional fields and omits Windows-only controls", () => {
  const pe = createBasePe();
  pe.coff.Machine = 0x0166;
  // Microsoft PE/COFF: 0x107 identifies IMAGE_ROM_OPTIONAL_HEADER.
  pe.opt = {
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
  };
  pe.entrySection = { name: ".text", index: 0 };
  pe.sections = [createPeSection(".text", { virtualSize: 0x200, pointerToRawData: 0x200 })];

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("firmware or option ROM image"));
  assert.ok(html.includes("IMAGE_ROM_OPTIONAL_HEADER"));
  assert.ok(html.includes("BaseOfBss"));
  assert.ok(html.includes("GprMask"));
  assert.ok(html.includes("CprMask"));
  assert.ok(html.includes("GpValue"));
  assert.ok(!html.includes("peChecksumValidateButton"));
  assert.ok(!html.includes("OperatingSystemVersion"));
  assert.ok(!html.includes("SizeOfImage"));
});

void test("renderHeaders keeps unknown optional-header magic in a generic header-only view", () => {
  const pe = createBasePe();
  // Deliberately non-standard optional-header magic to exercise the generic fallback path.
  pe.opt = {
    Magic: 0x999,
    LinkerMajor: 1,
    LinkerMinor: 0,
    SizeOfCode: 0,
    SizeOfInitializedData: 0,
    SizeOfUninitializedData: 0,
    AddressOfEntryPoint: 0x1000,
    BaseOfCode: 0x1000
  };
  pe.sections = [createPeSection(".text", { sizeOfRawData: 0x100, pointerToRawData: 0x200 })];

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.ok(html.includes("unrecognized optional-header magic"));
  assert.ok(html.includes("optional-header magic is not one of the standard PE32, PE32+, or ROM layouts"));
  assert.ok(html.includes("Variant-specific fields stop here"));
  assert.ok(!html.includes("peChecksumValidateButton"));
});

void test("renderHeaders maps COFF characteristic bits to the correct semantic labels", () => {
  const pe = createBasePe();
  pe.coff.Characteristics = 0x5000; // SYSTEM | UP_SYSTEM_ONLY

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>SYSTEM<\/span>/);
  assert.match(html, /<span class="opt dim"[^>]*>DLL<\/span>/);
  assert.match(html, /<span class="opt sel"[^>]*>UP_SYSTEM_ONLY<\/span>/);
});

void test("renderHeaders uses the official Microsoft subsystem labels", () => {
  const pe = createBasePe();
  // Microsoft PE format, "Windows Subsystem": 8 = IMAGE_SUBSYSTEM_NATIVE_WINDOWS.
  (pe.opt as PeWindowsOptionalHeader).Subsystem = 8;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>Native Windows<\/span>/);
  assert.match(html, /Native Windows - Native Win9x driver \(0x0008\)/);
});

void test("renderHeaders surfaces clearer official labels where they help a learner", () => {
  const pe = createBasePe();
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
  const pe = createBasePe();
  // Microsoft PE format, "Machine Types": 0x01C2 = IMAGE_FILE_MACHINE_THUMB.
  pe.coff.Machine = 0x01c2;

  const out: string[] = [];
  renderHeaders(pe, out);
  const html = out.join("");

  assert.match(html, /<span class="opt sel"[^>]*>Thumb<\/span>/);
  assert.match(html, /Thumb - ARM Thumb code: compact instructions often used to save space \(0x01c2\)/);
});
