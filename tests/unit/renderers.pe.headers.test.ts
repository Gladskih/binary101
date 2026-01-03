"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { renderHeaders } from "../../renderers/pe/headers.js";
import type { PeParseResult } from "../../analyzers/pe/index.js";

const createBasePe = (): PeParseResult =>
  ({
    dos: {
      e_magic: "MZ",
      e_cblp: 0,
      e_cp: 0,
      e_crlc: 0,
      e_cparhdr: 0,
      e_minalloc: 0,
      e_maxalloc: 0,
      e_ss: 0,
      e_sp: 0,
      e_csum: 0,
      e_ip: 0,
      e_cs: 0,
      e_lfarlc: 0,
      e_oemid: 0,
      e_oeminfo: 0,
      e_lfanew: 0x80,
      stub: { kind: "stub", note: "" }
    },
    coff: {
      Machine: 0x14c,
      NumberOfSections: 0,
      TimeDateStamp: 0,
      PointerToSymbolTable: 0,
      NumberOfSymbols: 0,
      SizeOfOptionalHeader: 0,
      Characteristics: 0
    },
    opt: {
      isPlus: false,
      Magic: 0x10b,
      LinkerMajor: 0,
      LinkerMinor: 0,
      SizeOfCode: 0,
      SizeOfInitializedData: 0,
      SizeOfUninitializedData: 0,
      AddressOfEntryPoint: 0,
      ImageBase: 0x400000,
      SectionAlignment: 0x1000,
      FileAlignment: 0x200,
      OSVersionMajor: 0,
      OSVersionMinor: 0,
      ImageVersionMajor: 0,
      ImageVersionMinor: 0,
      SubsystemVersionMajor: 0,
      SubsystemVersionMinor: 0,
      Subsystem: 2,
      DllCharacteristics: 0,
      SizeOfImage: 0,
      SizeOfHeaders: 0,
      CheckSum: 0,
      SizeOfStackReserve: 0,
      SizeOfStackCommit: 0,
      SizeOfHeapReserve: 0,
      SizeOfHeapCommit: 0
    },
    dirs: [],
    sections: [],
    entrySection: null,
    rvaToOff: (() => null) as unknown,
    imports: [],
    rsds: null,
    debugWarning: null,
    loadcfg: null,
    exports: null as unknown,
    tls: null,
    reloc: null as unknown,
    exception: null as unknown,
    boundImports: null as unknown,
    delayImports: null as unknown,
    clr: null,
    security: null,
    iat: null,
    resources: null,
    overlaySize: 0,
    imageEnd: 0,
    imageSizeMismatch: false,
    coverage: [],
    hasCert: false,
    signature: "PE"
  }) as unknown as PeParseResult;

void test("renderHeaders covers known/unknown branches and exact linker versions", () => {
  const pe = createBasePe();
  pe.opt.isPlus = true;
  pe.opt.LinkerMajor = 14;
  pe.opt.LinkerMinor = 2;
  pe.opt.OSVersionMajor = 6;
  pe.opt.OSVersionMinor = 1;
  pe.coff.Characteristics = 0x2000;
  pe.dirs = [{ index: 1, name: "IMPORT", rva: 0x1000, size: 0x10 }];
  pe.sections = [
    {
      name: ".text",
      virtualSize: 0x100,
      virtualAddress: 0x1000,
      sizeOfRawData: 0x200,
      pointerToRawData: 0x400,
      entropy: 6.5,
      characteristics: 0x60000020
    },
    {
      name: ".weird",
      virtualSize: 0x20,
      virtualAddress: 0x2000,
      sizeOfRawData: 0x20,
      pointerToRawData: 0x600,
      characteristics: 0
    }
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
  pe.opt.LinkerMajor = 13;
  pe.opt.LinkerMinor = 0;
  pe.opt.OSVersionMajor = 11;
  pe.opt.OSVersionMinor = 0;
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
