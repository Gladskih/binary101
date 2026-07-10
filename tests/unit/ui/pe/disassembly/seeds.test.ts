"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../../analyzers/coff/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../../../../analyzers/pe/optional-header/magic.js";
import type { PeWindowsParseResult } from "../../../../../analyzers/pe/core/parse-result.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { MSVC_RTTI_LAYOUT } from "../../../../../analyzers/pe/msvc-rtti/layout.js";
import { collectPeDisassemblySeeds } from "../../../../../ui/pe-disassembly-seeds.js";

void test("collectPeDisassemblySeeds gathers basic Windows PE entry seeds", async () => {
  const seeds = await collectPeDisassemblySeeds(new File([new Uint8Array(0)], "empty-pe"), createWindowsPe());
  assert.equal(seeds.canonicalMachine, IMAGE_FILE_MACHINE_AMD64);
  assert.equal(seeds.entrypointRva, 0x1234);
  assert.deepEqual(seeds.exportRvas, [0x2000]);
  assert.deepEqual(seeds.unwindBeginRvas, [0x3000]);
  assert.deepEqual(seeds.unwindHandlerRvas, [0x4000]);
  assert.deepEqual(seeds.tlsCallbackRvas, [0x5000]);
  assert.deepEqual(seeds.extraEntrypoints, []);
});

void test("collectPeDisassemblySeeds exposes confirmed Go function starts", async () => {
  const pe = createWindowsPe();
  pe.goRuntime = {
    layout: "go1.20+",
    pointerSize: 8,
    pcHeaderAddress: 0x140002000n,
    moduleDataAddress: 0x140003000n,
    fileCount: 1,
    textRange: { start: 0x140002000n, end: 0x140002040n },
    functions: [
      { name: "runtime.main", start: 0x140002000n, end: 0x140002020n },
      { name: "main.main", start: 0x140002020n, end: 0x140002040n }
    ]
  };

  const seeds = await collectPeDisassemblySeeds(new File([new Uint8Array(0)], "go-pe"), pe);

  assert.deepEqual(seeds.extraEntrypoints, [{
    source: "Go runtime functab",
    rvas: [0x2000, 0x2020]
  }]);
});

void test("collectPeDisassemblySeeds exposes only unique executable MSVC RTTI targets", async () => {
  const pe = createWindowsPe();
  pe.sections.push({
    name: inlinePeSectionName(".rdata"),
    virtualAddress: 0x3000,
    virtualSize: 0x1000,
    sizeOfRawData: 0x1000,
    pointerToRawData: 0x3000,
    characteristics: 0x40000040
  });
  pe.msvcRtti = {
    layout: MSVC_RTTI_LAYOUT,
    classHierarchies: [],
    completeObjectLocators: [],
    types: [],
    vftables: [
      {
        completeObjectLocatorRva: 0x5000,
        functionTargetRvas: [
          0x2000,
          0x2010,
          0x2000,
          0x3000,
          0x7000,
          0x1_0000_0000,
          -1,
          1.5
        ],
        locatorSlotRva: 0x5100,
        rva: 0x5108
      },
      {
        completeObjectLocatorRva: 0x5200,
        functionTargetRvas: [0x2010],
        locatorSlotRva: 0x5300,
        rva: 0x5308
      }
    ]
  };

  const seeds = await collectPeDisassemblySeeds(
    new File([new Uint8Array(0)], "msvc-rtti-pe"),
    pe
  );

  assert.deepEqual(seeds.extraEntrypoints, [{
    source: "MSVC RTTI vftables",
    rvas: [0x2000, 0x2010]
  }]);
});

const createWindowsPe = (): PeWindowsParseResult => ({
  dos: {} as PeWindowsParseResult["dos"],
  signature: "PE",
  coff: { Machine: IMAGE_FILE_MACHINE_AMD64 } as PeWindowsParseResult["coff"],
  opt: {
    Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC,
    AddressOfEntryPoint: 0x1234,
    ImageBase: 0x140000000n,
    SizeOfImage: 0x8000,
    SizeOfHeaders: 0x400
  } as PeWindowsParseResult["opt"],
  dirs: [],
  sections: [{
    name: inlinePeSectionName(".text"),
    virtualAddress: 0x2000,
    virtualSize: 0x1000,
    sizeOfRawData: 0x1000,
    pointerToRawData: 0x2000,
    characteristics: 0x20000000 // Microsoft PE format: IMAGE_SCN_MEM_EXECUTE.
  }],
  entrySection: null,
  rvaToOff: () => null,
  imageEnd: 0,
  imageSizeMismatch: false,
  hasCert: false,
  debug: null,
  imports: {} as PeWindowsParseResult["imports"],
  loadcfg: null,
  exports: {
    entries: [
      { rva: 0x2000, forwarder: null },
      { rva: 0, forwarder: null },
      { rva: 0x7000, forwarder: null },
      { rva: 0x2100, forwarder: "other.dll.Target" }
    ]
  } as PeWindowsParseResult["exports"],
  tls: { CallbackRvas: [0x5000, 0] } as PeWindowsParseResult["tls"],
  reloc: null,
  msvcRtti: null,
  exception: {
    beginRvas: [0x3000, 0],
    handlerRvas: [0x4000, 0]
  } as PeWindowsParseResult["exception"],
  boundImports: null,
  delayImports: null,
  clr: null,
  security: null,
  iat: null,
  importLinking: null,
  resources: null
});
