"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../analyzers/pe/machine.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "../../analyzers/pe/optional-header/magic.js";
import type { PeWindowsParseResult } from "../../analyzers/pe/core/parse-result.js";
import { collectPeDisassemblySeeds } from "../../ui/pe-disassembly-seeds.js";

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

const createWindowsPe = (): PeWindowsParseResult => ({
  dos: {} as PeWindowsParseResult["dos"],
  signature: "PE",
  coff: { Machine: IMAGE_FILE_MACHINE_AMD64 } as PeWindowsParseResult["coff"],
  opt: {
    Magic: PE32_PLUS_OPTIONAL_HEADER_MAGIC,
    AddressOfEntryPoint: 0x1234,
    ImageBase: 0x140000000n,
    SizeOfHeaders: 0x400
  } as PeWindowsParseResult["opt"],
  dirs: [],
  sections: [],
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
      { rva: 0x2100, forwarder: "other.dll.Target" }
    ]
  } as PeWindowsParseResult["exports"],
  tls: { CallbackRvas: [0x5000, 0] } as PeWindowsParseResult["tls"],
  reloc: null,
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
