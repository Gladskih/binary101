"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeApiStringReferenceCollector } from "../../../../../analyzers/pe/disassembly/api-string-references.js";
import type { PeImportParseResult } from "../../../../../analyzers/pe/imports/index.js";
import type { PeImportMetadataEntry } from "../../../../../pe-import-metadata-schema.js";
import {
  fixtureIced,
  imm,
  instruction,
  mem
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE = 0x400000n;
const IAT_RVA = 0x2000;
const TEXT_RVA = 0x1000;
const PE_HEADER_RVA_LIMIT = 0x400;

const metadata: PeImportMetadataEntry = {
  sourceKind: "winapi",
  id: "winapi:KERNEL32.dll:GetProcAddress",
  module: "KERNEL32.dll",
  entrypoint: "GetProcAddress",
  namespace: null,
  api: "GetProcAddress",
  signature: "GetProcAddress",
  returnType: "void *",
  rawReturnType: "void *",
  parameters: [{
    name: "lpProcName",
    type: "Windows.Win32.Foundation.PCSTR",
    rawType: "Windows.Win32.Foundation.PCSTR",
    direction: "in",
    x86StackBytes: Uint32Array.BYTES_PER_ELEMENT
  }],
  callingConvention: "winapi",
  variadic: false,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
};

const imports: PeImportParseResult = {
  thunkEntrySize: Uint32Array.BYTES_PER_ELEMENT,
  entries: [{
    dll: "KERNEL32.dll",
    originalFirstThunkRva: 0x2800,
    timeDateStamp: 0,
    forwarderChain: 0,
    firstThunkRva: IAT_RVA,
    lookupSource: "import-lookup-table",
    thunkTableTerminated: true,
    functions: [{ name: "GetProcAddress", apiMetadata: metadata }]
  }]
};

const imageVa = (rva: number): bigint => IMAGE_BASE + BigInt(rva);

void test("collector skips API string candidates inside PE headers", async () => {
  const collector = createPeApiStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE,
    is64Bit: false,
    imports,
    headerRvaLimit: PE_HEADER_RVA_LIMIT,
    rvaToOff: rva => rva < PE_HEADER_RVA_LIMIT ? rva : null
  });

  collector.record(instruction("Push", [imm(IMAGE_BASE)], { ip: imageVa(TEXT_RVA), length: 1 }));
  collector.record(instruction(
    "Call",
    [mem("UInt32", undefined, imageVa(IAT_RVA))],
    {
      ip: imageVa(TEXT_RVA + 1),
      length: 1,
      flowControl: "IndirectCall",
      indirectControlFlow: "near-call"
    }
  ));

  assert.deepEqual(
    await collector.references(new MockFile(new Uint8Array([0x4d, 0x5a, 0x78, 0x00]))),
    []
  );
});
