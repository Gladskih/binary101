"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createPeApiStringReferenceCollector } from "../../../../../analyzers/pe/disassembly/api-string-references.js";
import type { PeImportParseResult } from "../../../../../analyzers/pe/imports/index.js";
import type {
  PeImportMetadataEntry,
  PeImportMetadataParameter
} from "../../../../../pe-import-metadata-schema.js";
import {
  fixtureIced,
  imm,
  instruction,
  mem,
  reg,
  type FixtureMemorySize,
  type FixtureRegister
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const IMAGE_BASE_AMD64 = 0x140000000n;
const IMAGE_BASE_I386 = 0x400000n;
const IAT_RVA = 0x2000;
const RDATA_RVA = 0x3000;
const RDATA_OFFSET = 0x100;
const RDATA_SIZE = 0x200;
const TEXT_RVA = 0x1000;
const SECOND_STRING_DELTA = 0x40;
const IMPORT_LOOKUP_TABLE_RVA = 0x2800;

const parameter = (
  name: string | null,
  type: string,
  x86StackBytes = Uint32Array.BYTES_PER_ELEMENT,
  direction: PeImportMetadataParameter["direction"] = "in"
): PeImportMetadataParameter => ({ name, type, rawType: type, direction, x86StackBytes });

const metadataEntry = (
  sourceKind: PeImportMetadataEntry["sourceKind"],
  module: string,
  entrypoint: string,
  parameters: PeImportMetadataParameter[]
): PeImportMetadataEntry => ({
  sourceKind,
  id: `${sourceKind}:${module}:${entrypoint}`,
  module,
  entrypoint,
  namespace: null,
  api: entrypoint,
  signature: entrypoint,
  returnType: "int",
  rawReturnType: "int",
  parameters,
  callingConvention: sourceKind === "ucrt" ? "cdecl" : "winapi",
  variadic: false,
  noReturn: false,
  setLastError: false,
  characterSet: null,
  architecture: [],
  platform: []
});

const importTable = (
  dll: string,
  metadata: PeImportMetadataEntry,
  thunkEntrySize: number
): PeImportParseResult => ({
  thunkEntrySize,
  entries: [{
    dll,
    originalFirstThunkRva: IMPORT_LOOKUP_TABLE_RVA,
    timeDateStamp: 0,
    forwarderChain: 0,
    firstThunkRva: IAT_RVA,
    lookupSource: "import-lookup-table",
    thunkTableTerminated: true,
    functions: [{ name: metadata.entrypoint, apiMetadata: metadata }]
  }]
});

const asciiz = (text: string): Uint8Array =>
  new Uint8Array([...new TextEncoder().encode(text), 0]);

const utf16z = (text: string): Uint8Array => {
  const bytes = new Uint8Array((text.length + 1) * Uint16Array.BYTES_PER_ELEMENT);
  for (let index = 0; index < text.length; index += 1) {
    bytes[index * 2] = text.charCodeAt(index) & 0xff;
    bytes[index * 2 + 1] = text.charCodeAt(index) >> 8;
  }
  return bytes;
};

const createReader = (
  entries: Array<{ rva: number; bytes: Uint8Array }>
): { reader: MockFile; rvaToOff: (rva: number) => number | null } => {
  const bytes = new Uint8Array(RDATA_OFFSET + RDATA_SIZE);
  bytes.fill(0xff, RDATA_OFFSET);
  entries.forEach(entry => bytes.set(entry.bytes, RDATA_OFFSET + entry.rva - RDATA_RVA));
  return {
    reader: new MockFile(bytes),
    rvaToOff: rva => rva >= RDATA_RVA && rva < RDATA_RVA + RDATA_SIZE
      ? RDATA_OFFSET + rva - RDATA_RVA
      : null
  };
};

const imageVa = (imageBase: bigint, rva: number): bigint => imageBase + BigInt(rva);

const leaArgument = (
  imageBase: bigint,
  ipRva: number,
  register: FixtureRegister,
  argumentRva: number
) => instruction(
  "Lea",
  [reg(register), mem("UInt64", "RIP", imageVa(imageBase, argumentRva))],
  { ip: imageVa(imageBase, ipRva), length: 1 }
);

const pushArgument = (
  imageBase: bigint,
  ipRva: number,
  argumentRva: number
) => instruction(
  "Push",
  [imm(imageVa(imageBase, argumentRva))],
  { ip: imageVa(imageBase, ipRva), length: 1 }
);

const importedCall = (
  imageBase: bigint,
  ipRva: number,
  size: FixtureMemorySize
) => instruction(
  "Call",
  [mem(size, size === "UInt64" ? "RIP" : undefined, imageVa(imageBase, IAT_RVA))],
  {
    ip: imageVa(imageBase, ipRva),
    length: 1,
    flowControl: "IndirectCall",
    indirectControlFlow: "near-call"
  }
);

void test("collector resolves WinAPI UTF-16 string arguments from x64 register calls", async () => {
  const textRva = RDATA_RVA;
  const captionRva = RDATA_RVA + SECOND_STRING_DELTA;
  const { reader, rvaToOff } = createReader([
    { rva: textRva, bytes: utf16z("hello") },
    { rva: captionRva, bytes: utf16z("caption") }
  ]);
  const metadata = metadataEntry("winapi", "USER32.dll", "MessageBoxW", [
    parameter("hWnd", "Windows.Win32.Foundation.HWND"),
    parameter("lpText", "Windows.Win32.Foundation.PWSTR"),
    parameter("lpCaption", "Windows.Win32.Foundation.PWSTR"),
    parameter("uType", "u4")
  ]);
  const collector = createPeApiStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE_AMD64,
    is64Bit: true,
    imports: importTable("USER32.dll", metadata, BigUint64Array.BYTES_PER_ELEMENT),
    rvaToOff
  });

  [
    leaArgument(IMAGE_BASE_AMD64, TEXT_RVA, "RDX", textRva),
    leaArgument(IMAGE_BASE_AMD64, TEXT_RVA + 1, "R8", captionRva),
    importedCall(IMAGE_BASE_AMD64, TEXT_RVA + 2, "UInt64")
  ].forEach(decoded => collector.record(decoded));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    byteLength: reference.byteLength,
    text: reference.text,
    module: reference.callSites[0]?.module,
    entrypoint: reference.callSites[0]?.entrypoint,
    sourceKind: reference.callSites[0]?.sourceKind,
    parameterName: reference.callSites[0]?.parameterName
  })), [
    {
      rva: textRva,
      encoding: "utf-16le",
      byteLength: 10,
      text: "hello",
      module: "USER32.dll",
      entrypoint: "MessageBoxW",
      sourceKind: "winapi",
      parameterName: "lpText"
    },
    {
      rva: captionRva,
      encoding: "utf-16le",
      byteLength: 14,
      text: "caption",
      module: "USER32.dll",
      entrypoint: "MessageBoxW",
      sourceKind: "winapi",
      parameterName: "lpCaption"
    }
  ]);
});

void test("collector resolves UCRT narrow string arguments from x86 stack calls", async () => {
  const fileNameRva = RDATA_RVA;
  const modeRva = RDATA_RVA + SECOND_STRING_DELTA;
  const { reader, rvaToOff } = createReader([
    { rva: fileNameRva, bytes: asciiz("config.ini") },
    { rva: modeRva, bytes: asciiz("rb") }
  ]);
  const metadata = metadataEntry("ucrt", "ucrtbase.dll", "fopen", [
    parameter("_FileName", "const char *"),
    parameter("_Mode", "const char *")
  ]);
  const collector = createPeApiStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE_I386,
    is64Bit: false,
    imports: importTable("ucrtbase.dll", metadata, Uint32Array.BYTES_PER_ELEMENT),
    rvaToOff
  });

  [
    pushArgument(IMAGE_BASE_I386, TEXT_RVA, modeRva),
    pushArgument(IMAGE_BASE_I386, TEXT_RVA + 1, fileNameRva),
    importedCall(IMAGE_BASE_I386, TEXT_RVA + 2, "UInt32")
  ].forEach(decoded => collector.record(decoded));
  const references = await collector.references(reader);

  assert.deepEqual(references.map(reference => ({
    rva: reference.rva,
    encoding: reference.encoding,
    text: reference.text,
    module: reference.callSites[0]?.module,
    entrypoint: reference.callSites[0]?.entrypoint,
    sourceKind: reference.callSites[0]?.sourceKind,
    parameterName: reference.callSites[0]?.parameterName
  })), [
    {
      rva: fileNameRva,
      encoding: "ascii",
      text: "config.ini",
      module: "ucrtbase.dll",
      entrypoint: "fopen",
      sourceKind: "ucrt",
      parameterName: "_FileName"
    },
    {
      rva: modeRva,
      encoding: "ascii",
      text: "rb",
      module: "ucrtbase.dll",
      entrypoint: "fopen",
      sourceKind: "ucrt",
      parameterName: "_Mode"
    }
  ]);
});

void test("collector skips unmapped and unterminated string candidates", async () => {
  const { reader, rvaToOff } = createReader([
    { rva: RDATA_RVA, bytes: new TextEncoder().encode("unterminated") }
  ]);
  const metadata = metadataEntry("ucrt", "ucrtbase.dll", "fopen", [
    parameter("_FileName", "const char *")
  ]);
  const collector = createPeApiStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE_AMD64,
    is64Bit: true,
    imports: importTable("ucrtbase.dll", metadata, BigUint64Array.BYTES_PER_ELEMENT),
    rvaToOff
  });

  [
    leaArgument(IMAGE_BASE_AMD64, TEXT_RVA, "RCX", RDATA_RVA + RDATA_SIZE),
    importedCall(IMAGE_BASE_AMD64, TEXT_RVA + 1, "UInt64"),
    leaArgument(IMAGE_BASE_AMD64, TEXT_RVA + 2, "RCX", RDATA_RVA),
    importedCall(IMAGE_BASE_AMD64, TEXT_RVA + 3, "UInt64")
  ].forEach(decoded => collector.record(decoded));
  const references = await collector.references(reader);

  assert.deepEqual(references, []);
});

void test("collector skips pure output string parameters", async () => {
  const { reader, rvaToOff } = createReader([{ rva: RDATA_RVA, bytes: utf16z("not an input") }]);
  const metadata = metadataEntry("winapi", "KERNEL32.dll", "GetModuleFileNameW", [parameter("hModule", "Windows.Win32.Foundation.HMODULE"), parameter("lpFilename", "Windows.Win32.Foundation.PWSTR", Uint32Array.BYTES_PER_ELEMENT, "out"), parameter("nSize", "u4")]);
  const collector = createPeApiStringReferenceCollector(fixtureIced, {
    imageBase: IMAGE_BASE_AMD64, is64Bit: true,
    imports: importTable("KERNEL32.dll", metadata, BigUint64Array.BYTES_PER_ELEMENT), rvaToOff
  });

  collector.record(leaArgument(IMAGE_BASE_AMD64, TEXT_RVA, "RDX", RDATA_RVA));
  collector.record(importedCall(IMAGE_BASE_AMD64, TEXT_RVA + 1, "UInt64"));

  assert.deepEqual(await collector.references(reader), []);
});
