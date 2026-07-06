"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/index.js";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../../analyzers/coff/machine.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import type { IcedInstructionObject } from "../../../../../analyzers/x86/disassembly-iced.js";
import type { PeDelayImportEntry } from "../../../../../analyzers/pe/imports/delay.js";
import type { PeImportParseResult } from "../../../../../analyzers/pe/imports/index.js";
import {
  imm,
  instruction,
  mem
} from "../../../../helpers/pe-entrypoint-emulation-fixture.js";
import { createScriptedIced } from "../../../../helpers/pe-entrypoint-scripted-iced-fixture.js";
import { MockFile } from "../../../../helpers/mock-file.js";

// Microsoft PE format: RVA fields and executable code-section flags.
const IMAGE_SCN_CNT_CODE = 0x00000020;
const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
const IMAGE_SCN_MEM_READ = 0x40000000;
const IMAGE_BASE_AMD64 = 0x140000000n;
const TEXT_SECTION_RVA = 0x1000;
const IAT_RVA = 0x2000;
const IMPORT_LOOKUP_TABLE_RVA = 0x3000;
const SCRIPTED_INSTRUCTION_LENGTH = 1;
const DELAY_IMPORT_ATTRIBUTES_RVA_BASED = 1;

const createTextSection = (rawSize: number) => [{
  name: inlinePeSectionName(".text"),
  virtualSize: rawSize,
  virtualAddress: TEXT_SECTION_RVA,
  sizeOfRawData: rawSize,
  pointerToRawData: 0,
  characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
}];

const mapTextRvaToOffset = (rawSize: number) => (rva: number): number | null =>
  rva >= TEXT_SECTION_RVA && rva < TEXT_SECTION_RVA + rawSize ? rva - TEXT_SECTION_RVA : null;

const createSingleImport = (): PeImportParseResult => ({
  thunkEntrySize: BigUint64Array.BYTES_PER_ELEMENT,
  entries: [{
    dll: "KERNEL32.dll",
    originalFirstThunkRva: IMPORT_LOOKUP_TABLE_RVA,
    timeDateStamp: 0,
    forwarderChain: 0,
    firstThunkRva: IAT_RVA,
    lookupSource: "import-lookup-table",
    thunkTableTerminated: true,
    functions: [{ name: "Sleep" }]
  }]
});

const createSingleDelayImport = (): { entries: PeDelayImportEntry[] } => ({
  entries: [{
    Attributes: DELAY_IMPORT_ATTRIBUTES_RVA_BASED,
    ModuleHandleRVA: 0,
    ImportAddressTableRVA: IAT_RVA,
    ImportNameTableRVA: 0,
    BoundImportAddressTableRVA: 0,
    UnloadInformationTableRVA: 0,
    TimeDateStamp: 0,
    name: "USER32.dll",
    functions: [{ name: "MessageBoxW" }]
  }]
});

const imageVa = (rva: number): bigint => IMAGE_BASE_AMD64 + BigInt(rva);

const directIatCall = (rva: number): IcedInstructionObject => instruction(
  "Call",
  [mem("UInt64", "RIP", imageVa(IAT_RVA))],
  { flowControl: "IndirectCall", ip: imageVa(rva), length: SCRIPTED_INSTRUCTION_LENGTH }
);

const directIatJump = (rva: number): IcedInstructionObject => instruction(
  "Jmp",
  [mem("UInt64", "RIP", imageVa(IAT_RVA))],
  { flowControl: "IndirectBranch", ip: imageVa(rva), length: SCRIPTED_INSTRUCTION_LENGTH }
);

const directCall = (rva: number, targetRva: number): IcedInstructionObject => instruction(
  "Call",
  [imm(imageVa(targetRva), "NearBranch64")],
  {
    flowControl: "Call",
    ip: imageVa(rva),
    length: SCRIPTED_INSTRUCTION_LENGTH,
    nearBranchTarget: imageVa(targetRva)
  }
);

const nearReturnInstruction = (rva: number): IcedInstructionObject => instruction(
  "Ret",
  [],
  { flowControl: "Return", ip: imageVa(rva), length: SCRIPTED_INSTRUCTION_LENGTH }
);

const analyzeScriptedInstructions = (
  fileName: string,
  instructions: IcedInstructionObject[],
  imports: PeImportParseResult | undefined,
  delayImports: { entries: PeDelayImportEntry[] } | undefined,
  exportRvas: number[] = []
) => analyzePeInstructionSets(
  new MockFile(new Uint8Array(instructions.length), fileName),
  {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: IMAGE_BASE_AMD64,
    entrypointRva: TEXT_SECTION_RVA,
    ...(imports ? { imports } : {}),
    ...(delayImports ? { delayImports } : {}),
    exportRvas,
    rvaToOff: mapTextRvaToOffset(instructions.length),
    sections: createTextSection(instructions.length)
  },
  async () => createScriptedIced(instructions)
);

void test("analyzePeInstructionSets counts direct IAT calls once per decoded instruction", async () => {
  const secondCallRva = TEXT_SECTION_RVA + SCRIPTED_INSTRUCTION_LENGTH;
  const returnRva = secondCallRva + SCRIPTED_INSTRUCTION_LENGTH;
  const instructions = [
    directIatCall(TEXT_SECTION_RVA),
    directIatCall(secondCallRva),
    nearReturnInstruction(returnRva)
  ];

  const report = await analyzeScriptedInstructions(
    "iat-calls.exe",
    instructions,
    createSingleImport(),
    undefined,
    [secondCallRva]
  );

  assert.deepEqual(report.directIatReferences, [{
    slotRva: IAT_RVA,
    callReferenceCount: 2,
    jumpReferenceCount: 0
  }]);
});

void test("analyzePeInstructionSets counts one IAT jump in a shared import thunk", async () => {
  const secondCallRva = TEXT_SECTION_RVA + SCRIPTED_INSTRUCTION_LENGTH;
  const returnRva = secondCallRva + SCRIPTED_INSTRUCTION_LENGTH;
  const thunkRva = returnRva + SCRIPTED_INSTRUCTION_LENGTH;
  const instructions = [
    directCall(TEXT_SECTION_RVA, thunkRva),
    directCall(secondCallRva, thunkRva),
    nearReturnInstruction(returnRva),
    directIatJump(thunkRva)
  ];

  const report = await analyzeScriptedInstructions(
    "iat-thunk.exe",
    instructions,
    createSingleImport(),
    undefined
  );

  assert.deepEqual(report.directIatReferences, [{
    slotRva: IAT_RVA,
    callReferenceCount: 0,
    jumpReferenceCount: 1
  }]);
});

void test("analyzePeInstructionSets counts delay-load IAT references", async () => {
  const report = await analyzeScriptedInstructions(
    "delay-iat-call.exe",
    [directIatCall(TEXT_SECTION_RVA)],
    undefined,
    createSingleDelayImport()
  );

  assert.deepEqual(report.directIatReferences, [{
    slotRva: IAT_RVA,
    callReferenceCount: 1,
    jumpReferenceCount: 0
  }]);
});
