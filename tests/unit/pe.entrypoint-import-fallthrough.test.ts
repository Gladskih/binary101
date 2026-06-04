"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { getReturningImportFallthrough } from "../../analyzers/pe/disassembly/entrypoint-import-fallthrough.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  TestInstruction,
  createExecutableSection,
  fakeIced
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import type { AnalyzePeEntrypointDisassemblyOptions } from "../../analyzers/pe/disassembly/index.js";
import type { IcedX86Module } from "../../analyzers/x86/disassembly-iced.js";

const iced = fakeIced as unknown as IcedX86Module;
type IcedInstruction = Parameters<typeof getReturningImportFallthrough>[3];

const createOptions = (): AnalyzePeEntrypointDisassemblyOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_AMD64,
  is64Bit: true,
  imageBase: 0x140000000n,
  entrypointRva: 0x1000,
  rvaToOff: rva => rva - 0x1000,
  sections: [createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 })]
});

const createBranchInstruction = (nextRva: number, flowControl: number): IcedInstruction => {
  const instruction = new TestInstruction();
  instruction.flowControl = flowControl;
  instruction.nextIP = 0x140000000n + BigInt(nextRva);
  return instruction as unknown as IcedInstruction;
};

const createIndirectCallInstruction = (nextRva: number): IcedInstruction =>
  createBranchInstruction(nextRva, fakeIced.FlowControl["IndirectCall"]);

void test("getReturningImportFallthrough returns in-block fallthrough for known returning imports", () => {
  assert.deepEqual(
    getReturningImportFallthrough(
      iced,
      createOptions(),
      { rvaStart: 0x1000, fileOffsetStart: 0, data: new Uint8Array([0x15, 0xc3]) },
      createIndirectCallInstruction(0x1001),
      {
        label: "KERNEL32.dll!GetSystemTimeAsFileTime",
        slotRva: 0x2000,
        importKind: "eager",
        guardIatEntry: false
      }
    ),
    { kind: "current-block", rva: 0x1001 }
  );
});

void test("getReturningImportFallthrough returns source call returns for import thunks", () => {
  assert.deepEqual(
    getReturningImportFallthrough(
      iced,
      createOptions(),
      { rvaStart: 0x1002, fileOffsetStart: 2, data: new Uint8Array([0x25]) },
      createBranchInstruction(0x1001, fakeIced.FlowControl["IndirectBranch"]),
      {
        label: "KERNEL32.dll!GetSystemTimeAsFileTime",
        slotRva: 0x2000,
        importKind: "eager",
        guardIatEntry: false
      },
      0x1001
    ),
    { kind: "source-call", rva: 0x1001 }
  );
});

void test("getReturningImportFallthrough rejects unknown imports and out-of-block returns", () => {
  assert.equal(
    getReturningImportFallthrough(
      iced,
      createOptions(),
      { rvaStart: 0x1000, fileOffsetStart: 0, data: new Uint8Array([0x15, 0xc3]) },
      createIndirectCallInstruction(0x1001),
      { label: "KERNEL32.dll!ExitProcess", slotRva: 0x2000, importKind: "eager", guardIatEntry: false }
    ),
    null
  );
  assert.equal(
    getReturningImportFallthrough(
      iced,
      createOptions(),
      { rvaStart: 0x1000, fileOffsetStart: 0, data: new Uint8Array([0x15]) },
      createIndirectCallInstruction(0x1001),
      {
        label: "KERNEL32.dll!GetSystemTimeAsFileTime",
        slotRva: 0x2000,
        importKind: "eager",
        guardIatEntry: false
      }
    ),
    null
  );
});
