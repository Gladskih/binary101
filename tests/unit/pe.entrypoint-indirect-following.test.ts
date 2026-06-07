"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  TestDecoder,
  analyzeEntrypoint,
  createExecutableSection,
  fakeIced,
  type TestInstruction
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

void test("analyzePeEntrypointDisassembly annotates indirect calls through the IAT", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x15]),
    createExecutableSection({ virtualSize: 1, sizeOfRawData: 1 }),
    0x1000,
    {
      imports: {
        thunkEntrySize: 8,
        entries: [{
          dll: "KERNEL32.dll",
          originalFirstThunkRva: 0x3000,
          timeDateStamp: 0,
          forwarderChain: 0,
          firstThunkRva: 0x2000,
          lookupSource: "import-lookup-table",
          thunkTableTerminated: true,
          functions: [{ name: "ExitProcess" }]
        }]
      }
    }
  );
  const target = result.blocks[0]?.instructions[0]?.target;
  assert.equal(target?.kind, "import");
  assert.equal(target?.label, "KERNEL32.dll!ExitProcess");
  assert.equal(target?.slotRva, 0x2000);
  assert.equal(target?.guardIatEntry, false);
  assert.equal(result.blocks[0]?.instructions.length, 1);
  assert.ok(result.issues.some(issue => /stopped at imported target/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly continues after known returning imports", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x15, 0xc3]),
    createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
    0x1000,
    {
      imports: {
        thunkEntrySize: 8,
        entries: [{
          dll: "KERNEL32.dll",
          originalFirstThunkRva: 0x3000,
          timeDateStamp: 0,
          forwarderChain: 0,
          firstThunkRva: 0x2000,
          lookupSource: "import-lookup-table",
          thunkTableTerminated: true,
          functions: [{ name: "GetSystemTimeAsFileTime" }]
        }]
      }
    }
  );
  const target = result.blocks[0]?.instructions[0]?.target;
  assert.equal(result.blocks.length, 1);
  assert.deepEqual(result.blocks[0]?.instructions.map(instruction => instruction.text), [
    "call [iat]",
    "ret"
  ]);
  assert.equal(target?.kind, "import");
  assert.equal(target?.label, "KERNEL32.dll!GetSystemTimeAsFileTime");
  assert.equal(target?.returnRva, 0x1001);
  assert.equal(target?.returnFollowed, true);
  assert.ok(result.issues.some(issue => /continued after returning import/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly continues after unknown indirect calls", async () => {
  class RegisterCallDecoder extends TestDecoder {
    override decodeOut(instruction: TestInstruction): void {
      super.decodeOut(instruction);
      if (instruction.ip === 0x140001000n) {
        instruction.flowControl = fakeIced.FlowControl.IndirectCall;
        instruction.op0Kind = fakeIced.OpKind.Register;
        instruction.text = "call eax";
      }
    }
  }
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x15, 0xc3]), "entry.exe"), 0, 2),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0x140000000n,
      entrypointRva: 0x1000,
      rvaToOff: rva => rva - 0x1000,
      sections: [createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 })]
    },
    async () => ({ ...fakeIced, Decoder: RegisterCallDecoder })
  );
  assert.equal(result.blocks.length, 1);
  assert.deepEqual(result.blocks[0]?.instructions.map(instruction => instruction.text), [
    "call eax",
    "ret"
  ]);
  assert.deepEqual(result.blocks[0]?.instructions[0]?.notes, [
    "Unknown indirect call target; preview continues at fallthrough."
  ]);
  assert.ok(result.issues.some(issue => /continued after unknown indirect call/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly continues after unknown memory calls", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x15, 0xc3]),
    createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 })
  );
  assert.equal(result.blocks.length, 1);
  assert.deepEqual(result.blocks[0]?.instructions.map(instruction => instruction.text), [
    "call [iat]",
    "ret"
  ]);
  assert.deepEqual(result.blocks[0]?.instructions[0]?.notes, [
    "Unknown indirect call target; preview continues at fallthrough."
  ]);
});

void test("analyzePeEntrypointDisassembly continues after CFG guard pointer calls", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x15, 0xc3]),
    createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
    0x1000,
    {
      loadcfg: {
        GuardCFCheckFunctionPointer: 0x140002000n,
        GuardCFDispatchFunctionPointer: 0n
      } as never
    }
  );
  assert.equal(result.blocks.length, 1);
  assert.deepEqual(result.blocks[0]?.instructions.map(instruction => instruction.text), [
    "call [iat]",
    "ret"
  ]);
  assert.deepEqual(result.blocks[0]?.instructions[0]?.notes, [
    "CFG guard function pointer call is treated as returning."
  ]);
  assert.ok(result.issues.some(issue => /continued after CFG guard/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly follows returns from direct import thunks", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0xe8, 0xc3, 0x25]),
    createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 }),
    0x1000,
    {
      imports: {
        thunkEntrySize: 8,
        entries: [{
          dll: "KERNEL32.dll",
          originalFirstThunkRva: 0x3000,
          timeDateStamp: 0,
          forwarderChain: 0,
          firstThunkRva: 0x2000,
          lookupSource: "import-lookup-table",
          thunkTableTerminated: true,
          functions: [{ name: "GetSystemTimeAsFileTime" }]
        }]
      }
    }
  );
  const thunkTarget = result.blocks[1]?.instructions[0]?.target;
  assert.equal(result.blocks.length, 3);
  assert.equal(result.blocks[1]?.kind, "followed-call");
  assert.equal(result.blocks[1]?.startRva, 0x1002);
  assert.equal(result.blocks[2]?.kind, "followed-import-return");
  assert.equal(result.blocks[2]?.startRva, 0x1001);
  assert.equal(thunkTarget?.kind, "import");
  assert.equal(thunkTarget?.returnRva, 0x1001);
  assert.equal(thunkTarget?.returnFollowed, true);
  assert.deepEqual(result.blocks[2]?.instructions.map(instruction => instruction.text), ["ret"]);
});

void test(
  "analyzePeEntrypointDisassembly shows imports reached through direct thunks",
  async () => {
    const result = await analyzeEntrypoint(
      new Uint8Array([0xe8, 0x90, 0x25]),
      createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 }),
      0x1000,
      {
        imports: {
          thunkEntrySize: 8,
          entries: [{
            dll: "USER32.dll",
            originalFirstThunkRva: 0x3000,
            timeDateStamp: 0,
            forwarderChain: 0,
            firstThunkRva: 0x2000,
            lookupSource: "import-lookup-table",
            thunkTableTerminated: true,
            functions: [{ name: "MessageBoxW" }]
          }]
        },
        loadcfg: {
          tables: { guardIat: { entries: [{ index: 0, rva: 0x2000 }] } }
        } as never
      }
    );
    const thunkTarget = result.blocks[1]?.instructions[0]?.target;
    assert.equal(result.blocks[1]?.kind, "followed-call");
    assert.equal(thunkTarget?.kind, "import");
    assert.equal(thunkTarget?.label, "USER32.dll!MessageBoxW");
    assert.equal(thunkTarget?.guardIatEntry, true);
  }
);
