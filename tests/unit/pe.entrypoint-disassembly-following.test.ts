"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IMAGE_SCN_CNT_CODE,
  analyzeEntrypoint,
  createExecutableSection
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import type { PeEntrypointInstructionTarget } from "../../analyzers/pe/disassembly/index.js";

const assertBranchTarget = (
  target: PeEntrypointInstructionTarget | undefined
): Extract<PeEntrypointInstructionTarget, { kind: "branch" }> => {
  assert.equal(target?.kind, "branch");
  return target as Extract<PeEntrypointInstructionTarget, { kind: "branch" }>;
};

void test("analyzePeEntrypointDisassembly follows direct call targets as separate blocks", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0xe8, 0x90, 0xc3]),
    createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 })
  );

  assert.equal(result.blocks.length, 2);
  assert.equal(result.blocks[0]?.kind, "entrypoint");
  assert.equal(result.blocks[1]?.kind, "followed-call");
  assert.equal(result.blocks[1]?.startRva, 0x1002);
  assert.equal(result.blocks[0]?.instructions[0]?.target?.kind, "code");
  assert.equal(result.blocks[0]?.instructions[0]?.target?.followed, true);
  assert.deepEqual(result.blocks[1]?.instructions.map(instruction => instruction.text), ["ret"]);
});

void test("analyzePeEntrypointDisassembly refuses followed targets in non-executable sections", async () => {
  const dataSection = createExecutableSection({
    virtualAddress: 0x1002,
    virtualSize: 1,
    sizeOfRawData: 1,
    pointerToRawData: 2,
    characteristics: IMAGE_SCN_CNT_CODE
  });
  const result = await analyzeEntrypoint(
    new Uint8Array([0xe8, 0x90, 0xc3]),
    createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
    0x1000,
    { sections: [createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }), dataSection] }
  );

  assert.equal(result.blocks.length, 1);
  assert.equal(result.blocks[0]?.instructions[0]?.target?.kind, "code");
  assert.equal(result.blocks[0]?.instructions[0]?.target?.followed, false);
  assert.ok(result.issues.some(issue => /non-executable section/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly follows conditional branch edges as separate blocks", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x74, 0xc3, 0x90, 0xc3]),
    createExecutableSection({ virtualSize: 4, sizeOfRawData: 4 })
  );
  const branchTarget = assertBranchTarget(result.blocks[0]?.instructions[0]?.target);

  assert.equal(result.blocks.length, 3);
  assert.equal(result.blocks[1]?.kind, "followed-branch");
  assert.equal(result.blocks[1]?.startRva, 0x1002);
  assert.equal(result.blocks[2]?.kind, "followed-fallthrough");
  assert.equal(result.blocks[2]?.startRva, 0x1001);
  assert.equal(branchTarget.branchRva, 0x1002);
  assert.equal(branchTarget.branchFollowed, true);
  assert.equal(branchTarget.fallthroughRva, 0x1001);
  assert.equal(branchTarget.fallthroughFollowed, true);
  assert.deepEqual(result.blocks[1]?.instructions.map(instruction => instruction.text), ["op_90", "ret"]);
  assert.deepEqual(result.blocks[2]?.instructions.map(instruction => instruction.text), ["ret"]);
});

void test("analyzePeEntrypointDisassembly reports refused conditional branch edges", async () => {
  const dataSection = createExecutableSection({
    virtualAddress: 0x1002,
    virtualSize: 1,
    sizeOfRawData: 1,
    pointerToRawData: 2,
    characteristics: IMAGE_SCN_CNT_CODE
  });
  const result = await analyzeEntrypoint(
    new Uint8Array([0x74, 0xc3, 0xc3]),
    createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
    0x1000,
    { sections: [createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }), dataSection] }
  );
  const branchTarget = assertBranchTarget(result.blocks[0]?.instructions[0]?.target);

  assert.equal(result.blocks.length, 2);
  assert.equal(result.blocks[1]?.kind, "followed-fallthrough");
  assert.equal(result.blocks[1]?.startRva, 0x1001);
  assert.equal(branchTarget.branchRva, 0x1002);
  assert.equal(branchTarget.branchFollowed, false);
  assert.equal(branchTarget.fallthroughRva, 0x1001);
  assert.equal(branchTarget.fallthroughFollowed, true);
  assert.ok(result.issues.some(issue => /non-executable section/i.test(issue)));
});

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
  assert.deepEqual(result.blocks[0]?.instructions.map(instruction => instruction.text), ["call [iat]", "ret"]);
  assert.equal(target?.kind, "import");
  assert.equal(target?.label, "KERNEL32.dll!GetSystemTimeAsFileTime");
  assert.equal(target?.returnRva, 0x1001);
  assert.equal(target?.returnFollowed, true);
  assert.ok(result.issues.some(issue => /continued after returning import/i.test(issue)));
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

void test("analyzePeEntrypointDisassembly shows imports reached through direct thunks", async () => {
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
});
