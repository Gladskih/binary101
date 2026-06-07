"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_SCN_CNT_CODE,
  TestDecoder,
  fakeIced,
  analyzeEntrypoint,
  createExecutableSection,
  type TestInstruction
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import type { PeEntrypointInstructionTarget } from "../../analyzers/pe/disassembly/index.js";
import { MockFile } from "../helpers/mock-file.js";

const assertBranchTarget = (
  target: PeEntrypointInstructionTarget | undefined
): Extract<PeEntrypointInstructionTarget, { kind: "branch" }> => {
  assert.equal(target?.kind, "branch");
  return target as Extract<PeEntrypointInstructionTarget, { kind: "branch" }>;
};

const assertKnownReturnTarget = (
  target: PeEntrypointInstructionTarget | undefined
): Extract<PeEntrypointInstructionTarget, { kind: "return"; rva: number }> => {
  assert.equal(target?.kind, "return");
  assert.ok(target && "rva" in target);
  return target;
};

void test(
  "analyzePeEntrypointDisassembly follows direct call targets as separate blocks",
  async () => {
    const result = await analyzeEntrypoint(
      new Uint8Array([0xe8, 0x90, 0xc3]),
      createExecutableSection({ virtualSize: 3, sizeOfRawData: 3 })
    );

    assert.equal(result.blocks.length, 3);
    assert.equal(result.blocks[0]?.kind, "entrypoint");
    assert.equal(result.blocks[1]?.kind, "followed-call");
    assert.equal(result.blocks[1]?.startRva, 0x1002);
    assert.equal(result.blocks[2]?.kind, "followed-return");
    assert.equal(result.blocks[2]?.startRva, 0x1001);
    assert.equal(result.blocks[0]?.instructions[0]?.target?.kind, "code");
    assert.equal(result.blocks[0]?.instructions[0]?.target?.followed, true);
    assert.equal(
      assertKnownReturnTarget(result.blocks[1]?.instructions[0]?.target).rva,
      0x1001
    );
    assert.deepEqual(result.blocks[1]?.instructions.map(instruction => instruction.text), ["ret"]);
    assert.deepEqual(result.blocks[2]?.instructions.map(instruction => instruction.text), [
      "op_90",
      "ret"
    ]);
  }
);

void test(
  "analyzePeEntrypointDisassembly refuses followed targets in non-executable sections",
  async () => {
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
      {
        sections: [
          createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
          dataSection
        ]
      }
    );

    assert.equal(result.blocks.length, 1);
    assert.equal(result.blocks[0]?.instructions[0]?.target?.kind, "code");
    assert.equal(result.blocks[0]?.instructions[0]?.target?.followed, false);
    assert.ok(result.issues.some(issue => /non-executable section/i.test(issue)));
  }
);

void test(
  "analyzePeEntrypointDisassembly follows conditional branch edges as separate blocks",
  async () => {
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
    assert.deepEqual(result.blocks[1]?.instructions.map(instruction => instruction.text), [
      "op_90",
      "ret"
    ]);
    assert.deepEqual(result.blocks[2]?.instructions.map(instruction => instruction.text), ["ret"]);
  }
);

void test("analyzePeEntrypointDisassembly guards repeated contexts at one RVA", async () => {
  class RecursiveCallDecoder extends TestDecoder {
    override decodeOut(instruction: TestInstruction): void {
      instruction.ip = this.ip;
      instruction.length = 1;
      instruction.nextIP = this.ip + 1n;
      instruction.code = 1;
      instruction.flowControl = fakeIced.FlowControl.Call;
      instruction.nearBranchTarget = this.ip;
      instruction.op0Kind = fakeIced.OpKind.NearBranch64;
      instruction.text = "call self";
      this.position += 1;
      this.ip = instruction.nextIP;
    }
  }
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0xe8]), "recursive.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0x140000000n,
      entrypointRva: 0x1000,
      rvaToOff: rva => rva - 0x1000,
      sections: [createExecutableSection({ virtualSize: 1, sizeOfRawData: 1 })]
    },
    async () => ({ ...fakeIced, Decoder: RecursiveCallDecoder })
  );
  const lastInstruction = result.blocks.at(-1)?.instructions.at(-1);

  assert.ok(result.blocks.length > 16);
  assert.equal(lastInstruction?.target?.kind, "code");
  assert.equal(lastInstruction?.target?.followed, false);
  assert.ok(result.issues.some(issue => /distinct emulation contexts/i.test(issue)));
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
    {
      sections: [
        createExecutableSection({ virtualSize: 2, sizeOfRawData: 2 }),
        dataSection
      ]
    }
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
