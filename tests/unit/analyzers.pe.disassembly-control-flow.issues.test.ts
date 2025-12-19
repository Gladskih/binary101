"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { disassembleControlFlowForInstructionSets } from "../../analyzers/x86/disassembly-control-flow.js";

type FakeInstruction = {
  code: number;
  length: number;
  ip: bigint;
  nextIP: bigint;
  flowControl: number;
  nearBranchTarget: bigint;
  op0Kind: number;
  cpuidFeatures(): Int32Array;
  free(): void;
};

type FakeDecoder = {
  ip: bigint;
  position: number;
  readonly canDecode: boolean;
  decodeOut(instruction: FakeInstruction): void;
  free(): void;
};

type FakeIced = {
  Code: Record<string, number> & Record<number, string | undefined>;
  Decoder: new (bitness: number, data: Uint8Array, options: number) => FakeDecoder;
  DecoderOptions: { None: number };
  FlowControl: Record<string, number> & Record<number, string | undefined>;
  OpKind: Record<string, number> & Record<number, string | undefined>;
  Instruction: new () => FakeInstruction;
};

class TestInstruction implements FakeInstruction {
  code = 0;
  length = 0;
  ip = 0n;
  nextIP = 0n;
  flowControl = 0;
  nearBranchTarget = 0n;
  op0Kind = 0;
  cpuidFeatures(): Int32Array {
    return new Int32Array();
  }
  free(): void {}
}

class TestDecoder implements FakeDecoder {
  readonly bitness: number;
  readonly data: Uint8Array;
  ip: bigint;
  position: number;

  constructor(bitness: number, data: Uint8Array) {
    this.bitness = bitness;
    this.data = data;
    this.ip = 0n;
    this.position = 0;
  }

  get canDecode(): boolean {
    return this.position >= 0 && this.position < this.data.length;
  }

  decodeOut(instruction: FakeInstruction): void {
    const byte = this.data[this.position] ?? 0;
    const isInvalid = byte === 0;

    instruction.ip = this.ip;
    instruction.length = 1;
    instruction.nextIP = this.ip + 1n;
    instruction.code = isInvalid ? -1 : 1;
    instruction.flowControl = 0;
    instruction.op0Kind = 0;
    instruction.nearBranchTarget = 0n;

    this.ip = instruction.nextIP;
    this.position += 1;
  }

  free(): void {}
}

const fakeIced: FakeIced = {
  Code: { INVALID: -1, Ud2: -2 },
  Decoder: TestDecoder as unknown as FakeIced["Decoder"],
  DecoderOptions: { None: 0 },
  FlowControl: {
    Exception: 9,
    UnconditionalBranch: 1,
    ConditionalBranch: 2,
    Call: 3,
    XbeginXabortXend: 4,
    IndirectBranch: 5,
    Return: 6,
    Interrupt: 7
  },
  OpKind: { NearBranch16: 1, NearBranch32: 2, NearBranch64: 3 },
  Instruction: TestInstruction as unknown as FakeIced["Instruction"]
};

void test("disassembleControlFlowForInstructionSets caps repeated decode-stop issues", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();
  const data = new Uint8Array(1000).fill(0);
  const entrypoints = Array.from({ length: data.length }, (_, index) => 0x1000 + index);

  const result = await disassembleControlFlowForInstructionSets({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSets>[0]["iced"],
    bitness: 64,
    imageBase: 0n,
    sections: [{ rvaStart: 0x1000, data }],
    entrypoints,
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, data.length);
  assert.equal(result.invalidInstructionCount, data.length);
  assert.equal(issues.length, 201);
  assert.match(issues.at(-1) ?? "", /omitted/i);
});
