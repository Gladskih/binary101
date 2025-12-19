"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { disassembleControlFlowForInstructionSetsVaddr } from "../../analyzers/x86/disassembly-control-flow-vaddr.js";

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
  features = new Int32Array();
  cpuidFeatures(): Int32Array {
    return this.features;
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

    instruction.ip = this.ip;
    instruction.length = byte === 0xee ? 0 : 1;
    instruction.nextIP = this.ip + 1n;
    instruction.op0Kind = 0;
    instruction.nearBranchTarget = 0n;

    let code = 1;
    let flowControl = 0;
    if (byte === 0) {
      code = -1;
    } else if (byte === 0x01) {
      code = -2;
      flowControl = 9;
    } else if (byte === 0x02) {
      code = 2;
      flowControl = 9;
    } else if (byte === 0xe9) {
      code = 3;
      flowControl = 1;
      instruction.op0Kind = 3;
      instruction.nearBranchTarget = 0x2000n;
    }

    instruction.code = code;
    instruction.flowControl = flowControl;
    (instruction as TestInstruction).features = new Int32Array([byte]);

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

void test("disassembleControlFlowForInstructionSetsVaddr caps repeated decode-stop issues", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();
  const data = new Uint8Array(1000).fill(0);
  const entrypoints = Array.from({ length: data.length }, (_, index) => 0x1000n + BigInt(index));

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [{ vaddrStart: 0x1000n, data }],
    entrypoints,
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.bytesDecoded, data.length);
  assert.equal(result.instructionCount, data.length);
  assert.equal(result.invalidInstructionCount, data.length);
  assert.equal(issues.length, 201);
  assert.match(issues.at(-1) ?? "", /omitted/i);
});

void test("disassembleControlFlowForInstructionSetsVaddr continues past UD2 trap instructions", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();
  const data = new Uint8Array([0x01, 0x90]);

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [{ vaddrStart: 0x1000n, data }],
    entrypoints: [0x1000n],
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, 2);
  assert.equal(result.invalidInstructionCount, 0);
  assert.equal(featureCounts.get(0x01), undefined);
  assert.equal(featureCounts.get(0x90), 1);
});

void test("disassembleControlFlowForInstructionSetsVaddr stops on exception flow-control (non-UD2)", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();
  const data = new Uint8Array([0x02, 0x90]);

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [{ vaddrStart: 0x1000n, data }],
    entrypoints: [0x1000n],
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, 1);
  assert.equal(result.invalidInstructionCount, 1);
  assert.ok(issues.some(issue => issue.includes("Stopping at an invalid instruction")));
});

void test("disassembleControlFlowForInstructionSetsVaddr queues unconditional branch targets in other sections", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [
      { vaddrStart: 0x1000n, data: new Uint8Array([0xe9]) },
      { vaddrStart: 0x2000n, data: new Uint8Array([0x90]) }
    ],
    entrypoints: [0x1000n],
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, 2);
  assert.equal(featureCounts.get(0xe9), 1);
  assert.equal(featureCounts.get(0x90), 1);
});

void test("disassembleControlFlowForInstructionSetsVaddr does not decode fallthrough across section boundaries", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [
      { vaddrStart: 0x1000n, data: new Uint8Array([0x90]) },
      { vaddrStart: 0x1001n, data: new Uint8Array([0x90]) }
    ],
    entrypoints: [0x1000n],
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, 1);
  assert.equal(featureCounts.get(0x90), 1);
});

void test("disassembleControlFlowForInstructionSetsVaddr reports zero-length instruction decodes", async () => {
  const issues: string[] = [];
  const featureCounts = new Map<number, number>();

  const result = await disassembleControlFlowForInstructionSetsVaddr({
    iced: fakeIced as unknown as Parameters<typeof disassembleControlFlowForInstructionSetsVaddr>[0]["iced"],
    bitness: 64,
    sections: [{ vaddrStart: 0x1000n, data: new Uint8Array([0xee]) }],
    entrypoints: [0x1000n],
    yieldEveryInstructions: 0,
    featureCounts,
    issues
  });

  assert.equal(result.instructionCount, 1);
  assert.equal(result.invalidInstructionCount, 1);
  assert.ok(issues.some(issue => issue.includes("zero-length instruction")));
});

