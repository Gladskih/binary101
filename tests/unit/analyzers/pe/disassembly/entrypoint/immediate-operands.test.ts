"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { collectImmediateOperands } from "../../../../../../analyzers/pe/disassembly/entrypoint/immediate-operands.js";
import type {
  IcedInstructionObject,
  IcedModule,
} from "../../../../../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;

const instructionWithKinds = (
  kinds: number[],
  values: bigint[]
): IcedInstructionObject => ({
  opCount: kinds.length,
  opKind: (operand: number) => {
    if (operand >= kinds.length) throw new Error("out of range");
    return kinds[operand] ?? iced.OpKind.Register;
  },
  immediate: (operand: number) => {
    const value = values[operand];
    if (value == null) throw new Error("missing immediate");
    return value;
  }
} as unknown as IcedInstructionObject);

void test("collectImmediateOperands returns immediate values with operand indexes", () => {
  const decoder = new iced.Decoder(
    32,
    new Uint8Array([0xb8, 0x4e, 0xe6, 0x40, 0xbb]),
    iced.DecoderOptions.None
  );
  const instruction = new iced.Instruction();
  try {
    decoder.decodeOut(instruction);
    assert.deepEqual(collectImmediateOperands(icedModule, instruction), [{
      operand: 1,
      value: 0xbb40e64en
    }]);
  } finally {
    instruction.free();
    decoder.free();
  }
});

void test("collectImmediateOperands returns all iced immediate operand kinds", () => {
  assert.deepEqual(
    collectImmediateOperands(icedModule, instructionWithKinds([
      iced.OpKind.Immediate8,
      iced.OpKind.Immediate8_2nd,
      iced.OpKind.Immediate16,
      iced.OpKind.Immediate32,
      iced.OpKind.Immediate64,
      iced.OpKind.Immediate8to16,
      iced.OpKind.Immediate8to32,
      iced.OpKind.Immediate8to64,
      iced.OpKind.Immediate32to64
    ], [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n])),
    [
      { operand: 0, value: 1n },
      { operand: 1, value: 2n },
      { operand: 2, value: 3n },
      { operand: 3, value: 4n },
      { operand: 4, value: 5n },
      { operand: 5, value: 6n },
      { operand: 6, value: 7n },
      { operand: 7, value: 8n },
      { operand: 8, value: 9n }
    ]
  );
});

void test("collectImmediateOperands ignores non-immediate operands without over-reading", () => {
  assert.deepEqual(
    collectImmediateOperands(
      icedModule,
      instructionWithKinds([iced.OpKind.Register, iced.OpKind.Immediate32], [99n, 7n])
    ),
    [{ operand: 1, value: 7n }]
  );
});

void test("collectImmediateOperands ignores immediate accessor failures", () => {
  assert.deepEqual(
    collectImmediateOperands(icedModule, {
      opCount: 1,
      opKind: () => iced.OpKind.Immediate32,
      immediate: () => {
        throw new Error("bad operand");
      }
    } as unknown as IcedInstructionObject),
    []
  );
});
