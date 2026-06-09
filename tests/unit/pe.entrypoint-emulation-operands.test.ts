"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";
import { resolveRegister } from "../../analyzers/pe/disassembly/entrypoint/emulation-registers.js";
import {
  isSameRegisterOperand,
  operandBits,
  readOperand,
  resolveMemoryAddress,
  resolveStackPointer,
  writeOperand
} from "../../analyzers/pe/disassembly/entrypoint/emulation-operands.js";
import {
  createEmulationState,
  known,
  readRegister,
  writeRegister
} from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";

const icedModule = iced as unknown as IcedModule;

const decodeOne = (bytes: number[], bitness = 64): iced.Instruction => {
  const decoder = new iced.Decoder(bitness, new Uint8Array(bytes), iced.DecoderOptions.None);
  const instruction = new iced.Instruction();
  decoder.decodeOut(instruction);
  decoder.free();
  return instruction;
};

void test("isSameRegisterOperand compares decoded register operands", () => {
  const same = decodeOne([0x31, 0xc0]);
  const different = decodeOne([0x31, 0xc8]);
  const immediate = decodeOne([0xb8, 0x01, 0x00, 0x00, 0x00]);
  try {
    assert.equal(isSameRegisterOperand(icedModule, same), true);
    assert.equal(isSameRegisterOperand(icedModule, different), false);
    assert.equal(isSameRegisterOperand(icedModule, immediate), false);
  } finally {
    same.free();
    different.free();
    immediate.free();
  }
});

void test("resolveMemoryAddress rejects unsupported memory base registers", () => {
  const state = createEmulationState(64);
  const instruction = decodeOne([0x48, 0x8b, 0x05, 0x00, 0x00, 0x00, 0x00]);
  try {
    assert.equal(resolveMemoryAddress(icedModule, state, instruction), null);
  } finally {
    instruction.free();
  }
});

void test("readOperand and writeOperand use concrete stack addresses", () => {
  const state = createEmulationState(64);
  const store = decodeOne([0x48, 0x89, 0x44, 0x24, 0x08]);
  const load = decodeOne([0x48, 0x8b, 0x5c, 0x24, 0x08]);
  try {
    writeRegister(state, resolveRegister(icedModule, iced.Register.RAX), known(9n, 64));
    writeOperand(icedModule, state, store, 0, readOperand(icedModule, state, store, 1));

    writeOperand(icedModule, state, load, 0, readOperand(icedModule, state, load, 1));

    assert.deepEqual(readRegister(state, resolveRegister(icedModule, iced.Register.RBX)), {
      kind: "known",
      value: 9n,
      bits: 64
    });
  } finally {
    store.free();
    load.free();
  }
});

void test("resolveMemoryAddress uses base, index, scale, and displacement", () => {
  const state = createEmulationState(64);
  const instruction = decodeOne([0x48, 0x8b, 0x44, 0x8b, 0x10]);
  try {
    writeRegister(state, resolveRegister(icedModule, iced.Register.RBX), known(0x1000n, 64));
    writeRegister(state, resolveRegister(icedModule, iced.Register.RCX), known(3n, 64));

    assert.equal(resolveMemoryAddress(icedModule, state, instruction), 0x101cn);
  } finally {
    instruction.free();
  }
});

void test("readOperand resolves 32-bit negative frame displacements", () => {
  const state = createEmulationState(32);
  // Intel SDM Vol. 2 PUSH: FF /6 with disp8 F8 encodes PUSH r/m32 [EBP-8].
  const instruction = decodeOne([0xff, 0x75, 0xf8], 32);
  try {
    writeRegister(state, resolveRegister(icedModule, iced.Register.EBP), known(0x1000n, 32));
    state.memory.set(0x0ff8n.toString(), known(0x40100cn, 32));

    assert.equal(resolveMemoryAddress(icedModule, state, instruction), 0x0ff8n);
    assert.deepEqual(readOperand(icedModule, state, instruction, 0), {
      kind: "known",
      value: 0x40100cn,
      bits: 32
    });
  } finally {
    instruction.free();
  }
});

void test("readOperand selects the requested immediate operand", () => {
  const state = createEmulationState(64);
  const instruction = decodeOne([0xc8, 0x34, 0x12, 0x56]);
  try {
    assert.deepEqual(readOperand(icedModule, state, instruction, 1), {
      kind: "known",
      value: 0x56n,
      bits: 64
    });
  } finally {
    instruction.free();
  }
});

void test("operandBits reports register and memory operand widths", () => {
  const register = decodeOne([0x0f, 0xb6, 0xc0]);
  const memory = decodeOne([0x8b, 0x04, 0x24]);
  try {
    assert.equal(operandBits(icedModule, register, 0), 32);
    assert.equal(operandBits(icedModule, register, 1), 8);
    assert.equal(operandBits(icedModule, memory, 1), 32);
  } finally {
    register.free();
    memory.free();
  }
});

void test("readOperand and writeOperand tolerate out-of-range operand indexes", () => {
  const state = createEmulationState(64);
  const instruction = decodeOne([0x90]);
  try {
    assert.deepEqual(readOperand(icedModule, state, instruction, 0), { kind: "unknown" });
    writeOperand(icedModule, state, instruction, 0, known(1n, 64));
    assert.equal(state.registers.size, 1);
  } finally {
    instruction.free();
  }
});

void test("readOperand coerces memory reads to the instruction memory width", () => {
  const state = createEmulationState(64);
  const instruction = decodeOne([0x8b, 0x04, 0x24]);
  try {
    state.memory.set(0x100000000000n.toString(), known(0x1122_3344_5566_7788n, 64));

    assert.deepEqual(readOperand(icedModule, state, instruction, 1), {
      kind: "known",
      value: 0x5566_7788n,
      bits: 32
    });
  } finally {
    instruction.free();
  }
});

void test("resolveStackPointer returns the bitness-specific stack alias", () => {
  assert.deepEqual(resolveStackPointer(icedModule, createEmulationState(64)), {
    canonical: "RSP",
    accessBits: 64,
    bitOffset: 0
  });
  assert.deepEqual(resolveStackPointer(icedModule, createEmulationState(32)), {
    canonical: "RSP",
    accessBits: 32,
    bitOffset: 0
  });
});
