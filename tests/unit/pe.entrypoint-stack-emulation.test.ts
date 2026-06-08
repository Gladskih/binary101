"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import {
  createEmulationState,
  emulateInstruction,
  type EmulationState
} from "../../analyzers/pe/disassembly/entrypoint/emulation.js";
import type { IcedModule } from "../../analyzers/pe/disassembly/entrypoint/iced.js";

const icedModule = iced as unknown as IcedModule;

const emulateBytesWithState = (
  bytes: number[],
  bitness: 32 | 64 = 64
): EmulationState => {
  const decoder = new iced.Decoder(bitness, new Uint8Array(bytes), iced.DecoderOptions.None);
  const state = createEmulationState(bitness);
  try {
    while (decoder.canDecode) {
      const decoded = new iced.Instruction();
      try {
        decoder.decodeOut(decoded);
        emulateInstruction(icedModule, decoded, { rva: 0, fileOffset: 0, text: "" }, state);
      } finally {
        decoded.free();
      }
    }
    return state;
  } finally {
    decoder.free();
  }
};

void test("emulateInstruction models basic stack push and pop", () => {
  const state = emulateBytesWithState([
    0x48, 0xbb, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x53,
    0x58
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x1122334455667788n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction lets pushed 64-bit flags expose the saved return slot", () => {
  const state = emulateBytesWithState([
    // Seed a call-like saved return VA on the synthetic stack, then rewrite it
    // below PUSHFQ's 8-byte flags slot before POPFQ restores the stack.
    0x48, 0xb8, 0x05, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
    0x50,
    0x9c,
    0x48, 0x83, 0x44, 0x24, 0x08, 0x0c,
    0x9d,
    0x5b
  ]);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x140001011n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction lets pushed 32-bit flags expose the saved return slot", () => {
  const state = emulateBytesWithState([
    // PUSHFD reserves a 4-byte flags slot, so the saved return is at [esp+4].
    0xb8, 0x05, 0x10, 0x40, 0x00,
    0x50,
    0x9c,
    0x83, 0x44, 0x24, 0x04, 0x05,
    0x9d,
    0x5b
  ], 32);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x40100an,
    bits: 32
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction models operand-size 16-bit flag pushes", () => {
  const state = emulateBytesWithState([
    // 66 PUSHF reserves a 2-byte flags slot in 64-bit code.
    0x48, 0xb8, 0x05, 0x10, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00,
    0x50,
    0x66, 0x9c,
    0x48, 0x83, 0x44, 0x24, 0x02, 0x0c,
    0x66, 0x9d,
    0x5b
  ]);

  assert.deepEqual(state.registers.get("RBX"), {
    kind: "known",
    value: 0x140001011n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.equal(state.memory.size, 0);
});
