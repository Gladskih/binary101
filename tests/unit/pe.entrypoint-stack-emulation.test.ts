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

void test("emulateInstruction uses operand-size width for 16-bit push", () => {
  const state = emulateBytesWithState([
    0x48, 0xc7, 0xc0, 0x22, 0x11, 0x00, 0x00,
    0x66, 0x50
  ]);

  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0xffffffffffen,
    bits: 64
  });
  assert.deepEqual(state.memory.get(0xffffffffffen.toString()), {
    kind: "known",
    value: 0x1122n,
    bits: 16
  });
});

void test("emulateInstruction models enter nesting zero and leave", () => {
  const state = emulateBytesWithState([
    0xc8, 0x20, 0x00, 0x00,
    0xc9
  ]);

  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x100000000000n,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RBP"), { kind: "unknown" });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction pushad stores the original ESP slot", () => {
  const state = emulateBytesWithState([0x60], 32);

  assert.deepEqual(state.memory.get(0x0fffffecn.toString()), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x0fffffe0n,
    bits: 32
  });
});

void test("emulateInstruction popad restores saved general registers", () => {
  const state = emulateBytesWithState([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xb9, 0x02, 0x00, 0x00, 0x00,
    0xba, 0x03, 0x00, 0x00, 0x00,
    0xbb, 0x04, 0x00, 0x00, 0x00,
    0xbd, 0x05, 0x00, 0x00, 0x00,
    0xbe, 0x06, 0x00, 0x00, 0x00,
    0xbf, 0x07, 0x00, 0x00, 0x00,
    0x60,
    0x61
  ], 32);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 1n, bits: 32 });
  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 4n, bits: 32 });
  assert.deepEqual(state.registers.get("RDI"), { kind: "known", value: 7n, bits: 32 });
  assert.deepEqual(state.registers.get("RSP"), {
    kind: "known",
    value: 0x10000000n,
    bits: 32
  });
  assert.equal(state.memory.size, 0);
});

void test("emulateInstruction marks nested enter frames unknown", () => {
  const state = emulateBytesWithState([0xc8, 0x00, 0x00, 0x01]);

  assert.deepEqual(state.registers.get("RSP"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RBP"), { kind: "unknown" });
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
