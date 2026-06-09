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
import { collectKnownValues } from "../../analyzers/pe/disassembly/entrypoint/emulation-state.js";

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

void test("emulateInstruction models sign and zero extension moves", () => {
  const state = emulateBytesWithState([
    0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,
    0x0f, 0xb6, 0xc0,
    0x0f, 0xbe, 0xc8
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 0xffn, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 0xffff_ffffn, bits: 64 });
});

void test("emulateInstruction models unary arithmetic and shifts", () => {
  const state = emulateBytesWithState([
    0xb8, 0x00, 0x00, 0x00, 0x80,
    0xd1, 0xf8,
    0xff, 0xc0,
    0xf7, 0xd8
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x3fff_ffffn,
    bits: 64
  });
});

void test("emulateInstruction masks 64-bit variable shift counts", () => {
  const state = emulateBytesWithState([
    0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,
    0x31, 0xc9,
    0xb1, 0x20,
    0x48, 0xd3, 0xe0
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x1_0000_0000n,
    bits: 64
  });
});

void test("emulateInstruction models logical shifts and rotates", () => {
  const state = emulateBytesWithState([
    0xb8, 0x00, 0x00, 0x00, 0x80,
    0xd1, 0xe8,
    0xb8, 0x01, 0x00, 0x00, 0x80,
    0xd1, 0xc0,
    0xd1, 0xc8
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x8000_0001n,
    bits: 64
  });
});

void test("emulateInstruction marks carry rotates unknown when count is nonzero", () => {
  const state = emulateBytesWithState([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xd1, 0xd0
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "unknown" });
});

void test("emulateInstruction models double-precision shifts", () => {
  const state = emulateBytesWithState([
    0xb8, 0x78, 0x56, 0x34, 0x12,
    0xb9, 0x00, 0x00, 0x00, 0xf0,
    0x0f, 0xa4, 0xc8, 0x04
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0x2345_678fn,
    bits: 64
  });
});

void test("emulateInstruction joins conditional move outcomes when flags are unknown", () => {
  const state = emulateBytesWithState([
    0xb8, 0x01, 0x00, 0x00, 0x00,
    0xb9, 0x02, 0x00, 0x00, 0x00,
    0x0f, 0x45, 0xc1
  ]);

  assert.deepEqual(
    collectKnownValues(state.registers.get("RAX")).map(value => value.value),
    [1n, 2n]
  );
});

void test("emulateInstruction stores setcc as boolean alternatives", () => {
  const state = emulateBytesWithState([0x0f, 0x95, 0x04, 0x24]);

  assert.deepEqual(
    collectKnownValues(state.memory.get(0x100000000000n.toString())).map(value => value.value),
    [0n, 1n]
  );
});

void test("emulateInstruction models xchg, xadd, and cmpxchg register effects", () => {
  const state = emulateBytesWithState([
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xb9, 0x04, 0x00, 0x00, 0x00,
    0x87, 0xc8,
    0x0f, 0xc1, 0xc8,
    0xba, 0x09, 0x00, 0x00, 0x00,
    0x0f, 0xb1, 0xca
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 9n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 9n, bits: 64 });
});

void test("emulateInstruction models accumulator sign-extension instructions", () => {
  const state = emulateBytesWithState([
    0x31, 0xc0,
    0xb0, 0xff,
    0x66, 0x98,
    0x98,
    0x99
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 64
  });
  assert.deepEqual(state.registers.get("RDX"), {
    kind: "known",
    value: 0xffff_ffffn,
    bits: 64
  });
});

void test("emulateInstruction models multiply and bit count instructions", () => {
  const state = emulateBytesWithState([
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0xb9, 0x04, 0x00, 0x00, 0x00,
    0xf7, 0xe1,
    0xf3, 0x0f, 0xb8, 0xc8
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "known", value: 12n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 0n, bits: 64 });
  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 2n, bits: 64 });
});

void test("emulateInstruction models signed imul low-result forms", () => {
  const state = emulateBytesWithState([
    0xb8, 0x03, 0x00, 0x00, 0x00,
    0x6b, 0xc0, 0xfe
  ]);

  assert.deepEqual(state.registers.get("RAX"), {
    kind: "known",
    value: 0xffff_fffan,
    bits: 64
  });
});

void test("emulateInstruction invalidates accumulator registers for div", () => {
  const state = emulateBytesWithState([
    0x31, 0xd2,
    0xb8, 0x0a, 0x00, 0x00, 0x00,
    0xb9, 0x02, 0x00, 0x00, 0x00,
    0xf7, 0xf1
  ]);

  assert.deepEqual(state.registers.get("RAX"), { kind: "unknown" });
  assert.deepEqual(state.registers.get("RDX"), { kind: "unknown" });
});

void test("emulateInstruction models bit scan and zero-count instructions", () => {
  const state = emulateBytesWithState([
    0xb8, 0x10, 0x00, 0x00, 0x00,
    0x0f, 0xbc, 0xc8,
    0x0f, 0xbd, 0xd0,
    0xf3, 0x0f, 0xbd, 0xd8,
    0xf3, 0x0f, 0xbc, 0xf0
  ]);

  assert.deepEqual(state.registers.get("RCX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RDX"), { kind: "known", value: 4n, bits: 64 });
  assert.deepEqual(state.registers.get("RBX"), { kind: "known", value: 27n, bits: 64 });
  assert.deepEqual(state.registers.get("RSI"), { kind: "known", value: 4n, bits: 64 });
});
