import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { getX86DirectMemoryBranch } from "../../../../analyzers/x86/direct-memory-reference.js";

const reference = (bytes: number[], bitness: 32 | 64 = 64) => {
  const decoder = new iced.Decoder(bitness, Uint8Array.from(bytes), iced.DecoderOptions.None);
  decoder.ip = 0x1000n;
  const instruction = decoder.decode();
  const result = getX86DirectMemoryBranch(iced, instruction);
  instruction.free();
  decoder.free();
  return result;
};

void test("resolves RIP-relative and absolute slot calls and jumps", () => {
  // Intel SDM Vol. 2: CALL/JMP r/m and effective address calculation.
  assert.deepEqual(reference([0xff, 0x15, 0xfa, 0x0f, 0, 0]), { kind: "call", address: 0x2000n });
  assert.deepEqual(reference([0xff, 0x25, 0xfa, 0x0f, 0, 0]), { kind: "jump", address: 0x2000n });
  assert.deepEqual(reference([0xff, 0x15, 0, 0x20, 0, 0], 32), { kind: "call", address: 0x2000n });
});

void test("rejects FS/GS, indexed/register targets and ordinary instructions", () => {
  assert.equal(reference([0x64, 0xff, 0x15, 0xf9, 0x0f, 0, 0]), null);
  assert.equal(reference([0x65, 0xff, 0x25, 0xf9, 0x0f, 0, 0]), null);
  assert.equal(reference([0xff, 0x14, 0xc5, 0, 0x20, 0, 0]), null);
  assert.equal(reference([0xff, 0xd0]), null);
  assert.equal(reference([0x90]), null);
});
