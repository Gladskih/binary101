import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86-disasm";
import { Amd64PrologMachine } from "../../../../../../analyzers/pe/exception/amd64/prolog-machine.js";

const run = (bytes: number[], inspect: (machine: Amd64PrologMachine) => void): void => {
  const factory = new iced.InstructionInfoFactory();
  const decoder = new iced.Decoder(64, Uint8Array.from(bytes), iced.DecoderOptions.None);
  const instruction = new iced.Instruction();
  const machine = new Amd64PrologMachine(iced, factory);
  try {
    while (decoder.canDecode) { decoder.decodeOut(instruction); machine.step(instruction); }
    inspect(machine);
  } finally { instruction.free(); decoder.free(); factory.free(); }
};

void test("tracks original register aliases and signed affine stack addresses", () => {
  run([0x48, 0x89, 0xd8, 0x48, 0x8d, 0x6c, 0x24, 0xf0], machine => {
    assert.deepEqual(machine.value(iced.Register.RAX), { kind: "original", register: iced.Register.RBX });
    assert.deepEqual(machine.value(iced.Register.RBP), { kind: "stack", offset: -16n });
  });
});

void test("invalidates partial and implicit writes", () => {
  run([0x48, 0x89, 0xd8, 0x66, 0xb8, 0x34, 0x12, 0x0f, 0xa2], machine => {
    assert.equal(machine.value(iced.Register.RAX), undefined);
    assert.equal(machine.value(iced.Register.RBX), undefined);
  });
});

void test("zero extends 32-bit constants and tracks add/sub in temporary registers", () => {
  run([0xb8, 0xff, 0xff, 0xff, 0xff, 0x48, 0x83, 0xc0, 8, 0x48, 0x83, 0xe8, 3], machine => {
    assert.deepEqual(machine.value(iced.Register.RAX), { kind: "constant", offset: 0x100000004n });
  });
});

void test("does not retain an original register after unknown arithmetic or a memory load", () => {
  run([0x48, 0x83, 0xc3, 8, 0x48, 0x8b, 0x04, 0x24], machine => {
    assert.equal(machine.value(iced.Register.RBX), undefined);
    assert.equal(machine.value(iced.Register.RAX), undefined);
  });
});

void test("does not invent stack addresses for indexed or 32-bit addressing", () => {
  run([0x48, 0x8d, 0x04, 0x0c, 0x67, 0x48, 0x8d, 0x2c, 0x24], machine => {
    assert.equal(machine.value(iced.Register.RAX), undefined);
    assert.equal(machine.value(iced.Register.RBP), undefined);
  });
});

void test("invalidates overlapping stack writes", () => {
  run([0x48, 0x89, 0x5c, 0x24, 8, 0x48, 0x83, 0x64, 0x24, 8, 0], machine => {
    assert.equal(machine.memory.get(8n)?.value, undefined);
  });
});

void test("marks unknown-address stores as potentially aliasing saved stack slots", () => {
  run([0x48, 0x89, 0x18], machine => {
    assert.equal(machine.uncertainMemory, true);
    assert.equal(machine.memory.size, 0);
  });
});

void test("does not equate a GS-relative store with a stack-relative save", () => {
  run([0x65, 0x48, 0x89, 0x5c, 0x24, 8], machine => {
    assert.equal(machine.memory.size, 0);
    assert.equal(machine.uncertainMemory, true);
  });
});

void test("preserves low XMM lanes across VZEROUPPER", () => {
  run([0xc5, 0xf8, 0x77], machine => {
    assert.deepEqual(machine.value(iced.Register.XMM6),
      { kind: "original", register: iced.Register.ZMM6 });
  });
});

void test("does not manufacture stack provenance after alignment and a call", () => {
  run([0x48, 0x83, 0xe4, 0xe0, 0xe8, 0, 0, 0, 0], machine => {
    assert.equal(machine.value(iced.Register.RSP), undefined);
    assert.equal(machine.value(iced.Register.RAX), undefined);
  });
});

void test("invalidates implicit and repeated memory writes", () => {
  run([0x48, 0x89, 0x1c, 0x24, 0x48, 0x89, 0xe7, 0xf3, 0x48, 0xab], machine => {
    assert.notDeepEqual(machine.memory.get(0n)?.value,
      { kind: "original", register: iced.Register.RBX });
    assert.equal(machine.uncertainMemory, true);
  });
});

void test("does not invalidate adjacent nonoverlapping saved slots", () => {
  run([], machine => {
    machine.write(0n, 8, { kind: "original", register: iced.Register.RBX });
    machine.write(16n, 8, { kind: "original", register: iced.Register.RBP });
    machine.write(8n, 8, { kind: "constant", offset: 0n });
    assert.deepEqual(machine.memory.get(0n)?.value, { kind: "original", register: iced.Register.RBX });
    assert.deepEqual(machine.memory.get(16n)?.value, { kind: "original", register: iced.Register.RBP });
    machine.write(4n, 4, undefined);
    assert.equal(machine.memory.has(0n), false);
    assert.equal(machine.memory.has(16n), true);
  });
});

void test("invalidates call-clobbered vectors and the ABI home area", () => {
  run([0x48, 0x89, 0x5c, 0x24, 8, 0xe8, 0, 0, 0, 0], machine => {
    assert.equal(machine.value(iced.Register.XMM5), undefined);
    assert.deepEqual(machine.value(iced.Register.XMM6), { kind: "original", register: iced.Register.ZMM6 });
    assert.equal(machine.memory.get(8n), undefined);
    assert.deepEqual(machine.memory.get(-8n), { size: 40, value: undefined });
  });
});

void test("does not claim that an EVEX masked store saves every XMM lane", () => {
  // Independently assembled with LLVM MC: VMOVDQA32 [RSP+16]{K1}, XMM6.
  run([0x62, 0xf1, 0x7d, 0x09, 0x7f, 0x74, 0x24, 0x01], machine => {
    assert.equal(machine.memory.get(16n)?.value, undefined);
  });
});
