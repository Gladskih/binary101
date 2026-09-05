import assert from "node:assert/strict";
import { test } from "node:test";
import * as iced from "iced-x86";
import { isIcedX86Module } from "../../../../../analyzers/x86/disassembly-iced.js";
import { createPeSpecialInstructionCollector } from
  "../../../../../analyzers/pe/disassembly/special-instructions.js";

// Encodings: Intel SDM Vol. 2 instruction reference.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const collect = (bytes: number[], bitness = 64) => {
  assert.ok(isIcedX86Module(iced));
  const collector = createPeSpecialInstructionCollector(iced);
  const decoder = new iced.Decoder(bitness, Uint8Array.from(bytes), iced.DecoderOptions.None);
  while (decoder.canDecode) {
    const instruction = decoder.decode();
    collector.record(instruction);
    instruction.free();
  }
  decoder.free();
  return collector.findings();
};

void test("collects syscall sites, not syscall numbers or ordinary calls", () => {
  assert.deepEqual(collect([0x0f, 0x05, 0x0f, 0x05, 0x0f, 0x34, 0xe8, 0, 0, 0, 0]), [
    { category: "syscall", instruction: "SYSCALL", count: 2 },
    { category: "syscall", instruction: "SYSENTER", count: 1 }
  ]);
});

void test("distinguishes the Windows interrupt gateway from other software interrupts", () => {
  assert.deepEqual(collect([0xcd, 0x2e, 0xcd, 0x80, 0xcc, 0x0f, 0x0b], 32), [
    { category: "syscall", instruction: "INT 0x2E", count: 1 },
    { category: "trap", instruction: "INT 0x80", count: 1 },
    { category: "trap", instruction: "INT3", count: 1 },
    { category: "trap", instruction: "UD2", count: 1 }
  ]);
});

void test("separates kernel privilege from IOPL restrictions and ordinary timing instructions", () => {
  assert.deepEqual(collect([0x0f, 0x32, 0xfa, 0xe4, 0x80, 0x0f, 0x31, 0x90]), [
    { category: "privileged", instruction: "RDMSR", count: 1 },
    { category: "io-privilege", instruction: "CLI", count: 1 },
    { category: "io-privilege", instruction: "IN", count: 1 }
  ]);
});


void test("ignores empty, truncated and invalid instructions", () => {
  assert.deepEqual(collect([]), []);
  assert.deepEqual(collect([0x0f]), []);
  assert.deepEqual(collect([0xf0, 0x0f, 0x05]), []);
});

// Intel SDM Vol. 2: each I/O width and each explicit trap must retain its category.
for (const [name, bytes] of [
  ["STI", [0xfb]], ["INSB", [0x6c]], ["INSW", [0x66, 0x6d]], ["INSD", [0x6d]],
  ["OUT", [0xe6, 0x80]], ["OUTSB", [0x6e]], ["OUTSW", [0x66, 0x6f]], ["OUTSD", [0x6f]]
] as const) {
  void test(`classifies ${name} as conditional I/O privilege`, () => {
    assert.deepEqual(collect([...bytes], 32), [
      { category: "io-privilege", instruction: name, count: 1 }
    ]);
  });
}

for (const [name, bytes] of [
  ["INT1", [0xf1]], ["INTO", [0xce]],
  ["UD0", [0x0f, 0xff, 0xc0]], ["UD1", [0x0f, 0xb9, 0xc0]]
] as const) {
  void test(`classifies ${name} as an explicit trap`, () => {
    assert.deepEqual(collect([...bytes], 32), [{ category: "trap", instruction: name, count: 1 }]);
  });
}

void test("tolerates missing mnemonic metadata", () => {
  assert.ok(isIcedX86Module(iced));
  const collector = createPeSpecialInstructionCollector({ ...iced, Mnemonic: {} });
  const instruction = iced.Instruction.create(iced.Code.Syscall);
  collector.record(instruction);
  instruction.free();
  assert.deepEqual(collector.findings(), []);
});
