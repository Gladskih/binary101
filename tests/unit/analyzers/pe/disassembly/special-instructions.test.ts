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
    { categories: ["syscall"], instruction: "SYSCALL", count: 2, sampleRvas: [0, 2] },
    { categories: ["syscall"], instruction: "SYSENTER", count: 1, sampleRvas: [4] }
  ]);
});

for (const [address, expected] of [
  [0x140001000n, [0x1000]], [0x140000000n, [0]],
  [0x23fffffffn, [0xffffffff]], [0x13fffffffn, []], [0x240000000n, []]
] as const) {
  void test(`checks PE RVA boundaries for address ${address}`, () => {
    assert.ok(isIcedX86Module(iced));
    const collector = createPeSpecialInstructionCollector(iced, 0x140000000n);
    const instruction = iced.Instruction.create(iced.Code.Syscall);
    instruction.ip = address;
    collector.record(instruction);
    instruction.free();
    assert.equal(collector.findings()[0]?.count, 1);
    assert.deepEqual(collector.findings()[0]?.sampleRvas, expected);
  });
}
