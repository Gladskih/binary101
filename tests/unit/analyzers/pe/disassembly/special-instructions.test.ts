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

void test("distinguishes the Windows interrupt gateway from other software interrupts", () => {
  assert.deepEqual(collect([0xcd, 0x2e, 0xcd, 0x80, 0xcc, 0x0f, 0x0b], 32), [
    { categories: ["syscall"], instruction: "INT 0x2E", count: 1, sampleRvas: [0] },
    { categories: ["trap"], instruction: "INT 0x80", count: 1, sampleRvas: [2] },
    { categories: ["trap"], instruction: "INT3", count: 1, sampleRvas: [4] },
    { categories: ["trap"], instruction: "UD2", count: 1, sampleRvas: [5] }
  ]);
});

void test("separates kernel privilege from IOPL restrictions and ordinary timing instructions", () => {
  assert.deepEqual(collect([0x0f, 0x32, 0xfa, 0xe4, 0x80, 0x0f, 0x31, 0x90]), [
    { categories: ["system-state", "privileged"], instruction: "RDMSR", count: 1, sampleRvas: [0] },
    { categories: ["io-privilege"], instruction: "CLI", count: 1, sampleRvas: [2] },
    { categories: ["io-privilege"], instruction: "IN", count: 1, sampleRvas: [3] },
    { categories: ["timing"], instruction: "RDTSC", count: 1, sampleRvas: [5] }
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
      { categories: ["io-privilege"], instruction: name, count: 1, sampleRvas: [0] }
    ]);
  });
}

for (const [name, bytes] of [
  ["INT1", [0xf1]], ["INTO", [0xce]],
  ["UD0", [0x0f, 0xff, 0xc0]], ["UD1", [0x0f, 0xb9, 0xc0]]
] as const) {
  void test(`classifies ${name} as an explicit trap`, () => {
    assert.deepEqual(collect([...bytes], 32), [{ categories: ["trap"], instruction: name, count: 1, sampleRvas: [0] }]);
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

// Intel SDM Vol. 2 and AMD APM Vol. 3 instruction encodings; independent test oracle.
for (const [name, category, bytes] of [
  ["VMXON", "virtualization", [0xf3, 0x0f, 0xc7, 0x30]],
  ["VMRUN", "virtualization", [0x0f, 0x01, 0xd8]],
  ["VMCALL", "hypercall", [0x0f, 0x01, 0xc1]],
  ["VMMCALL", "hypercall", [0x0f, 0x01, 0xd9]],
  ["VMFUNC", "virtualization", [0x0f, 0x01, 0xd4]],
  ["CPUID", "cpu-query", [0x0f, 0xa2]],
  ["XGETBV", "cpu-query", [0x0f, 0x01, 0xd0]],
  ["RDTSC", "timing", [0x0f, 0x31]],
  ["RDTSCP", "timing", [0x0f, 0x01, 0xf9]],
  ["RDPMC", "timing", [0x0f, 0x33]],
  ["SIDT", "system-state", [0x0f, 0x01, 0x08]],
  ["MOV CR", "system-state", [0x0f, 0x20, 0xc0]],
  ["MOV DR", "system-state", [0x0f, 0x23, 0xc0]],
  ["CLFLUSH", "cache-tlb", [0x0f, 0xae, 0x38]],
  ["INVLPG", "cache-tlb", [0x0f, 0x01, 0x38]],
  ["ENDBR64", "hardware-security", [0xf3, 0x0f, 0x1e, 0xfa]],
  ["WRPKRU", "hardware-security", [0x0f, 0x01, 0xef]],
  ["ENCLU", "hardware-security", [0x0f, 0x01, 0xd7]],
  ["XBEGIN", "transaction", [0xc7, 0xf8, 0, 0, 0, 0]],
  ["XTEST", "transaction", [0x0f, 0x01, 0xd6]],
  ["STAC", "hardware-security", [0x0f, 0x01, 0xcb]],
  ["CLAC", "hardware-security", [0x0f, 0x01, 0xca]],
  ["SWAPGS", "system-state", [0x0f, 0x01, 0xf8]],
  ["XSAVES", "system-state", [0x0f, 0xc7, 0x28]],
  ["XRSTORS", "system-state", [0x0f, 0xc7, 0x18]],
  ["SYSRETQ", "privileged", [0x48, 0x0f, 0x07]]
] as const) {
  void test(`recognizes ${name} as ${category}`, () => {
    const findings = collect([...bytes]);
    assert.equal(findings.length, 1);
    assert.equal(findings[0]?.instruction, name);
    assert.ok(findings[0]?.categories.includes(category));
  });
}

void test("retains CPU privilege alongside purpose without counting the site twice", () => {
  assert.deepEqual(collect([0xf3, 0x0f, 0xc7, 0x30]), [{
    categories: ["virtualization", "privileged"], instruction: "VMXON", count: 1, sampleRvas: [0]
  }]);
});

void test("does not classify ordinary MOV operands as system registers", () => {
  assert.deepEqual(collect([0x48, 0x89, 0xc0, 0x48, 0x8b, 0x00]), []);
});

void test("bounds address examples while retaining the full site count", () => {
  assert.deepEqual(collect([0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc]), [{
    categories: ["trap"], instruction: "INT3", count: 6, sampleRvas: [0, 1, 2]
  }]);
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

void test("retains uncatalogued privileged instructions and known privileged purpose", () => {
  // AMD APM Vol. 3: SKINIT; Intel SDM Vol. 2: HLT.
  assert.deepEqual(collect([0x0f, 0x01, 0xde, 0xf4]).map(finding => finding.categories), [
    ["privileged"], ["privileged"]
  ]);
});

void test("missing register metadata does not turn every MOV into a system operation", () => {
  assert.ok(isIcedX86Module(iced));
  const { Register: _register, ...withoutRegisters } = iced;
  const collector = createPeSpecialInstructionCollector(withoutRegisters);
  const decoder = new iced.Decoder(64, Uint8Array.from([0x48, 0x89, 0xc0]), iced.DecoderOptions.None);
  const instruction = decoder.decode();
  collector.record(instruction);
  instruction.free();
  decoder.free();
  assert.deepEqual(collector.findings(), []);
});

void test("invalid instructions are rejected even with a recognizable mnemonic", () => {
  assert.ok(isIcedX86Module(iced));
  const collector = createPeSpecialInstructionCollector(iced);
  const instruction = iced.Instruction.create(iced.Code.INVALID);
  Object.defineProperty(instruction, "mnemonic", { value: iced.Mnemonic.Syscall });
  collector.record(instruction);
  instruction.free();
  assert.deepEqual(collector.findings(), []);
});

void test("never asks the decoder for a nonexistent MOV operand or a memory operand register", () => {
  assert.ok(isIcedX86Module(iced));
  const collector = createPeSpecialInstructionCollector(iced);
  const decoder = new iced.Decoder(64, Uint8Array.from([0x48, 0x8b, 0x00]), iced.DecoderOptions.None);
  const instruction = decoder.decode();
  instruction.opKind = operand => {
    assert.ok(operand < instruction.opCount);
    return iced.Instruction.prototype.opKind.call(instruction, operand);
  };
  instruction.opRegister = operand => {
    assert.equal(instruction.opKind(operand), iced.OpKind.Register);
    return iced.Instruction.prototype.opRegister.call(instruction, operand);
  };
  collector.record(instruction);
  instruction.free();
  decoder.free();
  assert.deepEqual(collector.findings(), []);
});

for (const register of ["XCR0", "CR0suffix", "DR0suffix"]) {
  void test(`ignores malformed register metadata ${register}`, () => {
    assert.ok(isIcedX86Module(iced));
    const registers = { ...iced.Register };
    Object.defineProperty(registers, iced.Register.RAX, { value: register });
    const collector = createPeSpecialInstructionCollector({ ...iced, Register: registers });
    const decoder = new iced.Decoder(64, Uint8Array.from([0x48, 0x89, 0xc0]), iced.DecoderOptions.None);
    const instruction = decoder.decode();
    collector.record(instruction);
    instruction.free();
    decoder.free();
    assert.deepEqual(collector.findings(), []);
  });
}

void test("recognizes multi-digit control-register names from decoder metadata", () => {
  assert.ok(isIcedX86Module(iced));
  const registers = { ...iced.Register };
  Object.defineProperty(registers, iced.Register.RAX, { value: "CR10" });
  const collector = createPeSpecialInstructionCollector({ ...iced, Register: registers });
  // iced exposes CR0..CR15 register IDs; this isolates name matching from encoding validity.
  const decoder = new iced.Decoder(64, Uint8Array.from([0x48, 0x89, 0xc0]), iced.DecoderOptions.None);
  const instruction = decoder.decode();
  collector.record(instruction);
  instruction.free();
  decoder.free();
  assert.equal(collector.findings()[0]?.instruction, "MOV CR");
});
