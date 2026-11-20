"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfInstructionSets, type AnalyzeElfInstructionSetOptions } from "../../../../../analyzers/elf/disassembly.js";
import type { ElfProgramHeader, ElfSectionHeader } from "../../../../../analyzers/elf/types.js";
import { MockFile } from "../../../../helpers/mock-file.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 1,
    typeName: "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 1n,
    memsz: 1n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfProgramHeader;

// Intel SDM Vol. 2 encodings: RDMSR, CLI, RET, NOP, truncated two-byte opcode.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const analyzeSpecialBytes = (bytes: number[], address: bigint, machine = 62) =>
  analyzeElfInstructionSets(new MockFile(Uint8Array.from(bytes), "special.elf"), {
    machine, is64Bit: machine === 62, littleEndian: true, entrypointVaddr: address,
    programHeaders: [ph({ flags: 1, vaddr: address, filesz: BigInt(bytes.length) })], sections: []
  });

void test("ELF64 collects privileges with exact high addresses and skips unreachable sites", async () => {
  const report = await analyzeSpecialBytes([0x0f, 0x32, 0xfa, 0xc3, 0xfa], 0xffff800000001000n);

  assert.deepEqual(report.specialInstructions, [
    { categories: ["system-state", "privileged"], instruction: "RDMSR", count: 1,
      sampleAddresses: [0xffff800000001000n] },
    { categories: ["io-privilege"], instruction: "CLI", count: 1,
      sampleAddresses: [0xffff800000001002n] }
  ]);
});

void test("ELF32 counts sites and limits examples to three addresses", async () => {
  const report = await analyzeSpecialBytes([0xfa, 0xfa, 0xfa, 0xfa, 0xc3], 0x1000n, 3);

  assert.deepEqual(report.specialInstructions, [
    { categories: ["io-privilege"], instruction: "CLI", count: 4,
      sampleAddresses: [0x1000n, 0x1001n, 0x1002n] }
  ]);
});

void test("x32 ELF decodes AMD64 instructions in long mode", async () => {
  // AMD64 MOV r64, imm64 (REX.W+B) followed by RET, in an ELFCLASS32 object.
  const code = Uint8Array.of(0x49, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xc3);
  const report = await analyzeElfInstructionSets(new MockFile(code), {
    machine: 62, is64Bit: false, littleEndian: true, entrypointVaddr: 0x1000n,
    programHeaders: [ph({ flags: 1, vaddr: 0x1000n, filesz: BigInt(code.length) })], sections: []
  });

  assert.equal(report.bitness, 64);
  assert.equal(report.instructionCount, 2);
  assert.equal(report.invalidInstructionCount, 0);
  assert.deepEqual(report.issues, []);
});

const executableSection = (index: number, offset: bigint, size: bigint): ElfSectionHeader => ({
  index, name: `.text.${index}`, type: 1, typeName: "SHT_PROGBITS", nameOff: 0,
  flags: 6n, flagNames: ["ALLOC", "EXECINSTR"], addr: 0n, offset, size,
  link: 0, info: 0, addralign: 1n, entsize: 0n
});

void test("ET_REL samples separate code sections at the same sh_addr", async () => {
  // RET in section 1, unreachable padding, then VADDPS ymm0,ymm0,ymm0 and RET in section 2.
  const code = Uint8Array.of(0, 0xc3, 0, 0xc5, 0xfc, 0x58, 0xc0, 0xc3);
  const report = await analyzeElfInstructionSets(new MockFile(code), {
    fileType: 1, machine: 62, is64Bit: true, littleEndian: true, entrypointVaddr: 0n,
    programHeaders: [], sections: [executableSection(1, 1n, 1n), executableSection(2, 3n, 5n)]
  });

  assert.equal(report.bytesDecoded, 6);
  assert.equal(report.instructionCount, 3);
  assert.ok(report.instructionSets.some(set => set.id === "AVX"));
});

void test("ET_REL uses function offsets and ignores apparent cross-section branches", async () => {
  // Section 1 has two bytes of padding and JMP +1, aiming past the RET in section 2.
  const code = Uint8Array.of(0, 0xfa, 0xfa, 0xeb, 1, 0xc3, 0xfa, 0xc3);
  const report = await analyzeElfInstructionSets(new MockFile(code), {
    fileType: 1, machine: 62, is64Bit: true, littleEndian: true, entrypointVaddr: 0n,
    programHeaders: [],
    sections: [executableSection(1, 1n, 4n), executableSection(2, 5n, 3n)],
    symbolTables: [{ sectionIndex: 3, issues: [], entries: [
      { name: "launch", value: 2n, size: 2n, sectionIndex: 1, info: 0x12, other: 0 },
      { name: "stop", value: 0n, size: 1n, sectionIndex: 2, info: 0x12, other: 0 }
    ] }]
  });

  assert.equal(report.instructionCount, 2);
  assert.deepEqual(report.specialInstructions, []);
  assert.equal(report.seedSummary?.fallbackSource, null);
  assert.equal(report.seedSummary?.sources[0]?.added, 2);
});

void test("ELF x86 ISA rejects unsupported machine and header layout combinations", async () => {
  const file = new MockFile(Uint8Array.of(0xc3));
  const options: AnalyzeElfInstructionSetOptions = {
    machine: 3, is64Bit: true, littleEndian: true, entrypointVaddr: 0x1000n, sections: [],
    programHeaders: [ph({ flags: 1, vaddr: 0x1000n })]
  };
  const invalidClass = await analyzeElfInstructionSets(file, options);
  const invalidEncoding = await analyzeElfInstructionSets(file, { ...options, littleEndian: false });

  assert.equal(invalidClass.bytesSampled, 0);
  assert.match(invalidClass.issues.join(" "), /EM_386 requires the ELF32 file class/);
  assert.equal(invalidEncoding.bytesSampled, 0);
  assert.match(invalidEncoding.issues.join(" "), /Big-endian ELF is not supported/);
});

void test("ELF retains findings before truncated instructions and ignores ordinary code", async () => {
  const report = await analyzeSpecialBytes([0x90, 0xfa, 0x0f], 0x1000n);

  assert.deepEqual(report.specialInstructions, [
    { categories: ["io-privilege"], instruction: "CLI", count: 1, sampleAddresses: [0x1001n] }
  ]);
  assert.equal(report.invalidInstructionCount, 1);
  assert.ok(report.issues.some(issue => issue.includes("invalid instruction")));
});

void test("ELF reports no special instructions for ordinary code or empty input", async () => {
  const ordinary = await analyzeSpecialBytes([0x90, 0xc3], 0x1000n);
  const empty = await analyzeSpecialBytes([], 0x1000n);

  assert.deepEqual(ordinary.specialInstructions, []);
  assert.deepEqual(empty.specialInstructions, []);
});

void test("analyzeElfInstructionSets returns an empty report for unsupported machines", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const report = await analyzeElfInstructionSets(file, {
    machine: 40,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: [],
    sections: []
  });

  assert.equal(report.bytesSampled, 0);
  assert.equal(report.instructionCount, 0);
  assert.equal(report.instructionSets.length, 0);
  assert.ok(report.issues.some(issue => issue.includes("only supported")));
});

void test("analyzeElfInstructionSets returns an empty report when no executable regions exist", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0n,
    programHeaders: [],
    sections: []
  });

  assert.equal(report.bytesSampled, 0);
  assert.ok(report.issues.some(issue => issue.includes("No executable")));
});

void test("analyzeElfInstructionSets samples bytes but returns early when aborted", async () => {
  const file = new MockFile(new Uint8Array([1, 2, 3, 4]), "elf.bin");
  const controller = new AbortController();
  controller.abort();

  const opts: AnalyzeElfInstructionSetOptions = {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0x1000n,
    programHeaders: [ph({ index: 0, flags: 0x1, vaddr: 0x1000n, offset: 0n, filesz: 4n })],
    sections: [],
    signal: controller.signal
  };
  const report = await analyzeElfInstructionSets(file, opts);

  assert.equal(report.bytesSampled, 4);
  assert.equal(report.bytesDecoded, 0);
  assert.ok(report.issues.some(issue => issue.includes("cancelled")));
});

void test("analyzeElfInstructionSets supports executable spans larger than 4GiB (ELF64)", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "elf.bin");
  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0x1_0000_0000n,
    programHeaders: [
      ph({ index: 0, flags: 0x1, vaddr: 0x0n, offset: 0n, filesz: 1n }),
      ph({ index: 1, flags: 0x1, vaddr: 0x1_0000_0000n, offset: 0n, filesz: 1n })
    ],
    sections: []
  });

  assert.equal(report.bytesSampled, 2);
  assert.equal(report.bytesDecoded, 1);
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 0);
  assert.ok(!report.issues.some(issue => issue.includes("exceeds 4GiB")));
});

void test("analyzeElfInstructionSets can decode a small executable slice via iced-x86", async () => {
  const file = new MockFile(new Uint8Array([0x90, 0x90, 0xc3]), "elf.bin");
  const stages: string[] = [];
  const report = await analyzeElfInstructionSets(file, {
    machine: 62,
    is64Bit: true,
    littleEndian: true,
    entrypointVaddr: 0x1000n,
    programHeaders: [ph({ index: 0, flags: 0x1, vaddr: 0x1000n, offset: 0n, filesz: 3n })],
    sections: [],
    yieldEveryInstructions: 1,
    onProgress: progress => {
      stages.push(progress.stage);
    }
  });

  assert.equal(report.bytesSampled, 3);
  assert.equal(report.bytesDecoded, 3);
  assert.equal(report.instructionCount, 3);
  assert.equal(report.invalidInstructionCount, 0);
  assert.ok(stages.includes("loading"));
  assert.ok(stages.includes("decoding"));
  assert.ok(stages.includes("done"));
});
