"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzeElfInstructionSets, type AnalyzeElfInstructionSetOptions } from "../../analyzers/elf/disassembly.js";
import type { ElfProgramHeader } from "../../analyzers/elf/types.js";
import { MockFile } from "../helpers/mock-file.js";

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
