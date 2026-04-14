"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../analyzers/pe/disassembly/index.js";
import { inlinePeSectionName } from "../../analyzers/pe/sections/name.js";
import { MockFile } from "../helpers/mock-file.js";

const IMAGE_FILE_MACHINE_I386 = 0x014c;
const IMAGE_FILE_MACHINE_AMD64 = 0x8664;
const IMAGE_BASE_I386 = 0x400000n;
const IMAGE_BASE_AMD64 = 0x140000000n;
const TEXT_SECTION_RVA = 0x1000;
const TEXT_SECTION_CHARACTERISTICS = 0x60000020;

const createTextSection = (rawSize: number, virtualSize = rawSize) => [
  {
    name: inlinePeSectionName(".text"),
    virtualSize,
    virtualAddress: TEXT_SECTION_RVA,
    sizeOfRawData: rawSize,
    pointerToRawData: 0,
    characteristics: TEXT_SECTION_CHARACTERISTICS
  }
];

const mapTextRvaToOffset = (rawSize: number) => (rva: number): number | null =>
  rva >= TEXT_SECTION_RVA && rva < TEXT_SECTION_RVA + rawSize ? rva - TEXT_SECTION_RVA : null;

void test("analyzePeInstructionSets follows unconditional jumps and skips invalid bytes", async () => {
  const bytes = new Uint8Array([
    0xeb, 0x02, // jmp +2 (to the final nop)
    0xf0, 0x01, // invalid bytes that should be skipped
    0x90 // nop
  ]);
  const file = new MockFile(bytes, "jmp.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: IMAGE_BASE_AMD64,
    entrypointRva: TEXT_SECTION_RVA,
    rvaToOff: () => 0,
    sections: createTextSection(bytes.length)
  });

  assert.ok(report);
  assert.equal(report.instructionCount, 2);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("analyzePeInstructionSets samples full section bytes by default", async () => {
  const size = 300 * 1024;
  const bytes = new Uint8Array(size);
  bytes.fill(0x90); // nop
  bytes[0] = 0xc3; // ret (stop early but still sample full section)
  const file = new MockFile(bytes, "big.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: IMAGE_BASE_AMD64,
    entrypointRva: TEXT_SECTION_RVA,
    rvaToOff: () => 0,
    sections: createTextSection(bytes.length)
  });

  assert.ok(report);
  assert.equal(report.bytesSampled, size);
  assert.equal(report.bytesDecoded, 1);
  assert.equal(report.instructionCount, 1);
});

for (const seedCase of [
  { label: "export RVAs", fileName: "export.bin", seedOptions: { exportRvas: [TEXT_SECTION_RVA + 3] } },
  { label: "unwind begin RVAs", fileName: "unwind.bin", seedOptions: { unwindBeginRvas: [TEXT_SECTION_RVA + 3] } },
  { label: "unwind handler RVAs", fileName: "unwind-handler.bin", seedOptions: { unwindHandlerRvas: [TEXT_SECTION_RVA + 3] } },
  { label: "GuardCF function RVAs", fileName: "guardcf.bin", seedOptions: { guardCFFunctionRvas: [TEXT_SECTION_RVA + 3] } },
  {
    label: "SafeSEH handler RVAs",
    fileName: "safeseh.bin",
    seedOptions: { safeSehHandlerRvas: [TEXT_SECTION_RVA + 3] },
    coffMachine: IMAGE_FILE_MACHINE_I386,
    imageBase: IMAGE_BASE_I386,
    is64Bit: false
  },
  { label: "TLS callback RVAs", fileName: "tls-callback.bin", seedOptions: { tlsCallbackRvas: [TEXT_SECTION_RVA + 3] } }
]) {
  void test(`analyzePeInstructionSets uses ${seedCase.label} when provided`, async () => {
    const bytes = new Uint8Array([
      0xf0, 0x01, 0xce, // invalid instruction bytes
      0x90 // nop at the seeded entrypoint
    ]);
    const report = await analyzePeInstructionSets(new MockFile(bytes, seedCase.fileName), {
      coffMachine: seedCase.coffMachine ?? IMAGE_FILE_MACHINE_AMD64,
      is64Bit: seedCase.is64Bit ?? true,
      imageBase: seedCase.imageBase ?? IMAGE_BASE_AMD64,
      entrypointRva: 0,
      rvaToOff: mapTextRvaToOffset(bytes.length),
      sections: createTextSection(bytes.length),
      ...seedCase.seedOptions
    });

    assert.ok(report);
    assert.equal(report.instructionCount, 1);
    assert.equal(report.invalidInstructionCount, 0);
  });
}

void test("analyzePeInstructionSets continues past UD2 trap instructions", async () => {
  const bytes = new Uint8Array([
    0x0f, 0x0b, // ud2 (intentional trap)
    0x90, // nop
    0x90 // nop
  ]);
  const file = new MockFile(bytes, "ud2.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: IMAGE_BASE_AMD64,
    entrypointRva: TEXT_SECTION_RVA,
    rvaToOff: () => 0,
    sections: createTextSection(bytes.length)
  });

  assert.ok(report);
  assert.equal(report.instructionCount, 3);
  assert.equal(report.invalidInstructionCount, 0);
  assert.equal(report.bytesDecoded, bytes.length);
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("invalid instruction")));
});

void test("analyzePeInstructionSets samples only the loaded VirtualSize, not raw-file padding", async () => {
  const bytes = new Uint8Array([
    0x90, // mapped code byte
    0x90, 0x90, 0x90 // raw padding bytes that are not part of the loaded image
  ]);
  const file = new MockFile(bytes, "raw-tail.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: IMAGE_BASE_AMD64,
    entrypointRva: TEXT_SECTION_RVA,
    rvaToOff: () => 0,
    sections: createTextSection(bytes.length, 1)
  });

  assert.ok(report);
  assert.equal(report.bytesSampled, 1);
});
