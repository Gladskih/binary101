"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import {
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_I386,
  IMAGE_SCN_CNT_CODE,
  TestDecoder,
  analyzeEntrypoint,
  createExecutableSection,
  fakeIced,
  testDecoderBitnesses,
  throwingFreeIced
} from "../helpers/pe-entrypoint-disassembly-fixture.js";
import type { TestInstruction } from "../helpers/pe-entrypoint-disassembly-fixture.js";
import { MockFile } from "../helpers/mock-file.js";

const allInstructions = (result: Awaited<ReturnType<typeof analyzeEntrypoint>>) =>
  result.blocks.flatMap(block => block.instructions);

void test("analyzePeEntrypointDisassembly previews only until control flow", async () => {
  const result = await analyzeEntrypoint(new Uint8Array([0x90, 0x40, 0xc3, 0x90]));
  const instructions = allInstructions(result);

  assert.deepEqual(instructions.map(instruction => instruction.text), ["op_90", "op_40", "ret"]);
  assert.equal(result.instructionCount, 3);
  assert.equal(result.bytesDecoded, 3);
  assert.deepEqual(instructions.map(instruction => instruction.rva), [0x1000, 0x1001, 0x1002]);
  assert.deepEqual(instructions.map(instruction => instruction.fileOffset), [0, 1, 2]);
  assert.ok(result.issues.some(issue => /return with unknown stack target/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reports invalid entrypoint decodes", async () => {
  const result = await analyzeEntrypoint(new Uint8Array([0xff]));

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /invalid/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly uses validated PE bitness", async () => {
  testDecoderBitnesses.length = 0;
  const result = await analyzeEntrypoint(
    new Uint8Array([0x90]),
    createExecutableSection(),
    0x1000,
    { coffMachine: IMAGE_FILE_MACHINE_I386, is64Bit: false, imageBase: 0n }
  );

  assert.equal(result.bitness, 32);
  assert.equal(testDecoderBitnesses.at(-1), 32);
});

void test("analyzePeEntrypointDisassembly refuses non-executable entrypoint sections", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x90]),
    createExecutableSection({ characteristics: IMAGE_SCN_CNT_CODE })
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /non-executable section/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly bounds-checks raw section bytes", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array([0x90]),
    createExecutableSection({ virtualSize: 4, sizeOfRawData: 1 }),
    0x1002
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /outside the section bytes/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly uses mapped header bytes only within SizeOfHeaders", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x00, 0x90, 0xc3, 0x90]), "header.exe"), 0, 4),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0x140000000n,
      entrypointRva: 1,
      headerRvaLimit: 3,
      rvaToOff: rva => rva,
      sections: []
    },
    async () => fakeIced
  );

  assert.deepEqual(allInstructions(result).map(instruction => instruction.text), ["op_90", "ret"]);
  assert.equal(result.bytesDecoded, 2);
});

void test("analyzePeEntrypointDisassembly reports disassembler load failures", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 0,
      sections: [createExecutableSection()]
    },
    async () => {
      throw new Error("boom");
    }
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /Failed to load iced-x86/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reports when mapped file tail is empty", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "short-entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 1,
      sections: [createExecutableSection({ sizeOfRawData: 4 })]
    },
    async () => fakeIced
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /No file bytes/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly rejects unmapped header entrypoints", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "header-entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x300,
      headerRvaLimit: 0x200,
      rvaToOff: () => 0,
      sections: []
    },
    async () => fakeIced
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /mapped PE headers/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly rejects header entrypoints without file offsets", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "header-entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 1,
      headerRvaLimit: 2,
      rvaToOff: () => null,
      sections: []
    },
    async () => fakeIced
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /could not be mapped/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly rejects ambiguous PE metadata", async () => {
  const bytes = new Uint8Array([0x90]);
  const unsupported = await analyzeEntrypoint(bytes, createExecutableSection(), 0x1000, {
    coffMachine: 0xaa64
  });
  const absent = await analyzeEntrypoint(bytes, createExecutableSection(), 0);
  const oversized = await analyzeEntrypoint(bytes, createExecutableSection(), 0x1_0000_0000);
  const amd64As32 = await analyzeEntrypoint(bytes, createExecutableSection(), 0x1000, {
    is64Bit: false
  });
  const i386As64 = await analyzeEntrypoint(bytes, createExecutableSection(), 0x1000, {
    coffMachine: IMAGE_FILE_MACHINE_I386,
    is64Bit: true
  });
  const negativeImageBase = await analyzeEntrypoint(bytes, createExecutableSection(), 0x1000, {
    imageBase: -1n
  });

  assert.ok(unsupported.issues.some(issue => /only supported for x86/i.test(issue)));
  assert.ok(absent.issues.some(issue => /does not define an entry point/i.test(issue)));
  assert.ok(oversized.issues.some(issue => /outside the 32-bit RVA range/i.test(issue)));
  assert.ok(amd64As32.issues.some(issue => /AMD64.*32-bit/i.test(issue)));
  assert.ok(i386As64.issues.some(issue => /I386.*64-bit/i.test(issue)));
  assert.ok(negativeImageBase.issues.some(issue => /ImageBase is negative/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reports unexpected disassembler modules", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 0,
      sections: [createExecutableSection()]
    },
    async () => ({})
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /unexpected module shape/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reports runtime disassembly failures", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 0,
      sections: [createExecutableSection()]
    },
    async () => ({
      ...fakeIced,
      Decoder: class {
        constructor() {
          throw new Error("decode boom");
        }
      }
    })
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /disassembly failed/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly stops when decoded length crosses readable bytes", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 0,
      sections: [createExecutableSection({ sizeOfRawData: 1, virtualSize: 1 })]
    },
    async () => ({
      ...fakeIced,
      Decoder: class extends TestDecoder {
        override decodeOut(instruction: TestInstruction): void {
          super.decodeOut(instruction);
          instruction.length = 2;
        }
      }
    })
  );

  assert.equal(result.instructionCount, 0);
  assert.ok(result.issues.some(issue => /readable byte boundary/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly reads long straight-line previews to the boundary", async () => {
  const result = await analyzeEntrypoint(
    new Uint8Array(300).fill(0x90),
    createExecutableSection({ virtualSize: 300, sizeOfRawData: 300 })
  );

  assert.equal(result.instructionCount, 300);
  assert.equal(result.bytesDecoded, 300);
  assert.ok(result.issues.some(issue => /readable byte boundary/i.test(issue)));
});

void test("analyzePeEntrypointDisassembly ignores cleanup failures", async () => {
  const result = await analyzePeEntrypointDisassembly(
    createFileRangeReader(new MockFile(new Uint8Array([0x90]), "entry.exe"), 0, 1),
    {
      coffMachine: IMAGE_FILE_MACHINE_AMD64,
      is64Bit: true,
      imageBase: 0n,
      entrypointRva: 0x1000,
      rvaToOff: () => 0,
      sections: [createExecutableSection()]
    },
    async () => throwingFreeIced
  );

  assert.equal(result.instructionCount, 1);
  assert.equal(result.issues.length, 1);
  assert.ok(result.issues[0]?.includes("readable byte boundary"));
});
