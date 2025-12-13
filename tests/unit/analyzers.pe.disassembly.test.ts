"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../analyzers/pe/disassembly.js";
import { MockFile } from "../helpers/mock-file.js";

void test("analyzePeInstructionSets reports AVX and AVX-512 requirements", async () => {
  const bytes = new Uint8Array([
    // vmovaps xmm1,xmm5 (AVX)
    0xc5, 0xf8, 0x28, 0xcd,
    // vmovaps xmm10{k3}{z},xmm19 (AVX-512: AVX512VL + AVX512F)
    0x62, 0x31, 0x7c, 0x8b, 0x28, 0xd3
  ]);
  const file = new MockFile(bytes, "avx-pe.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0x1000,
    rvaToOff: (rva: number) => (rva === 0x1000 ? 0 : null),
    sections: [
      {
        name: ".text",
        virtualSize: bytes.length,
        virtualAddress: 0x1000,
        sizeOfRawData: bytes.length,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ]
  });

  assert.ok(report, "Expected disassembly report");
  assert.equal(report.instructionCount, 2);
  assert.equal(report.invalidInstructionCount, 0);
  const ids = new Set(report.instructionSets.map(set => set.id));
  assert.ok(ids.has("AVX"));
  assert.ok(ids.has("AVX512F"));
  assert.ok(ids.has("AVX512VL"));
});

void test("analyzePeInstructionSets skips unsupported machines", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "arm-pe.bin");
  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x01c0, // ARM
    is64Bit: false,
    imageBase: 0,
    entrypointRva: 0x1000,
    rvaToOff: () => 0,
    sections: []
  });

  assert.ok(report, "Expected report even when skipped");
  assert.equal(report.instructionCount, 0);
  assert.equal(report.instructionSets.length, 0);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("x86")));
});

void test("analyzePeInstructionSets reports unmapped entrypoint RVAs", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "unmapped.bin");
  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x14c,
    is64Bit: false,
    imageBase: 0x400000,
    entrypointRva: 0x1234,
    rvaToOff: () => null,
    sections: []
  });

  assert.ok(report);
  assert.equal(report.instructionCount, 0);
  assert.equal(report.instructionSets.length, 0);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("entry")));
});

void test("analyzePeInstructionSets falls back to .text when entrypoint is zero", async () => {
  const file = new MockFile(new Uint8Array([0x90, 0x90]), "fallback.bin");
  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    rvaToOff: () => null,
    sections: [
      {
        name: ".text",
        virtualSize: 2,
        virtualAddress: 0x1000,
        sizeOfRawData: 2,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ]
  });

  assert.ok(report);
  assert.equal(report.instructionCount, 2);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("falling back")));
});

void test("analyzePeInstructionSets reports out-of-bounds start offsets", async () => {
  const file = new MockFile(new Uint8Array([0x90]), "oob.bin");
  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x14c,
    is64Bit: false,
    imageBase: 0x400000,
    entrypointRva: 0x1000,
    rvaToOff: () => 10,
    sections: []
  });

  assert.ok(report);
  assert.equal(report.instructionCount, 0);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("no bytes")));
});

void test("analyzePeInstructionSets stops after too many consecutive invalid instructions", async () => {
  const invalidInstr = new Uint8Array([0xf0, 0x01, 0xce]); // lock add esi,ecx (invalid lock prefix)
  const bytes = new Uint8Array(invalidInstr.length * 200);
  for (let i = 0; i < 200; i++) {
    bytes.set(invalidInstr, i * invalidInstr.length);
  }

  const file = new MockFile(bytes, "invalid.bin");
  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0x1000,
    rvaToOff: () => 0,
    sections: [
      {
        name: ".text",
        virtualSize: bytes.length,
        virtualAddress: 0x1000,
        sizeOfRawData: bytes.length,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ]
  });

  assert.ok(report);
  assert.ok(report.invalidInstructionCount > 0);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("too many consecutive invalid")));
});

void test("analyzePeInstructionSets reports decoded bytes when capped", async () => {
  const bytes = new Uint8Array([0x90, 0x90]); // nop; nop
  const file = new MockFile(bytes, "cap.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0x1000,
    rvaToOff: () => 0,
    sections: [
      {
        name: ".text",
        virtualSize: bytes.length,
        virtualAddress: 0x1000,
        sizeOfRawData: bytes.length,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ],
    maxInstructions: 1
  });

  assert.ok(report);
  assert.equal(report.bytesSampled, 2);
  assert.equal(report.bytesDecoded, 1);
  assert.equal(report.instructionCount, 1);
  assert.ok(report.issues.some(issue => issue.toLowerCase().includes("analysis limit")));
});

void test("analyzePeInstructionSets reports progress while decoding", async () => {
  const bytes = new Uint8Array([0x90, 0x90]); // nop; nop
  const file = new MockFile(bytes, "progress.bin");
  const stages: string[] = [];

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0x1000,
    rvaToOff: () => 0,
    sections: [
      {
        name: ".text",
        virtualSize: bytes.length,
        virtualAddress: 0x1000,
        sizeOfRawData: bytes.length,
        pointerToRawData: 0,
        characteristics: 0x60000020
      }
    ],
    yieldEveryInstructions: 1,
    onProgress: progress => {
      stages.push(progress.stage);
      assert.ok(progress.bytesSampled > 0);
    }
  });

  assert.ok(report);
  assert.ok(stages.includes("loading"));
  assert.ok(stages.includes("decoding"));
});
