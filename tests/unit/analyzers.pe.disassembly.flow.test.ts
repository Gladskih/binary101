"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../analyzers/pe/disassembly.js";
import { MockFile } from "../helpers/mock-file.js";

void test("analyzePeInstructionSets follows unconditional jumps and skips invalid bytes", async () => {
  const bytes = new Uint8Array([
    0xeb, 0x02, // jmp +2 (to the final nop)
    0xf0, 0x01, // invalid bytes that should be skipped
    0x90 // nop
  ]);
  const file = new MockFile(bytes, "jmp.bin");

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
  assert.equal(report.bytesSampled, size);
  assert.equal(report.bytesDecoded, 1);
  assert.equal(report.instructionCount, 1);
});

void test("analyzePeInstructionSets uses export RVAs when provided", async () => {
  const bytes = new Uint8Array([
    0xf0, 0x01, 0xce, // invalid instruction bytes
    0x90 // nop (export start)
  ]);
  const file = new MockFile(bytes, "export.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    exportRvas: [0x1003],
    rvaToOff: (rva: number) => (rva >= 0x1000 && rva < 0x1000 + bytes.length ? rva - 0x1000 : null),
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
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("analyzePeInstructionSets uses unwind begin RVAs when provided", async () => {
  const bytes = new Uint8Array([
    0xf0, 0x01, 0xce, // invalid instruction bytes
    0x90 // nop (unwind begin)
  ]);
  const file = new MockFile(bytes, "unwind.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    unwindBeginRvas: [0x1003],
    rvaToOff: (rva: number) => (rva >= 0x1000 && rva < 0x1000 + bytes.length ? rva - 0x1000 : null),
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
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("analyzePeInstructionSets uses unwind handler RVAs when provided", async () => {
  const bytes = new Uint8Array([
    0xf0, 0x01, 0xce, // invalid instruction bytes
    0x90 // nop (unwind handler)
  ]);
  const file = new MockFile(bytes, "unwind-handler.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    unwindHandlerRvas: [0x1003],
    rvaToOff: (rva: number) => (rva >= 0x1000 && rva < 0x1000 + bytes.length ? rva - 0x1000 : null),
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
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("analyzePeInstructionSets uses TLS callback RVAs when provided", async () => {
  const bytes = new Uint8Array([
    0xf0, 0x01, 0xce, // invalid instruction bytes
    0x90 // nop (TLS callback)
  ]);
  const file = new MockFile(bytes, "tls-callback.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    tlsCallbackRvas: [0x1003],
    rvaToOff: (rva: number) => (rva >= 0x1000 && rva < 0x1000 + bytes.length ? rva - 0x1000 : null),
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
  assert.equal(report.instructionCount, 1);
  assert.equal(report.invalidInstructionCount, 0);
});

void test("analyzePeInstructionSets continues past UD2 trap instructions", async () => {
  const bytes = new Uint8Array([
    0x0f, 0x0b, // ud2 (intentional trap)
    0x90, // nop
    0x90 // nop
  ]);
  const file = new MockFile(bytes, "ud2.bin");

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
  assert.equal(report.instructionCount, 3);
  assert.equal(report.invalidInstructionCount, 0);
  assert.equal(report.bytesDecoded, bytes.length);
  assert.ok(!report.issues.some(issue => issue.toLowerCase().includes("invalid instruction")));
});
