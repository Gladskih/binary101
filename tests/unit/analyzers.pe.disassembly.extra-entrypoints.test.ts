"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeInstructionSets } from "../../analyzers/pe/disassembly.js";
import { MockFile } from "../helpers/mock-file.js";

void test("analyzePeInstructionSets uses extra entrypoints when provided", async () => {
  const bytes = new Uint8Array([
    0xf0, 0x01, 0xce, // invalid instruction bytes
    0x90 // nop (extra entrypoint)
  ]);
  const file = new MockFile(bytes, "extra-entry.bin");

  const report = await analyzePeInstructionSets(file, {
    coffMachine: 0x8664,
    is64Bit: true,
    imageBase: 0x140000000,
    entrypointRva: 0,
    extraEntrypoints: [{ source: "Extra seed", rvas: [0x1003] }],
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

