import assert from "node:assert/strict";
import { test } from "node:test";
import { analyzePeEntrypointDisassembly } from "../../../../../../analyzers/pe/disassembly/index.js";
import { createPeRvaFragments } from "../../../../../helpers/pe-rva-fragments.js";
import { IMAGE_FILE_MACHINE_AMD64, createExecutableSection, fakeIced }
  from "../../../../../helpers/pe-entrypoint-disassembly-fixture.js";

void test("entrypoint preview reports actual file offsets for fragmented RVA bytes", async () => {
  const fixture = createPeRvaFragments(0x1000, Uint8Array.of(0x90, 0x90, 0xc3), 1, 0, 32);
  const result = await analyzePeEntrypointDisassembly(fixture.reader, {
    coffMachine: IMAGE_FILE_MACHINE_AMD64,
    is64Bit: true,
    imageBase: 0n,
    entrypointRva: 0x1000,
    rvaToOff: fixture.mapping,
    sections: [createExecutableSection({ virtualSize: 3, sizeOfRawData: fixture.reader.size })]
  }, async () => fakeIced);
  const instructions = result.blocks.flatMap(block => block.instructions);
  assert.deepEqual(instructions.map(instruction => instruction.text), ["op_90", "op_90", "ret"]);
  assert.deepEqual(instructions.map(instruction => instruction.fileOffset), [0, 32, 33]);
});
