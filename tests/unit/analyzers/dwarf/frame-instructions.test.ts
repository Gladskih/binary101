import assert from "node:assert/strict";
import { test } from "node:test";
import { DwarfCursor } from "../../../../analyzers/dwarf/cursor.js";
import { readDwarfFrameInstructions } from "../../../../analyzers/dwarf/frame-instructions.js";
import { dwarfMacroSources } from "../../../fixtures/dwarf-macro-fixture.js";

const readInstructions = async (bytes: number[], machine = 3) => {
  const issues: string[] = [];
  const source = dwarfMacroSources([{ name: ".debug_frame", bytes }]).get(".debug_frame")!;
  const cursor = new DwarfCursor(source.reader, source.section, 0, bytes.length, true, issues);
  return { instructions: await readDwarfFrameInstructions(cursor, 4, 32, "little", machine, issues), issues };
};

void test("CFI expressions preserve nesting and validate nested dependencies", async () => {
  const result = await readInstructions([15, 3, 0xa3, 1, 0x9c]);

  assert.deepEqual(result.instructions[0]?.operands,
    [[{ offset: 0, opcode: 0xa3, operands: [[{ offset: 0, opcode: 0x9c, operands: [] }]] }]]);
  assert.match(result.issues.join(" "), /forbidden/);
});

void test("CFI expression length must be complete", async () => {
  const result = await readInstructions([15]);

  assert.deepEqual(result.instructions, []);
  assert.match(result.issues.join(" "), /Truncated/);
});

void test("MIPS advance_loc8 uses the architecture's fixed eight-byte operand", async () => {
  const result = await readInstructions([0x1d, 1, 0, 0, 0, 0, 0, 0, 0], 8);

  assert.equal(result.instructions[0]?.operation, "MIPS_advance_loc8");
  assert.deepEqual(result.instructions[0]?.operands, [1n]);
  assert.deepEqual(result.issues, []);
});

void test("architecture-specific CFI opcodes cannot be guessed for another machine", async () => {
  const result = await readInstructions([0x2d]);

  assert.deepEqual(result.instructions, []);
  assert.match(result.issues.join(" "), /Unknown CFI/);
});
