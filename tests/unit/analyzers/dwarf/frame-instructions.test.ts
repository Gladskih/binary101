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

void test("debug_frame set_loc retains its plain target-sized address operand", async () => {
  // DWARF 5 §6.4.2.1: set_loc uses an address, here the fixture's 32-bit 0x12345678.
  const result = await readInstructions([1, 0x78, 0x56, 0x34, 0x12]);

  assert.equal(result.instructions[0]?.operation, "set_loc");
  assert.deepEqual(result.instructions[0]?.operands, [0x12345678n]);
  assert.deepEqual(result.issues, []);
});

void test("decodes AArch64 CFI state and signed offset operands only on AArch64", async () => {
  const bytes = [0x2b, 2, 0x7f, 0x2c]; // Arm DWARF ABI section 4.4.
  const arm = await readInstructions(bytes, 183);
  const x86 = await readInstructions(bytes);

  assert.deepEqual(arm.instructions.map(i => [i.operation, i.operands]),
    [["AARCH64_set_ra_state", [2n, -1n]], ["AARCH64_negate_ra_state_with_pc", []]]);
  assert.deepEqual(arm.issues, []);
  assert.deepEqual(x86.instructions, []);
  assert.match(x86.issues.join(" "), /Unknown CFI opcode 0x2b/);
});

void test("a truncated AArch64 CFI offset does not become a valid state instruction", async () => {
  const result = await readInstructions([0x2b, 2, 0x80], 183);

  assert.deepEqual(result.instructions, []);
  assert.match(result.issues.join(" "), /truncated/i);
});
