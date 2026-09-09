import assert from "node:assert/strict";
import { test } from "node:test";
import { readElfCfiInstructions } from "../../../../analyzers/elf/cfi-instructions.js";
import { unwindCursor } from "../../../fixtures/elf-unwind.js";

// Operand layouts from DWARF 5 6.4.2; GNU additions from LLVM Dwarf.def.
for (const [opcode, name, operands] of [
  [0, "nop", []], [5, "offset_extended", [1, 2]], [6, "restore_extended", [1]],
  [7, "undefined", [1]], [8, "same_value", [1]], [9, "register", [1, 2]],
  [10, "remember_state", []], [11, "restore_state", []], [12, "def_cfa", [1, 2]],
  [13, "def_cfa_register", [1]], [14, "def_cfa_offset", [1]],
  [18, "def_cfa_sf", [1, 2]], [19, "def_cfa_offset_sf", [1]],
  [20, "val_offset", [1, 2]], [21, "val_offset_sf", [1, 2]],
  [0x2f, "GNU_negative_offset_extended", [1, 2]]
] as const) {
  void test(`decodes DW_CFA_${name}`, async () => {
    const { cursor, issues } = unwindCursor([opcode, ...operands]);
    assert.deepEqual(await readElfCfiInstructions(cursor, 8, 62),
      [{ offset: 0, operation: name, operands: operands.map(BigInt) }]);
    assert.deepEqual(issues, []);
  });
}

void test("decodes value expressions with their register operand", async () => {
  const { cursor, issues } = unwindCursor([22, 3, 1, 0x30]);
  assert.deepEqual(await readElfCfiInstructions(cursor, 8, 62),
    [{ offset: 0, operation: "val_expression", operands: [3n, "30"] }]);
  assert.deepEqual(issues, []);
});

void test("reads primary and extended CFI operands without applying register rules", async () => {
  const { cursor, issues } = unwindCursor([0x42, 0x83, 4, 0xc5, 0x11, 6, 0x78,
    1, 1, 0, 0, 0, 2, 7, 3, 8, 0, 4, 9, 0, 0, 0, 0x2e, 10]);
  const result = await readElfCfiInstructions(cursor, 4, 62);
  assert.deepEqual(result.map(item => item.operation), ["advance_loc", "offset", "restore",
    "offset_extended_sf", "set_loc", "advance_loc1", "advance_loc2", "advance_loc4", "GNU_args_size"]);
  assert.deepEqual(result[3]?.operands, [6n, -8n]);
  assert.deepEqual(issues, []);
});

void test("retains bounded DWARF expressions", async () => {
  const { cursor, issues } = unwindCursor([15, 2, 0x77, 8, 16, 1, 0]);
  const result = await readElfCfiInstructions(cursor, 8, 62);
  assert.deepEqual(result.map(item => item.operands), [["7708"], [1n, ""]]);
  assert.deepEqual(issues, []);
});

void test("reports truncated expressions, missing operands and unknown operations", async () => {
  const first = unwindCursor([15, 2, 0x77]);
  assert.deepEqual(await readElfCfiInstructions(first.cursor, 8, 62), []);
  assert.match(first.issues.join(" "), /expression/);
  const second = unwindCursor([0x80]);
  assert.deepEqual(await readElfCfiInstructions(second.cursor, 8, 62), []);
  assert.ok(second.issues.length > 0);
  const third = unwindCursor([0x3f]);
  assert.deepEqual(await readElfCfiInstructions(third.cursor, 8, 62), []);
  assert.match(third.issues.join(" "), /CFI/);
});

void test("recognizes architecture-specific state operations", async () => {
  const first = unwindCursor([0x2d]);
  assert.equal((await readElfCfiInstructions(first.cursor, 8, 183))[0]?.operation,
    "AARCH64_negate_ra_state");
  const second = unwindCursor([0x2d]);
  assert.equal((await readElfCfiInstructions(second.cursor, 4, 2))[0]?.operation, "GNU_window_save");
});

void test("bounds expanded CFI instructions", async () => {
  const { cursor, issues } = unwindCursor(Array.from({ length: 4097 }, () => 0));
  assert.equal((await readElfCfiInstructions(cursor, 8, 62)).length, 4096);
  assert.match(issues.join(" "), /limit/);
});
