import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeDwarfExpression } from "../../../../analyzers/dwarf/expressions.js";

const context = { version: 5, format: 32 as const, addressSize: 8, stringOffsetsBase: null };

void test("expressions decode signed frame offsets, registers, pieces, and entry values", async () => {
  const issues: string[] = [];
  // DWARF 5 7.7.1: fbreg -8; reg5; piece 4; entry_value(reg0); stack_value.
  const operations = await decodeDwarfExpression(
    Uint8Array.of(0x91, 0x78, 0x55, 0x93, 4, 0xa3, 1, 0x50, 0x9f), context, "little", issues
  );

  assert.deepEqual(operations.map(operation => operation.operands), [
    [-8n], [], [4n], [[{ offset: 0, opcode: 0x50, operands: [] }]], []
  ]);
  assert.deepEqual(issues, []);
});

void test("expressions reject truncated operands and unknown operation encodings", async () => {
  const truncated: string[] = [];
  const unknown: string[] = [];

  assert.equal((await decodeDwarfExpression(Uint8Array.of(0x03), context, "little", truncated))[0]?.incomplete, true);
  assert.equal((await decodeDwarfExpression(Uint8Array.of(0xff), context, "little", unknown))[0]?.incomplete, true);

  assert.match(truncated.join(" "), /Truncated/);
  assert.match(unknown.join(" "), /Unsupported DWARF expression/);
});

void test("conditional branches also reject targets inside an operand", async () => {
  const issues: string[] = [];

  await decodeDwarfExpression(Uint8Array.of(0x28, 1, 0, 0x10, 0), context, "little", issues);

  assert.match(issues.join(" "), /branch target 4/);
});

void test("expressions report branch operands outside instruction boundaries", async () => {
  const issues: string[] = [];
  // DW_OP_skip's signed two-byte operand targets one byte after its end (7.7.1).
  await decodeDwarfExpression(Uint8Array.of(0x2f, 1, 0, 0x10, 0), context, "little", issues);

  assert.match(issues.join(" "), /branch target/);
});

void test("expressions honor byte order in fixed operands and nested entry values", async () => {
  const little: string[] = [];
  const big: string[] = [];
  const bytes = Uint8Array.of(0x0a, 0x12, 0x34, 0xa3, 4, 0x0a, 0x12, 0x34, 0x50);

  assert.deepEqual(await decodeDwarfExpression(bytes, context, "little", little), [
    { offset: 0, opcode: 0x0a, operands: [0x3412n] },
    { offset: 3, opcode: 0xa3, operands: [[
      { offset: 0, opcode: 0x0a, operands: [0x3412n] }, { offset: 3, opcode: 0x50, operands: [] }
    ]] }
  ]);
  assert.equal((await decodeDwarfExpression(bytes, context, "big", big))[0]?.operands[0], 0x1234n);
  assert.equal(((await decodeDwarfExpression(bytes, context, "big", big))[1]?.operands[0] as Array<{operands: bigint[]}>)[0]?.operands[0], 0x1234n);
  assert.deepEqual(little, []);
  assert.deepEqual(big, []);
});

void test("expression branches accept instruction boundaries including nested expression ends", async () => {
  const issues: string[] = [];

  await decodeDwarfExpression(Uint8Array.of(0x2f, 1, 0, 0x50), context, "little", issues);
  await decodeDwarfExpression(Uint8Array.of(0x2f, 0xfd, 0xff), context, "little", issues);
  await decodeDwarfExpression(Uint8Array.of(0xa3, 3, 0x2f, 0, 0), context, "little", issues);
  assert.deepEqual(issues, []);
  assert.deepEqual(await decodeDwarfExpression(new Uint8Array(), context, "little", issues), []);
  await decodeDwarfExpression(Uint8Array.of(0x2f), context, "little", issues);
  assert.equal(issues.length, 1);
  assert.match(issues[0]!, /^DWARF expression at.*Truncated/);
});
