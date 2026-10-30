import assert from "node:assert/strict";
import { test } from "node:test";
import { readExpression, readInstruction } from "../../../../analyzers/wasm/instructions.js";
import { wasmReader } from "../../../fixtures/wasm-reader.js";

void test("decodes nested control flow through the matching expression end", async () => {
  const reader = wasmReader([4, 0x40, 5, 0x0b, 0x0b, 1], 1);
  assert.deepEqual((await readExpression(reader)).map(row => row.mnemonic), ["if", "else", "end", "end"]);
  assert.equal(reader.remaining, 1);
  assert.equal((await readExpression(wasmReader([6, 0x40, 0x18, 0, 0x0b]))).length, 3);
  await assert.rejects(readExpression(wasmReader([5, 0x0b])), /Unexpected else/);
  await assert.rejects(readExpression(wasmReader([0x18, 0])), /Unexpected delegate/);
  await assert.rejects(readExpression(wasmReader([2, 0x40, 0x0b])), /Truncated/);
});

void test("decodes bulk, SIMD, relaxed SIMD and atomic instructions", async () => {
  assert.equal((await readInstruction(wasmReader([0xfc, 8, 0, 0]))).mnemonic, "memory.init");
  assert.equal((await readInstruction(wasmReader([0xfd, 14]))).mnemonic, "i8x16.swizzle");
  assert.equal((await readInstruction(wasmReader([0xfd, 0x80, 2]))).mnemonic, "i8x16.relaxed_swizzle");
  assert.equal((await readInstruction(wasmReader([0xfe, 3, 0]))).mnemonic, "atomic.fence");
  assert.equal((await readInstruction(wasmReader([0xfe, 0x10, 2, 0]))).mnemonic, "i32.atomic.load");
  await assert.rejects(readInstruction(wasmReader([0xfe, 3, 1])), /reserved byte/);
  await assert.rejects(readInstruction(wasmReader([0xfc, 0x7f])), /Unsupported opcode/);
  await assert.rejects(readInstruction(wasmReader([0xff])), /Unsupported opcode/);
  await assert.rejects(readInstruction(wasmReader([0xfd])), /Truncated/);
});

void test("reads an expression with over 20000 instructions without truncation", async () => {
  assert.equal((await readExpression(wasmReader([...new Array<number>(20_001).fill(1), 0x0b]))).length,
    20_002);
});

void test("preserves prefixed instruction offsets and reserved-byte consumption", async () => {
  const reader = wasmReader([1, 0xfe, 3, 0, 0x0b]);
  assert.deepEqual(await readInstruction(reader), { offset: 0, mnemonic: "nop", operands: "" });
  assert.deepEqual(await readInstruction(reader), { offset: 1, mnemonic: "atomic.fence", operands: "" });
  assert.equal(reader.offset, 4);
});

void test("balances loop, block and try_table frames and rejects a duplicate else", async () => {
  const reader = wasmReader([3, 0x40, 2, 0x40, 0x1f, 0x40, 0, 0x0b, 0x0b, 0x0b, 0x0b]);
  assert.deepEqual((await readExpression(reader)).map(row => row.mnemonic),
    ["loop", "block", "try_table", "end", "end", "end", "end"]);
  assert.equal(reader.remaining, 0);
  await assert.rejects(readExpression(wasmReader([4, 0x40, 5, 5, 0x0b, 0x0b])), /Unexpected else/);
  assert.equal((await readExpression(wasmReader([4, 0x40, 4, 0x40, 5, 0x0b, 5, 0x0b, 0x0b]))).length, 7);
  assert.equal((await readExpression(wasmReader([2, 0x40, 4, 0x40, 5, 0x0b, 0x0b, 0x0b]))).length, 6);
});
