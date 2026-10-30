import assert from "node:assert/strict";
import { test } from "node:test";
import {
  readBlockType, readBulkOperands, readCoreOperands, readMemoryArgument, readSimdOperands
} from "../../../../analyzers/wasm/instruction-operands.js";
import { wasmReader } from "../../../fixtures/wasm-reader.js";

void test("reads block types and rejects reserved negative encodings", async () => {
  assert.equal(await readBlockType(wasmReader([0x40])), "");
  assert.equal(await readBlockType(wasmReader([0x7f])), "i32");
  assert.equal(await readBlockType(wasmReader([1])), "type 1");
  assert.equal(await readBlockType(wasmReader([0x63, 0])), "ref null 0");
  assert.equal(await readBlockType(wasmReader([0x64, 1])), "ref 1");
  await assert.rejects(readBlockType(wasmReader([0x41])), /Unsupported block type/);
});

void test("decodes memory32, memory64 and explicit memory-index immediates", async () => {
  assert.equal(await readMemoryArgument(wasmReader([2, 10])), "memory=0 align=2^2 offset=10");
  assert.equal(await readMemoryArgument(wasmReader([0x40, 1, 0x80, 0x80, 0x80, 0x80, 16])),
    "memory=1 align=2^0 offset=4294967296");
  await assert.rejects(readMemoryArgument(wasmReader([0x80, 1])), /alignment flags/);
});

void test("decodes branch tables, indirect calls, select and exception handlers", async () => {
  assert.equal(await readCoreOperands(wasmReader([0x40]), 2), "");
  assert.equal(await readCoreOperands(wasmReader([3]), 0x20), "3");
  assert.equal(await readCoreOperands(wasmReader([2, 0, 1, 2]), 0x0e), "0 1 default=2");
  assert.equal(await readCoreOperands(wasmReader([3, 1]), 0x11), "3 table=1");
  assert.equal(await readCoreOperands(wasmReader([1, 0x7f]), 0x1c), "i32");
  assert.equal(await readCoreOperands(wasmReader([0x40, 2, 0, 1, 2, 2, 3]), 0x1f), " 0:1:2 2:3");
  await assert.rejects(readCoreOperands(wasmReader([0x40, 1, 4]), 0x1f), /catch kind/);
  assert.equal(await readCoreOperands(wasmReader([0, 0]), 0x28), "memory=0 align=2^0 offset=0");
});

void test("preserves integer values, floating point payloads and signed zero", async () => {
  assert.equal(await readCoreOperands(wasmReader([0x7f]), 0x41), "-1");
  assert.equal(await readCoreOperands(wasmReader([0x7e]), 0x42), "-2");
  assert.equal(await readCoreOperands(wasmReader([0, 0, 0, 0x80]), 0x43), "-0 [00 00 00 80]");
  assert.equal(await readCoreOperands(wasmReader([0, 0, 0, 0, 0, 0, 0xf0, 0x3f]), 0x44),
    "1 [00 00 00 00 00 00 f0 3f]");
  assert.equal(await readCoreOperands(wasmReader([0x70]), 0xd0), "-16");
  assert.equal(await readCoreOperands(wasmReader([3]), 0xd2), "3");
  assert.equal(await readCoreOperands(wasmReader([]), 0x6a), "");
});

void test("decodes bulk-memory and SIMD immediate forms", async () => {
  assert.equal(await readBulkOperands(wasmReader([1, 2]), 8), "1 2");
  assert.equal(await readBulkOperands(wasmReader([3]), 9), "3");
  assert.equal(await readBulkOperands(wasmReader([]), 0), "");
  assert.equal(await readSimdOperands(wasmReader([0, 0]), 0), "memory=0 align=2^0 offset=0");
  assert.equal(await readSimdOperands(wasmReader([0, 0]), 92), "memory=0 align=2^0 offset=0");
  assert.equal(await readSimdOperands(wasmReader(new Array<number>(16).fill(0)), 12),
    new Array<string>(16).fill("00").join(" "));
  assert.equal(await readSimdOperands(wasmReader([3]), 21), "3");
  assert.equal(await readSimdOperands(wasmReader([0, 0, 3]), 84), "memory=0 align=2^0 offset=0 lane=3");
  assert.equal(await readSimdOperands(wasmReader([]), 14), "");
  await assert.rejects(readSimdOperands(wasmReader([]), 13), /Truncated/);
});

void test("covers immediate boundaries without consuming the following instruction", async () => {
  // Core binary instruction encodings: https://webassembly.github.io/spec/core/binary/instructions.html
  assert.equal(await readMemoryArgument(wasmReader([127, 2, 3])), "memory=2 align=2^63 offset=3");
  assert.equal(await readBlockType(wasmReader([0])), "type 0");
  assert.equal(await readCoreOperands(wasmReader([0x40, 1, 3, 2]), 0x1f), " 3:2");
  assert.equal(await readCoreOperands(wasmReader([0, 0]), 0x3e), "memory=0 align=2^0 offset=0");
  assert.equal(await readCoreOperands(wasmReader([2]), 0x3f), "2");
  assert.equal(await readCoreOperands(wasmReader([3]), 0x40), "3");
  assert.equal(await readCoreOperands(wasmReader([]), 1), "");
  assert.equal(await readSimdOperands(wasmReader([0, 0]), 11), "memory=0 align=2^0 offset=0");
  assert.equal(await readSimdOperands(wasmReader([1]), 34), "1");
  assert.equal(await readSimdOperands(wasmReader([0, 0, 1]), 91), "memory=0 align=2^0 offset=0 lane=1");
  const reader = wasmReader([1, 0x7f, 0x0b]);
  assert.equal(await readCoreOperands(reader, 0x1c), "i32");
  assert.equal(reader.remaining, 1);
  assert.equal(await readCoreOperands(wasmReader([2, 0x7f, 0x7e]), 0x1c), "i32 i64");
  assert.equal(await readCoreOperands(wasmReader([3, 1]), 0x13), "3 table=1");
});

void test("distinguishes 32-bit integer constants from 64-bit constants", async () => {
  // 2^32 fits i64 but not the signed i32 immediate encoding.
  const wide = [0x80, 0x80, 0x80, 0x80, 0x10];
  assert.equal(await readCoreOperands(wasmReader(wide), 0x42), "4294967296");
  await assert.rejects(readCoreOperands(wasmReader(wide), 0x41), /overflow/);
});
