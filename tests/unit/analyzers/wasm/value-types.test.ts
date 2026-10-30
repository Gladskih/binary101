import assert from "node:assert/strict";
import { test } from "node:test";
import { readGlobalType, readLimits, readTable, readTag, readValueType } from "../../../../analyzers/wasm/value-types.js";
import { wasmReader } from "../../../fixtures/wasm-reader.js";

void test("decodes numeric, reference, SIMD and typed reference types", async () => {
  assert.equal(await readValueType(wasmReader([0x7f])), "i32");
  assert.equal(await readValueType(wasmReader([0x7b])), "v128");
  assert.equal(await readValueType(wasmReader([0x63, 0])), "ref null 0");
  assert.equal(await readValueType(wasmReader([0x64, 1])), "ref 1");
  await assert.rejects(readValueType(wasmReader([0xff])), /Unsupported value type/);
  await assert.rejects(readValueType(wasmReader([0x63, 0x7f])), /Unsupported heap type/);
  assert.equal(await readValueType(wasmReader([0x63, 0x70])), "ref null -16");
});

void test("reads limits with shared and memory64 flags and checks ranges", async () => {
  assert.deepEqual(await readLimits(wasmReader([0, 1])),
    { min: 1n, max: null, shared: false, address64: false });
  assert.deepEqual(await readLimits(wasmReader([7, 1, 2])),
    { min: 1n, max: 2n, shared: true, address64: true });
  await assert.rejects(readLimits(wasmReader([8])), /Unsupported limits/);
  await assert.rejects(readLimits(wasmReader([1, 2, 1])), /below minimum/);
  await assert.rejects(readLimits(wasmReader([2, 1])), /require a maximum/);
  await assert.rejects(readLimits(wasmReader([1, 0])), /Truncated/);
});

void test("reads table, global and tag descriptors", async () => {
  assert.equal((await readTable(wasmReader([0x70, 0, 1]))).type, "funcref");
  assert.deepEqual(await readGlobalType(wasmReader([0x7e, 1])), { type: "i64", mutable: true });
  assert.deepEqual(await readGlobalType(wasmReader([0x7f, 0])), { type: "i32", mutable: false });
  await assert.rejects(readGlobalType(wasmReader([0x7f, 2])), /mutability/);
  assert.equal(await readTag(wasmReader([0, 2])), 2);
  await assert.rejects(readTag(wasmReader([1])), /tag attribute/);
});

void test("rejects numeric table elements and shared table limits", async () => {
  await assert.rejects(readTable(wasmReader([0x7f, 0, 1])), /reference type/);
  await assert.rejects(readTable(wasmReader([0x70, 3, 1, 2])), /Shared tables/);
});
