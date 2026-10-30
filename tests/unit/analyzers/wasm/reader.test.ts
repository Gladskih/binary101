import assert from "node:assert/strict";
import { test } from "node:test";
import { wasmReader } from "../../../fixtures/wasm-reader.js";
import { wasmString, wasmUnsigned } from "../../../fixtures/wasm-fixtures.js";

void test("reads unsigned integer boundaries, including legal padded encodings", async () => {
  assert.equal(await wasmReader([0xff, 0xff, 0xff, 0xff, 15]).u32(), 0xffffffff);
  assert.equal(await wasmReader([0x80, 0]).u32(), 0);
  assert.equal(await wasmReader([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1])
    .unsigned(64), 0xffffffffffffffffn);
  await assert.rejects(wasmReader([0xff, 0xff, 0xff, 0xff, 16]).u32(), /overflow/);
  await assert.rejects(wasmReader([0x80, 0x80, 0x80, 0x80, 0x80]).u32(), /too long/);
  await assert.rejects(wasmReader([0x80]).u32(), /Truncated/);
});

void test("reads signed boundaries and rejects invalid unused bits", async () => {
  assert.equal(await wasmReader([0x7f]).signed(32), -1n);
  assert.equal(await wasmReader([0x7e]).signed(33), -2n);
  assert.equal(await wasmReader([0xff, 0xff, 0xff, 0xff, 7]).signed(32), 2147483647n);
  assert.equal(await wasmReader([0x80, 0x80, 0x80, 0x80, 0x78]).signed(32), -2147483648n);
  await assert.rejects(wasmReader([0x80, 0x80, 0x80, 0x80, 0x80]).signed(32), /too long/);
  await assert.rejects(wasmReader([0xff, 0xff, 0xff, 0xff, 15]).signed(32), /overflow/);
  await assert.rejects(wasmReader([]).signed(64), /Truncated/);
});

void test("decodes UTF-8 across byte chunks and accepts long names without a cap", async () => {
  assert.equal(await wasmReader(wasmString("€😀"), 1).name(), "€😀");
  assert.equal(await wasmReader(wasmString("\ufeffname"), 1).name(), "\ufeffname");
  assert.equal(await wasmReader([0]).name(), "");
  assert.equal((await wasmReader(wasmString("a".repeat(70_000)), 4096).name()).length, 70_000);
  await assert.rejects(wasmReader([1, 0xff]).name(), /encoded data/);
  await assert.rejects(wasmReader([2, 0x61]).name(), /Truncated/);
});

void test("bounds nested readers, vectors, skips and trailing bytes", async () => {
  const reader = wasmReader([2, 1, 2, 3], 1);
  assert.deepEqual(await reader.vector(() => reader.u32()), [1, 2]);
  assert.throws(() => reader.finish(), /trailing/);
  assert.throws(() => reader.child(2), /Truncated/);
  await assert.rejects(reader.take(-1), /Truncated/);
  await assert.rejects(reader.take(NaN), /Invalid|Truncated/);
  const child = reader.child(1);
  await child.skip(1);
  child.finish();
  assert.equal(reader.remaining, 0);
  await assert.rejects(wasmReader([2, 0]).count(), /Truncated vector/);
});

void test("does not impose artificial vector limits", async () => {
  const count = 10_001;
  const reader = wasmReader([...wasmUnsigned(count), ...new Array<number>(count).fill(0)]);
  assert.equal((await reader.vector(() => reader.u32())).length, count);
});

void test("enforces nested-reader boundaries even when the file has more bytes", async () => {
  const parent = wasmReader([1, 2, 3]);
  const child = parent.child(1);
  await assert.rejects(child.skip(2), /Truncated/);
  assert.equal(parent.offset, 0);
  assert.throws(() => child.check(NaN), /Invalid byte count/);
  await assert.rejects(child.take(1.5), /Invalid byte count/);
});

void test("checks LEB128 lengths that end exactly on a seven-bit boundary", async () => {
  // u7/s7 have only one permitted byte, including padded encodings.
  await assert.rejects(wasmReader([0x80, 0]).unsigned(7), /too long/);
  await assert.rejects(wasmReader([0x80, 0]).signed(7), /too long/);
  await assert.rejects(wasmReader([0x80, 0x80, 0x80, 0x80, 0x10]).u32(), /overflow/);
});

void test("keeps UTF-8 sequences across decoding windows and rejects unfinished final sequences", async () => {
  const name = "a".repeat(65_535) + "€😀";
  assert.equal(await wasmReader(wasmString(name), 4096).name(), name);
  await assert.rejects(wasmReader([1, 0xc2]).name(), /encoded data/);
  const parent = wasmReader([3, 0x61, 0x62, 0x63]);
  const child = parent.child(2);
  await assert.rejects(child.name(), /Truncated/);
  assert.equal(parent.offset, 1);
});

void test("rejects oversized names before decoding any payload window", async () => {
  const reader = wasmReader([...wasmUnsigned(65_537), ...new Array<number>(65_536).fill(0x61)]);
  await assert.rejects(reader.name(), /Truncated/);
  assert.equal(reader.offset, 3);
});
