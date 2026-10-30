import assert from "node:assert/strict";
import { test } from "node:test";
import { WasmStream } from "../../../../analyzers/wasm/stream.js";

const streamFrom = (chunks: number[][], size: number): WasmStream => {
  const source = new ReadableStream<Uint8Array>({ start: controller => {
    for (const chunk of chunks) controller.enqueue(new Uint8Array(chunk));
    controller.close();
  } });
  return new WasmStream(source.getReader(), size);
};

void test("streams reads and skips across chunks without retaining skipped bytes", async () => {
  const stream = streamFrom([[1], [], [2, 3], [4]], 4);
  assert.deepEqual([...await stream.read(2)], [1, 2]);
  await stream.consume(1);
  assert.equal(await stream.byte(), 4);
  assert.equal(stream.position, 4);
  await assert.rejects(stream.consume(1), /truncated/);
  await assert.rejects(stream.consume(-1), /truncated/);
  await assert.rejects(stream.byte(), /Truncated/);
});

void test("handles empty chunks and unexpected EOF for byte and bulk reads", async () => {
  assert.equal(await streamFrom([[], [42]], 1).byte(), 42);
  await assert.rejects(streamFrom([], 1).byte(), /Truncated file stream/);
  await assert.rejects(streamFrom([[1]], 2).read(2), /Truncated file stream/);
  assert.deepEqual([...await streamFrom([], 0).read(0)], []);
});

void test("rejects invalid sizes before allocating or consuming bytes", async () => {
  await assert.rejects(streamFrom([], 0).read(NaN), /Invalid|Truncated/);
  await assert.rejects(streamFrom([], 0).consume(NaN), /Invalid|Truncated/);
  await assert.rejects(streamFrom([], 0).read(Infinity), /Invalid|Truncated/);
  await assert.rejects(streamFrom([], 0).read(-1), /Invalid|Truncated/);
});

void test("respects the logical EOF when the underlying stream has additional bytes", async () => {
  const stream = streamFrom([[1, 2, 3]], 2);
  assert.equal(await stream.byte(), 1);
  assert.equal(await stream.byte(), 2);
  await assert.rejects(stream.byte(), /Truncated file/);
  assert.equal(stream.position, 2);
});

void test("reads exact subranges of partially consumed chunks", async () => {
  const stream = streamFrom([[1, 2, 3, 4], [5, 6]], 6);
  assert.equal(await stream.byte(), 1);
  assert.deepEqual([...await stream.read(4)], [2, 3, 4, 5]);
  assert.equal(await stream.byte(), 6);
  assert.equal(stream.position, 6);
});
