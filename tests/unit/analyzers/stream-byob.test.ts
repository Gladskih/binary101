import assert from "node:assert/strict";
import { test } from "node:test";
import { readByobChunk } from "../../../analyzers/stream-byob.js";

void test("readByobChunk returns a partial chunk and then end of stream", async () => {
  const reader = new Blob([new Uint8Array([1, 2, 3])]).stream().getReader({ mode: "byob" });

  const chunk = await readByobChunk(reader, new Uint8Array(8));
  const end = await readByobChunk(reader, new Uint8Array(8));
  reader.releaseLock();

  assert.deepEqual(chunk, { done: false, value: new Uint8Array([1, 2, 3]) });
  assert.equal(end.done, true);
  assert.equal(end.value?.byteLength, 0);
});

void test("readByobChunk preserves the requested minimum across chunks", async () => {
  const reader = new ReadableStream<Uint8Array>({
    type: "bytes",
    start(controller) {
      controller.enqueue(new Uint8Array([1]));
      controller.enqueue(new Uint8Array([2, 3]));
      controller.close();
    }
  }).getReader({ mode: "byob" });

  const chunk = await readByobChunk(reader, new Uint8Array(8), { min: 3 });
  await reader.cancel();
  reader.releaseLock();

  assert.deepEqual(chunk, { done: false, value: new Uint8Array([1, 2, 3]) });
});

void test("readByobChunk propagates a source error", async () => {
  const failure = new Error("source read failed");
  const reader = new ReadableStream<Uint8Array>({
    type: "bytes", start: controller => controller.error(failure)
  }).getReader({ mode: "byob" });

  await assert.rejects(readByobChunk(reader, new Uint8Array(8)), failure);
  reader.releaseLock();
});

void test("readByobChunk rejects an empty destination without consuming the source", async () => {
  const reader = new Blob([new Uint8Array([1])]).stream().getReader({ mode: "byob" });

  await assert.rejects(readByobChunk(reader, new Uint8Array(0)), TypeError);
  const chunk = await readByobChunk(reader, new Uint8Array(8));
  await reader.cancel();
  reader.releaseLock();

  assert.deepEqual(chunk, { done: false, value: new Uint8Array([1]) });
});

void test("readByobChunk settles a pending read when cancelled", async () => {
  const reader = new ReadableStream<Uint8Array>({ type: "bytes" })
    .getReader({ mode: "byob" });

  const pending = readByobChunk(reader, new Uint8Array(8));
  await reader.cancel("test cancellation");
  const result = await pending;
  reader.releaseLock();

  assert.deepEqual(result, { done: true, value: undefined });
});

void test("readByobChunk rejects reads after releasing the reader", async () => {
  const reader = new Blob([]).stream().getReader({ mode: "byob" });
  reader.releaseLock();

  await assert.rejects(readByobChunk(reader, new Uint8Array(8)), TypeError);
});

void test("readByobChunk supports outstanding reads on the same reader", async () => {
  const reader = new ReadableStream<Uint8Array>({
    type: "bytes",
    start(controller) {
      controller.enqueue(new Uint8Array([1]));
      controller.enqueue(new Uint8Array([2]));
      controller.close();
    }
  }).getReader({ mode: "byob" });

  const first = readByobChunk(reader, new Uint8Array(1));
  const second = readByobChunk(reader, new Uint8Array(1));
  const chunks = await Promise.all([first, second]);
  reader.releaseLock();

  assert.deepEqual(chunks, [
    { done: false, value: new Uint8Array([1]) },
    { done: false, value: new Uint8Array([2]) }
  ]);
});
