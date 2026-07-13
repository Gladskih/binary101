"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { scanFileRangeForPatterns } from "../../../../analyzers/pe/go-runtime-scan.js";

class ChunkedBlob extends Blob {
  readonly chunks: Uint8Array<ArrayBuffer>[];
  cancelled = false;
  sliceBounds: [number, number] | null = null;
  streamCalls = 0;

  constructor(chunks: Uint8Array<ArrayBuffer>[]) {
    super(chunks);
    this.chunks = chunks;
  }

  override slice(start = 0, end = this.size): Blob {
    this.sliceBounds = [start, end];
    return start === 0 && end === this.size ? this : super.slice(start, end);
  }

  override stream(): ReadableStream<Uint8Array<ArrayBuffer>> {
    this.streamCalls += 1;
    let index = 0;
    return new ReadableStream({
      pull: controller => {
        const chunk = this.chunks[index];
        if (chunk) {
          controller.enqueue(chunk);
          index += 1;
        } else controller.close();
      },
      cancel: () => { this.cancelled = true; }
    });
  }
}

void test("scanFileRangeForPatterns finds a pattern across scan chunks", async () => {
  const file = new ChunkedBlob([
    new Uint8Array([0, 0, 0, 0, 0xf1]),
    new Uint8Array([0xff, 0xff, 0xff])
  ]);

  const matches = await scanFileRangeForPatterns(
    file,
    0,
    file.size,
    [new Uint8Array([0xf1, 0xff, 0xff, 0xff])],
    4
  );

  assert.deepEqual(matches, [4]);
});

void test("scanFileRangeForPatterns bounds scans to the requested range", async () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 1, 2, 3, 4]);
  const file = new File([bytes], "bounded.bin");

  const matches = await scanFileRangeForPatterns(
    file,
    4,
    4,
    [new Uint8Array([1, 2, 3, 4])],
    1
  );

  assert.deepEqual(matches, [4]);
});

void test("scanFileRangeForPatterns rejects empty and invalid ranges", async () => {
  const file = new ChunkedBlob([new Uint8Array(8)]);
  assert.deepEqual(await scanFileRangeForPatterns(file, -1, 20, [new Uint8Array([0])], 1), []);
  assert.equal(file.sliceBounds, null);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0.5, 4, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, Number.NaN, 4, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, file.size, 1, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 0, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 0.5, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, Number.NaN, [new Uint8Array([0])], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 4, [], 1), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 4, [new Uint8Array([0])], 0), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 4, [new Uint8Array([0])], 0.5), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 4, [new Uint8Array([0])], Number.NaN), []);
});

void test("scanFileRangeForPatterns checks only aligned offsets relative to the range start", async () => {
  const bytes = new Uint8Array(16);
  bytes.set([0xf1, 0xff, 0xff, 0xff], 4);
  bytes.set([0xf1, 0xff, 0xff, 0xff], 9);
  const file = new File([bytes], "aligned.bin");

  const matches = await scanFileRangeForPatterns(
    file,
    1,
    15,
    [new Uint8Array([0xf1, 0xff, 0xff, 0xff])],
    4
  );

  assert.deepEqual(matches, [9]);
});

void test("scanFileRangeForPatterns ignores empty patterns when nonempty patterns are present", async () => {
  const file = new File([new Uint8Array([1, 2, 3, 4])], "empty-pattern.bin");

  const matches = await scanFileRangeForPatterns(
    file,
    0,
    file.size,
    [new Uint8Array(0), new Uint8Array([3, 4])],
    1
  );

  assert.deepEqual(matches, [2]);
});

void test("scanFileRangeForPatterns verifies complete candidates and clamps the file range", async () => {
  const file = new ChunkedBlob([new Uint8Array([1, 2, 9, 4, 1, 2, 3, 4, 1])]);

  const matches = await scanFileRangeForPatterns(
    file,
    4,
    100,
    [new Uint8Array([1, 2, 3, 4]), new Uint8Array([2, 3])],
    1
  );

  assert.deepEqual(matches, [4, 5]);
  assert.deepEqual(file.sliceBounds, [4, file.size]);
});

void test("scanFileRangeForPatterns avoids opening a stream when no pattern can fit", async () => {
  const file = new ChunkedBlob([new Uint8Array(8)]);

  assert.deepEqual(
    await scanFileRangeForPatterns(file, 0, file.size, [new Uint8Array(file.size + 1)], 1),
    []
  );
  assert.equal(file.sliceBounds, null);
  assert.equal(file.streamCalls, 0);
});

void test("scanFileRangeForPatterns caps unique matches and cancels the stream", async () => {
  const file = new ChunkedBlob([
    new Uint8Array(40),
    new Uint8Array(40),
    new Uint8Array(40)
  ]);

  const matches = await scanFileRangeForPatterns(
    file,
    0,
    file.size,
    [new Uint8Array([0])],
    1
  );

  assert.deepEqual(matches, Array.from({ length: 64 }, (_, index) => index));
  assert.equal(file.cancelled, true);
});
