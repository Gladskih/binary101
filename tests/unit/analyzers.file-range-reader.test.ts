"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import { createSliceTrackingFile } from "../helpers/slice-tracking-file.js";

// Use a small explicit window so cache-boundary tests stay cheap and do not
// depend on the production-tuned default.
const TEST_READER_WINDOW_BYTES = 64;
const SMALL_READ_BYTES = 4;
const NEARBY_OFFSET_BYTES = 16;
const DEFAULT_FILE_BYTES = TEST_READER_WINDOW_BYTES * 2;
const EXACT_WINDOW_END_OFFSET_BYTES = TEST_READER_WINDOW_BYTES - SMALL_READ_BYTES;
const OFFSET_PAST_CACHED_WINDOW_BYTES = EXACT_WINDOW_END_OFFSET_BYTES + 1;
const INVALID_NEGATIVE_OFFSET_BYTES = -1;
const EOF_TAIL_BYTES = 12;

const toViewBytes = (view: DataView): number[] =>
  Array.from(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));

const createTrackedReaderFixture = (
  name: string,
  size = DEFAULT_FILE_BYTES
): {
  reader: ReturnType<typeof createFileRangeReader>;
  requests: number[];
  size: number;
} => {
  const bytes = Uint8Array.from({ length: size }, (_value, index) => index & 0xff);
  const tracked = createSliceTrackingFile(bytes, bytes.length, name);
  return {
    reader: createFileRangeReader(tracked.file, 0, tracked.file.size, TEST_READER_WINDOW_BYTES),
    requests: tracked.requests,
    size: tracked.file.size
  };
};

void test("createFileRangeReader reuses a cached window for nearby reads", async () => {
  const tracked = createTrackedReaderFixture("file-reader-cached-window");

  const firstView = await tracked.reader.read(0, SMALL_READ_BYTES);
  const secondView = await tracked.reader.read(NEARBY_OFFSET_BYTES, SMALL_READ_BYTES);

  assert.equal(firstView.byteLength, SMALL_READ_BYTES);
  assert.equal(secondView.byteLength, SMALL_READ_BYTES);
  assert.deepEqual(tracked.requests, [TEST_READER_WINDOW_BYTES]);
});

void test("createFileRangeReader reuses shifted cached windows with correct relative offsets", async () => {
  const tracked = createTrackedReaderFixture("file-reader-shifted-window");

  await tracked.reader.read(NEARBY_OFFSET_BYTES, SMALL_READ_BYTES);
  const shiftedView = await tracked.reader.read(NEARBY_OFFSET_BYTES * 2, SMALL_READ_BYTES);

  assert.deepEqual(toViewBytes(shiftedView), [32, 33, 34, 35]);
  assert.deepEqual(tracked.requests, [TEST_READER_WINDOW_BYTES]);
});

void test("createFileRangeReader caches exact-window reads at both cache boundaries", async () => {
  const tracked = createTrackedReaderFixture("file-reader-exact-window");

  const windowView = await tracked.reader.read(0, TEST_READER_WINDOW_BYTES);
  const repeatedStartView = await tracked.reader.read(0, SMALL_READ_BYTES);
  const repeatedEndView = await tracked.reader.read(
    EXACT_WINDOW_END_OFFSET_BYTES,
    SMALL_READ_BYTES
  );

  assert.equal(windowView.byteLength, TEST_READER_WINDOW_BYTES);
  assert.equal(repeatedStartView.byteLength, SMALL_READ_BYTES);
  assert.equal(repeatedEndView.byteLength, SMALL_READ_BYTES);
  assert.deepEqual(tracked.requests, [TEST_READER_WINDOW_BYTES]);
});

void test("createFileRangeReader does not reuse a cached window for earlier offsets", async () => {
  const tracked = createTrackedReaderFixture("file-reader-earlier-offset");

  await tracked.reader.read(NEARBY_OFFSET_BYTES, SMALL_READ_BYTES);
  const earlierView = await tracked.reader.read(0, SMALL_READ_BYTES);

  assert.equal(earlierView.byteLength, SMALL_READ_BYTES);
  assert.deepEqual(tracked.requests, [TEST_READER_WINDOW_BYTES, TEST_READER_WINDOW_BYTES]);
});

void test("createFileRangeReader does not reuse a cached window past its end", async () => {
  const tracked = createTrackedReaderFixture("file-reader-past-window");

  await tracked.reader.read(0, SMALL_READ_BYTES);
  const uncachedView = await tracked.reader.read(
    OFFSET_PAST_CACHED_WINDOW_BYTES,
    SMALL_READ_BYTES
  );

  assert.equal(uncachedView.byteLength, SMALL_READ_BYTES);
  assert.deepEqual(tracked.requests, [TEST_READER_WINDOW_BYTES, TEST_READER_WINDOW_BYTES]);
});

void test("createFileRangeReader returns empty views for invalid or empty ranges", async () => {
  const tracked = createTrackedReaderFixture("file-reader-invalid-ranges");

  const negativeView = await tracked.reader.read(INVALID_NEGATIVE_OFFSET_BYTES, SMALL_READ_BYTES);
  const eofView = await tracked.reader.read(tracked.size, SMALL_READ_BYTES);
  const emptyView = await tracked.reader.read(0, 0);

  assert.equal(negativeView.byteLength, 0);
  assert.equal(eofView.byteLength, 0);
  assert.equal(emptyView.byteLength, 0);
  assert.deepEqual(tracked.requests, []);
});

void test("createFileRangeReader clamps cached reads to the remaining file tail", async () => {
  const tracked = createTrackedReaderFixture(
    "file-reader-tail-clamp",
    TEST_READER_WINDOW_BYTES + EOF_TAIL_BYTES
  );

  const tailView = await tracked.reader.read(TEST_READER_WINDOW_BYTES, TEST_READER_WINDOW_BYTES);

  assert.equal(tailView.byteLength, EOF_TAIL_BYTES);
  assert.deepEqual(tracked.requests, [EOF_TAIL_BYTES]);
});

void test("createFileRangeReader does not cache oversized reads", async () => {
  const tracked = createTrackedReaderFixture(
    "file-reader-large-read",
    TEST_READER_WINDOW_BYTES + NEARBY_OFFSET_BYTES
  );

  const largeView = await tracked.reader.read(0, tracked.size);
  const smallView = await tracked.reader.read(NEARBY_OFFSET_BYTES, SMALL_READ_BYTES);

  assert.equal(largeView.byteLength, tracked.size);
  assert.equal(smallView.byteLength, SMALL_READ_BYTES);
  assert.deepEqual(tracked.requests.slice(0, 2), [tracked.size, TEST_READER_WINDOW_BYTES]);
});
