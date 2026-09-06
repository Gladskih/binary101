"use strict";

import assert from "node:assert/strict";
import { mock, test } from "node:test";
import { createFileRangeReader } from "../../../analyzers/file-range-reader.js";
import { createSliceTrackingFile } from "../../helpers/slice-tracking-file.js";

void test("createFileRangeReader uses bounded 64 KiB default windows", async () => {
  // Production's measured read-window size, independent of the exported constant.
  const tracked = createSliceTrackingFile(new Uint8Array(128 * 1024), 128 * 1024);
  const reader = createFileRangeReader(tracked.file, 0, tracked.file.size);

  await reader.read(0, 1);

  assert.deepEqual(tracked.requests, [64 * 1024]);
});

for (const limit of [NaN, Infinity, -Infinity, -1, 0]) {
  void test(`createFileRangeReader rejects invalid file limit ${limit}`, async () => {
    const tracked = createSliceTrackingFile(Uint8Array.of(10), 1);
    const reader = createFileRangeReader(tracked.file, 0, limit);

    assert.equal(reader.size, 0);
    assert.equal((await reader.read(0, 1)).byteLength, 0);
    assert.deepEqual(tracked.requests, []);
  });
}

for (const windowBytes of [NaN, Infinity, -Infinity, -1, 0]) {
  void test(`createFileRangeReader disables caching for invalid window ${windowBytes}`, async () => {
    const tracked = createSliceTrackingFile(Uint8Array.of(10, 20), 2);
    const reader = createFileRangeReader(tracked.file, 0, tracked.file.size, windowBytes);

    assert.deepEqual([...(await reader.readBytes(0, 1))], [10]);
    assert.deepEqual([...(await reader.readBytes(0, 1))], [10]);
    assert.deepEqual(tracked.requests, [1, 1]);
  });
}

void test("createFileRangeReader releases its stream lock when BYOB returns no storage", async () => {
  const reader = createFileRangeReader(new File([Uint8Array.of(10)], "missing-storage"), 0, 1);
  const release = mock.method(ReadableStreamBYOBReader.prototype, "releaseLock");
  const read = mock.method(ReadableStreamBYOBReader.prototype, "read", async () => ({ done: true }));

  try {
    await assert.rejects(reader.readInto(0, new Uint8Array(1)),
      { message: "BYOB read did not return its destination buffer" });
    assert.equal(release.mock.callCount(), 1);
  } finally {
    read.mock.restore();
    release.mock.restore();
  }
});
