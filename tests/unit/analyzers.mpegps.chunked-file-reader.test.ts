"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import { ChunkedFileReader } from "../../analyzers/mpegps/chunked-file-reader.js";
import { MockFile } from "../helpers/mock-file.js";

void test("ChunkedFileReader.hasBytes reflects loaded chunk coverage", async () => {
  const bytes = new Uint8Array(16).map((_, index) => index);
  const reader = new ChunkedFileReader(
    new MockFile(bytes, "reader.bin", "application/octet-stream"),
    8,
    2
  );

  assert.strictEqual(reader.hasBytes(0, 1), false);
  assert.strictEqual(await reader.ensureBytes(6, 3), true);
  assert.strictEqual(reader.hasBytes(6, 3), true);
  assert.strictEqual(reader.hasBytes(9, 1), true);
  assert.strictEqual(reader.hasBytes(10, 1), false);
});

void test("ChunkedFileReader.hasBytes rejects invalid or out-of-range requests", async () => {
  const reader = new ChunkedFileReader(
    new MockFile(new Uint8Array(8), "reader.bin", "application/octet-stream"),
    4,
    1
  );

  assert.strictEqual(reader.hasBytes(-1, 1), false);
  assert.strictEqual(reader.hasBytes(0, -1), false);
  assert.strictEqual(reader.hasBytes(8, 1), false);
  assert.strictEqual(await reader.ensureBytes(2, 2), true);
  assert.strictEqual(reader.hasBytes(7, 2), false);
});
