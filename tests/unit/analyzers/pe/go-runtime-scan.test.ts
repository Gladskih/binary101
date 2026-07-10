"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { scanFileRangeForPatterns } from "../../../../analyzers/pe/go-runtime-scan.js";

void test("scanFileRangeForPatterns finds a pattern across scan chunks", async () => {
  const bytes = new Uint8Array(64 * 1024 + 8);
  bytes.set([0xf1, 0xff, 0xff, 0xff], 64 * 1024 - 2);
  const file = new File([bytes], "cross-chunk.bin");

  const matches = await scanFileRangeForPatterns(
    file,
    0,
    file.size,
    [new Uint8Array([0xf1, 0xff, 0xff, 0xff])]
  );

  assert.deepEqual(matches, [64 * 1024 - 2]);
});

void test("scanFileRangeForPatterns bounds scans to the requested range", async () => {
  const bytes = new Uint8Array([1, 2, 3, 4, 1, 2, 3, 4]);
  const file = new File([bytes], "bounded.bin");

  const matches = await scanFileRangeForPatterns(
    file,
    4,
    4,
    [new Uint8Array([1, 2, 3, 4])]
  );

  assert.deepEqual(matches, [4]);
});

void test("scanFileRangeForPatterns rejects empty and invalid ranges", async () => {
  const file = new File([new Uint8Array(8)], "empty.bin");
  assert.deepEqual(await scanFileRangeForPatterns(file, -1, 4, [new Uint8Array([0])]), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 0, [new Uint8Array([0])]), []);
  assert.deepEqual(await scanFileRangeForPatterns(file, 0, 4, []), []);
});
