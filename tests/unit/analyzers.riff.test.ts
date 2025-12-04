"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseRiff } from "../../analyzers/riff/index.js";
import { createSimpleRiff, createNestedRiff } from "../fixtures/riff-sample-files.js";
import { MockFile } from "../helpers/mock-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

void test("parseRiff rejects non-RIFF input", async () => {
  const dv = new DataView(new Uint8Array([0x00, 0x01, 0x02]).buffer);
  const riff = await parseRiff(new MockFile(new Uint8Array(dv.buffer), "bad.bin"));
  assert.strictEqual(riff, null);
});

void test("parseRiff reads top-level chunks", async () => {
  const riff = expectDefined(await parseRiff(createSimpleRiff()));
  assert.strictEqual(riff.formType, "TEST");
  assert.strictEqual(riff.chunks.length, 1);
  assert.strictEqual(riff.chunks[0]?.size, 4);
  assert.strictEqual(riff.stats.chunkCount, 1);
  assert.strictEqual(riff.stats.truncatedChunks, 0);
});

void test("parseRiff reports nested LIST chunks", async () => {
  const riff = expectDefined(await parseRiff(createNestedRiff()));
  const [list] = riff.chunks;
  assert.ok(list);
  assert.strictEqual(list.listType, "INFO");
  assert.ok(list.children && list.children.length === 2);
});

void test("parseRiff flags truncated chunk sizes", async () => {
  const file = createSimpleRiff();
  const bytes = new Uint8Array(await file.arrayBuffer());
  // Inflate the first chunk size beyond the file length.
  new DataView(bytes.buffer).setUint32(16, 0xfffffff0, true);
  const truncated = await parseRiff(new MockFile(bytes, "trunc.riff"));
  assert.ok(truncated);
  assert.ok(truncated.issues.some(issue => issue.toLowerCase().includes("extends beyond")));
  assert.ok(truncated.stats.truncatedChunks >= 1);
});
