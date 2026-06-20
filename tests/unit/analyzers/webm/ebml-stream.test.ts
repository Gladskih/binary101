"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  createEbmlStreamReader,
  EbmlStreamReader
} from "../../../../analyzers/webm/ebml-stream.js";
import {
  createStreamTestElement,
  createTruncatedElementId
} from "../../../fixtures/webm-stream-fixtures.js";
import { MockFile } from "../../../helpers/mock-file.js";

void test("EbmlStreamReader reads an element and advances across its payload", async () => {
  const payload = new TextEncoder().encode("element-payload");
  const element = createStreamTestElement(payload);
  const startOffset = element.byteLength;
  const endOffset = startOffset + element.byteLength;
  const reader = new EbmlStreamReader(
    new Blob([new Uint8Array(element).buffer]).stream(),
    startOffset,
    endOffset
  );
  const issues: string[] = [];

  const header = await reader.readElementHeader(endOffset, issues);
  const parsedPayload = await reader.readBytes(header?.size ?? 0);
  await reader.cancel();

  assert.strictEqual(header?.offset, startOffset);
  assert.deepEqual(parsedPayload, payload);
  assert.strictEqual(reader.offset, endOffset);
  assert.deepEqual(issues, []);
});

void test("EbmlStreamReader reports a header truncated at the stream boundary", async () => {
  const bytes = createTruncatedElementId();
  const reader = new EbmlStreamReader(
    new Blob([new Uint8Array(bytes).buffer]).stream(),
    0,
    bytes.byteLength
  );
  const issues: string[] = [];

  const header = await reader.readElementHeader(bytes.byteLength, issues);
  await reader.cancel();

  assert.strictEqual(header, null);
  assert.ok(issues.some(issue => issue.includes("Unexpected end of data")));
});

void test("EbmlStreamReader reports an unexpectedly empty source", async () => {
  const expectedBytes = Uint8Array.BYTES_PER_ELEMENT;
  const reader = new EbmlStreamReader(new Blob([]).stream(), 0, expectedBytes);
  const issues: string[] = [];

  const header = await reader.readElementHeader(expectedBytes, issues);
  await reader.cancel();

  assert.strictEqual(header, null);
  assert.ok(issues.some(issue => issue.includes("Unexpected end of stream")));
});

void test("createEbmlStreamReader clamps invalid ranges", async () => {
  const file = new MockFile(new TextEncoder().encode("range-fixture"));

  const reader = createEbmlStreamReader(file, Number.NaN, Number.POSITIVE_INFINITY);
  const bytes = await reader.readBytes(file.size);
  await reader.cancel();

  assert.strictEqual(reader.offset, 0);
  assert.deepEqual([...bytes], []);
});
