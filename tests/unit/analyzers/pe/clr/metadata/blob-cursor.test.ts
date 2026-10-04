"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { MetadataBlobCursor } from "../../../../../../analyzers/pe/clr/metadata-blob-cursor.js";

void test("reads bounded slices, compressed integers and UTF-8", () => {
  const cursor = new MetadataBlobCursor(Uint8Array.of(7, 0x80, 0x80, 2, 0xc3, 0xa9), [], "Blob");
  assert.equal(cursor.readU8(), 7);
  assert.equal(cursor.readCompressedUInt(), 128);
  assert.equal(cursor.readUtf8(), "é");
  assert.equal(cursor.remaining, 0);
  cursor.finish();
  assert.deepEqual(cursor.issues, []);
});

void test("rejects truncated and reserved compressed integers once", () => {
  const cursor = new MetadataBlobCursor(Uint8Array.of(0xe0), [], "Blob");
  assert.equal(cursor.readCompressedUInt(), null);
  assert.equal(cursor.readU8(), null);
  assert.equal(cursor.readUtf8(), null);
  assert.equal(cursor.issues.length, 1);
  assert.match(cursor.issues[0]!, /compressed integer/);
});

for (const size of [-1, 0.5, Infinity, NaN, 2]) {
  void test(`rejects invalid slice size ${size}`, () => {
    const cursor = new MetadataBlobCursor(Uint8Array.of(1), [], "Blob");
    assert.equal(cursor.readBytes(size), null);
    assert.match(cursor.issues[0]!, /range/);
  });
}

void test("reports truncated UTF-8 and malformed strings", () => {
  const truncated = new MetadataBlobCursor(Uint8Array.of(2, 1), [], "Blob");
  assert.equal(truncated.readUtf8(), null);
  const malformed = new MetadataBlobCursor(Uint8Array.of(1, 0xff), [], "Blob");
  assert.equal(malformed.readUtf8(), null);
  assert.match(malformed.issues[0]!, /UTF-8/);
});

void test("reports trailing bytes and accepts empty strings and slices", () => {
  const cursor = new MetadataBlobCursor(Uint8Array.of(0, 7), [], "Blob");
  assert.equal(cursor.readUtf8(), "");
  assert.deepEqual(cursor.readBytes(0), new Uint8Array());
  cursor.finish();
  assert.match(cursor.issues[0]!, /1 trailing/);
});
