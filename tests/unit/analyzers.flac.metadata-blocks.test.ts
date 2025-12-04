"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseMetadataBlock } from "../../analyzers/flac/metadata-blocks.js";
import type { FlacApplicationBlock, FlacSeekTableBlock } from "../../analyzers/flac/types.js";

void test("parseMetadataBlock parses seek table entries and notes partial tails", () => {
  const payload = new Uint8Array(19);
  const view = new DataView(payload.buffer);
  view.setBigUint64(0, 1n, false);
  view.setBigUint64(8, 9n, false);
  view.setUint16(16, 256, false);
  payload[18] = 0xff; // partial entry byte
  const warnings: string[] = [];
  const block = parseMetadataBlock(
    3,
    false,
    payload.length,
    4,
    new DataView(payload.buffer),
    false,
    warnings
  ) as FlacSeekTableBlock;
  assert.strictEqual(block.type, "SEEKTABLE");
  assert.strictEqual(block.parsedEntries, 1);
  assert.strictEqual(block.points[0]?.frameSamples, 256);
  assert.ok(warnings.some(warning => warning.toLowerCase().includes("partial")));
});

void test("parseMetadataBlock reads application identifiers", () => {
  const payload = new Uint8Array([0x41, 0x42, 0x43, 0x44, 1, 2, 3]);
  const warnings: string[] = [];
  const block = parseMetadataBlock(
    2,
    false,
    payload.length,
    12,
    new DataView(payload.buffer),
    false,
    warnings
  ) as FlacApplicationBlock;
  assert.strictEqual(block.id, "ABCD");
  assert.strictEqual(block.dataLength, payload.length - 4);
  assert.deepStrictEqual(warnings, []);
});

void test("parseMetadataBlock warns on truncated Vorbis comments", () => {
  const vendor = new TextEncoder().encode("abc");
  const commentText = new TextEncoder().encode("TITLE=Hi");
  const payload = new Uint8Array(4 + vendor.length + 4 + 4 + commentText.length);
  const view = new DataView(payload.buffer);
  let offset = 0;
  view.setUint32(offset, vendor.length, true);
  offset += 4;
  payload.set(vendor, offset);
  offset += vendor.length;
  view.setUint32(offset, 1, true); // comment count
  offset += 4;
  view.setUint32(offset, commentText.length + 4, true); // declare longer than available
  offset += 4;
  payload.set(commentText, offset);

  const warnings: string[] = [];
  const block = parseMetadataBlock(
    4,
    false,
    payload.length,
    8,
    new DataView(payload.buffer),
    false,
    warnings
  );
  assert.strictEqual(block.type, "VORBIS_COMMENT");
  assert.ok(warnings.some(w => w.toLowerCase().includes("truncated")));
  if (block.type === "VORBIS_COMMENT") {
    assert.strictEqual(block.comments[0]?.key, "TITLE");
    assert.strictEqual(block.comments[0]?.value, "Hi");
  }
});
