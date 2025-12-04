"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parsePicture } from "../../analyzers/flac/picture-block.js";
import type { FlacPictureBlock } from "../../analyzers/flac/types.js";

const textEncoder = new TextEncoder();

const buildPayload = (): Uint8Array => {
  const mime = textEncoder.encode("image/jpeg");
  const desc = textEncoder.encode("cover");
  const data = new Uint8Array([9, 8, 7, 6, 5]);
  const header = new Uint8Array(32 + mime.length + desc.length);
  const view = new DataView(header.buffer);
  let offset = 0;
  view.setUint32(offset, 3, false);
  offset += 4;
  view.setUint32(offset, mime.length, false);
  offset += 4;
  header.set(mime, offset);
  offset += mime.length;
  view.setUint32(offset, desc.length, false);
  offset += 4;
  header.set(desc, offset);
  offset += desc.length;
  view.setUint32(offset, 100, false);
  view.setUint32(offset + 4, 200, false);
  view.setUint32(offset + 8, 24, false);
  view.setUint32(offset + 12, 0, false);
  view.setUint32(offset + 16, data.length, false);
  const payload = new Uint8Array(header.length + data.length);
  payload.set(header, 0);
  payload.set(data, header.length);
  return payload;
};

const createBase = (length: number): FlacPictureBlock => ({
  type: "PICTURE",
  rawType: 6,
  isLast: false,
  length,
  offset: 4,
  truncated: false,
  pictureType: null,
  mimeType: null,
  description: null,
  width: null,
  height: null,
  depth: null,
  colors: null,
  dataLength: null
});

void test("parsePicture extracts MIME, dimensions and data length", () => {
  const payload = buildPayload();
  const data = new DataView(payload.buffer);
  const warnings: string[] = [];
  const block = parsePicture(createBase(payload.length), data, warnings);
  assert.strictEqual(block.pictureType, 3);
  assert.strictEqual(block.mimeType, "image/jpeg");
  assert.strictEqual(block.description, "cover");
  assert.strictEqual(block.width, 100);
  assert.strictEqual(block.height, 200);
  assert.strictEqual(block.dataLength, 5);
  assert.deepStrictEqual(warnings, []);
});

void test("parsePicture reports truncated headers", () => {
  const payload = buildPayload().slice(0, 10);
  const data = new DataView(payload.buffer);
  const warnings: string[] = [];
  const block = parsePicture(createBase(payload.length), data, warnings);
  assert.ok(warnings.length >= 1);
  assert.ok(block.mimeType !== null);
});
