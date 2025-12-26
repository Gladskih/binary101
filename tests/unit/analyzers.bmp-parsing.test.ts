"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildBitmaskChannel,
  computeRowStride,
  describeCompression,
  describeDibKind,
  isUncompressedLayout,
  readInt32le,
  readUint16le,
  readUint32le
} from "../../analyzers/bmp/bmp-parsing.js";

void test("bmp parsing helpers decode integers with bounds checks", () => {
  const bytes = new Uint8Array([0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0xff, 0xff, 0xff, 0xff]);
  assert.strictEqual(readUint16le(bytes, 0), 0x1234);
  assert.strictEqual(readUint32le(bytes, 2), 0x12345678);
  assert.strictEqual(readInt32le(bytes, 6), -1);
  assert.strictEqual(readUint16le(bytes, 9), null);
  assert.strictEqual(readUint32le(bytes, 8), null);
});

void test("bmp parsing helpers describe known and unknown headers/compression", () => {
  assert.strictEqual(describeDibKind(12), "BITMAPCOREHEADER");
  assert.strictEqual(describeDibKind(40), "BITMAPINFOHEADER");
  assert.strictEqual(describeDibKind(108), "BITMAPV4HEADER");
  assert.strictEqual(describeDibKind(124), "BITMAPV5HEADER");
  assert.strictEqual(describeDibKind(64), "DIB (64 bytes)");
  assert.strictEqual(describeDibKind(16), "Core DIB (16 bytes)");
  assert.strictEqual(describeDibKind(null), null);

  assert.match(describeCompression(0) || "", /uncompressed/i);
  assert.match(describeCompression(3) || "", /BITFIELDS/i);
  assert.strictEqual(describeCompression(999), "Unknown (999)");
  assert.strictEqual(describeCompression(null), null);
});

void test("bmp parsing helpers decode bit masks and detect non-contiguous runs", () => {
  assert.strictEqual(buildBitmaskChannel(null), null);
  assert.strictEqual(buildBitmaskChannel(0), null);

  const red = buildBitmaskChannel(0x0000f800);
  assert.ok(red);
  assert.strictEqual(red.shift, 11);
  assert.strictEqual(red.bits, 5);
  assert.strictEqual(red.contiguous, true);

  const weird = buildBitmaskChannel(0b1011);
  assert.ok(weird);
  assert.strictEqual(weird.contiguous, false);
});

void test("bmp parsing helpers compute row stride and recognize uncompressed layouts", () => {
  assert.strictEqual(computeRowStride(1, 24), 4);
  assert.strictEqual(computeRowStride(2, 24), 8);
  assert.strictEqual(computeRowStride(0, 24), null);
  assert.strictEqual(computeRowStride(1, 0), null);
  assert.strictEqual(computeRowStride(null, 24), null);

  assert.strictEqual(isUncompressedLayout(null), true);
  assert.strictEqual(isUncompressedLayout(0), true);
  assert.strictEqual(isUncompressedLayout(3), true);
  assert.strictEqual(isUncompressedLayout(6), true);
  assert.strictEqual(isUncompressedLayout(1), false);
});

