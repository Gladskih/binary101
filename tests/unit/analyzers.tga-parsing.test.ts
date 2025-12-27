"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  computeBytesPerPixel,
  decodeFixedString,
  decodeOrigin,
  decodePossiblyBinaryField,
  describeColorMapType,
  describeDescriptorReservedBits,
  describeImageType,
  readUint16le,
  readUint32le,
  readUint8
} from "../../analyzers/tga/tga-parsing.js";

void test("tga parsing helpers decode integers with bounds checks", () => {
  const bytes = new Uint8Array([0x12, 0x34, 0x78, 0x56, 0x34, 0x12]);
  assert.strictEqual(readUint8(bytes, 0), 0x12);
  assert.strictEqual(readUint8(bytes, 6), null);
  assert.strictEqual(readUint16le(bytes, 0), 0x3412);
  assert.strictEqual(readUint16le(bytes, 5), null);
  assert.strictEqual(readUint32le(bytes, 1), 0x34567834);
  assert.strictEqual(readUint32le(bytes, 3), null);
});

void test("tga parsing helpers decode fixed strings and ID fields", () => {
  const bytes = new Uint8Array([0x41, 0x42, 0x00, 0x43, 0x20]);
  assert.strictEqual(decodeFixedString(bytes, 0, 5), "AB");

  const printable = new Uint8Array(Buffer.from("Hello world", "ascii"));
  assert.deepEqual(decodePossiblyBinaryField(printable), { text: "Hello world", previewHex: null });

  const binary = new Uint8Array([0x00, 0xff, 0x10, 0x20]);
  const decoded = decodePossiblyBinaryField(binary);
  assert.strictEqual(decoded.text, null);
  assert.match(decoded.previewHex || "", /^0x/);
});

void test("tga parsing helpers describe enums and decode origin", () => {
  assert.strictEqual(describeColorMapType(0), "No color map");
  assert.strictEqual(describeColorMapType(1), "Color map included");
  assert.match(describeColorMapType(2) || "", /Reserved/);
  assert.match(describeColorMapType(200) || "", /Developer-defined/);
  assert.strictEqual(describeColorMapType(null), null);

  assert.match(describeImageType(2) || "", /Truecolor/);
  assert.match(describeImageType(10) || "", /RLE/);
  assert.match(describeImageType(200) || "", /Developer-defined/);
  assert.match(describeImageType(7) || "", /Unknown/);
  assert.strictEqual(describeImageType(null), null);

  assert.strictEqual(computeBytesPerPixel(24), 3);
  assert.strictEqual(computeBytesPerPixel(15), 2);
  assert.strictEqual(computeBytesPerPixel(0), null);

  assert.strictEqual(decodeOrigin(0x00), "bottom-left");
  assert.strictEqual(decodeOrigin(0x10), "bottom-right");
  assert.strictEqual(decodeOrigin(0x20), "top-left");
  assert.strictEqual(decodeOrigin(0x30), "top-right");
  assert.strictEqual(decodeOrigin(null), null);

  assert.strictEqual(describeDescriptorReservedBits(0x00), null);
  assert.ok(describeDescriptorReservedBits(0x80));
});
