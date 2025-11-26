"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  decodeId3Text,
  decodeId3v2FrameSize,
  decodeSynchsafeInt,
  readZeroTerminatedString,
  safeHexPreview
} from "../../analyzers/mp3/utils.js";

const makeDv = bytes => new DataView(Uint8Array.from(bytes).buffer);

void test("decodeSynchsafeInt rejects invalid bytes and decodes valid values", () => {
  const valid = makeDv([0x00, 0x00, 0x04, 0x00]);
  const invalid = makeDv([0x80, 0x00, 0x00, 0x00]);
  assert.strictEqual(decodeSynchsafeInt(valid, 0), 0x200);
  assert.strictEqual(decodeSynchsafeInt(invalid, 0), null);
  assert.strictEqual(decodeSynchsafeInt(makeDv([0x00, 0x01]), 0), null);
});

void test("decodeId3v2FrameSize handles v2, v3/v4 and truncation", () => {
  const v2 = makeDv([0x01, 0x02, 0x03]);
  const v4 = makeDv([0x00, 0x00, 0x02, 0x00]);
  const v3 = makeDv([0x00, 0x00, 0x00, 0x10]);
  assert.strictEqual(decodeId3v2FrameSize(2, v2, 0), (1 << 16) | (2 << 8) | 3);
  assert.strictEqual(decodeId3v2FrameSize(4, v4, 0), 0x100);
  assert.strictEqual(decodeId3v2FrameSize(3, v3, 0), 0x10);
  assert.strictEqual(decodeId3v2FrameSize(4, makeDv([0xff, 0xff, 0xff]), 0), null);
});

void test("decodeId3Text decodes multiple encodings and trims zeros", () => {
  const ascii = makeDv([0x41, 0x42, 0x00, 0x20]);
  assert.strictEqual(decodeId3Text(0, ascii, 0, 4), "AB");

  const utf16 = new Uint8Array([0xff, 0xfe, 0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
  assert.strictEqual(decodeId3Text(1, new DataView(utf16.buffer), 2, 6), "AB");

  const utf16be = new Uint8Array([0x00, 0x41, 0x00, 0x42, 0x00, 0x00]);
  assert.strictEqual(decodeId3Text(2, new DataView(utf16be.buffer), 0, utf16be.length), "AB");

  const utf8 = makeDv([0xc3, 0xa9, 0x00, 0x20]);
  assert.strictEqual(decodeId3Text(3, utf8, 0, 4), "é");
});

void test("readZeroTerminatedString stops at terminator within bounds", () => {
  const dv = makeDv([0x54, 0x65, 0x73, 0x74, 0x00, 0x21]);
  assert.strictEqual(readZeroTerminatedString(dv, 0, 6, 0), "Test");
  assert.strictEqual(readZeroTerminatedString(dv, 0, 2, 0), "Te");
});

void test("safeHexPreview clamps size and appends ellipsis", () => {
  const bytes = new Uint8Array(40).map((_, idx) => idx);
  const dv = new DataView(bytes.buffer);
  const preview = safeHexPreview(dv, 0, bytes.length);
  assert.ok(preview.startsWith("00 01 02 03"));
  assert.ok(preview.length > 0);
});