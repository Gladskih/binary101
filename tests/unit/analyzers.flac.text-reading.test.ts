"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  clampLength,
  decodeAscii,
  decodeUtf8,
  isPrintableAscii
} from "../../analyzers/flac/text-reading.js";

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

void test("clampLength never exceeds available bytes", () => {
  assert.strictEqual(clampLength(10, 2, 5), 5);
  assert.strictEqual(clampLength(10, 8, 5), 2);
  assert.strictEqual(clampLength(4, 10, 3), 0);
});

void test("decodeUtf8 and decodeAscii respect bounds", () => {
  const bytes = new TextEncoder().encode("hello");
  const view = new DataView(bytes.buffer);
  assert.strictEqual(decodeUtf8(view, 0, 10, utf8Decoder), "hello");
  assert.strictEqual(decodeUtf8(view, 1, 2, utf8Decoder), "el");
  assert.strictEqual(decodeAscii(view, 2, 2), "ll");
});

void test("isPrintableAscii only accepts printable bytes", () => {
  assert.strictEqual(isPrintableAscii(new Uint8Array([0x41, 0x42, 0x7e])), true);
  assert.strictEqual(isPrintableAscii(new Uint8Array([0x41, 0x0a, 0x42])), false);
});
