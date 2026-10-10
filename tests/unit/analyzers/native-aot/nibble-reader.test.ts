import assert from "node:assert/strict";
import { test } from "node:test";
import { NibbleReader } from "../../../../analyzers/native-aot/nibble-reader.js";

void test("reads low nibble first and big-endian base-eight unsigned integers", () => {
  // nibblestream.h: 0x9,0x2 encodes 1*8+2; then 0x3 encodes three.
  const reader = new NibbleReader(Uint8Array.of(0x29, 0x43));

  assert.equal(reader.unsigned(), 10);
  assert.equal(reader.byteOffset, 1);
  assert.equal(reader.unsigned(), 3);
  assert.equal(reader.byteOffset, 2);
  assert.equal(reader.unsigned(), 4);
});

void test("reads signed magnitudes and the full UInt32 range", () => {
  const signed = new NibbleReader(Uint8Array.of(0x67, 0));
  const maximum = new NibbleReader(Uint8Array.of(0xfb, 0xff, 0xff, 0xff, 0xff, 0x07));

  assert.equal(signed.signed(), -3);
  assert.equal(signed.signed(), 3);
  assert.equal(signed.signed(), 0);
  assert.equal(maximum.unsigned(), 0xffffffff);
});

void test("rejects truncated continuations and values outside the format's UInt32", () => {
  assert.throws(() => new NibbleReader(Uint8Array.of(0x88)).unsigned(), /truncated/);
  assert.throws(() => new NibbleReader(new Uint8Array(6).fill(0xff)).unsigned(), /UInt32/);
});
