import assert from "node:assert/strict";
import test from "node:test";
import { ReadyToRunSignatureCursor } from "../../../../../analyzers/pe/clr/ready-to-run-signature-cursor.js";

void test("R2R signature cursor reads high-bit integers and advances its offset", () => {
  const cursor = new ReadyToRunSignatureCursor(Uint8Array.of(7, 0x81, 2, 0xc1, 2, 3, 4), 0);

  assert.equal(cursor.peek(), 7);
  assert.equal(cursor.unsigned(), 7);
  assert.equal(cursor.unsigned(), 258);
  assert.equal(cursor.unsigned(), 0x01020304);
  assert.equal(cursor.offset, 7);
  assert.equal(cursor.peek(), null);
  assert.throws(() => cursor.byte(), /truncated/);
});

void test("R2R cursor counts cannot exceed available encoded items", () => {
  const valid = new ReadyToRunSignatureCursor(Uint8Array.of(2, 1, 1), 0);
  const invalid = new ReadyToRunSignatureCursor(Uint8Array.of(3, 1, 1), 0);

  assert.equal(valid.count(), 2);
  assert.equal(valid.byte(), 1);
  assert.throws(() => invalid.count(), /count exceeds/);
});

void test("R2R cursor rejects malformed and truncated integers", () => {
  assert.throws(() => new ReadyToRunSignatureCursor(Uint8Array.of(0xe0), 0).unsigned(), /malformed/);
  assert.throws(() => new ReadyToRunSignatureCursor(Uint8Array.of(0x80), 0).unsigned(), /malformed/);
  assert.throws(() => new ReadyToRunSignatureCursor(new Uint8Array(), 0).unsigned(), /malformed/);
});

void test("R2R cursor rejects invalid initial offsets", () => {
  const bytes = Uint8Array.of(1);

  assert.throws(() => new ReadyToRunSignatureCursor(bytes, -1).byte(), /out of bounds/);
  assert.throws(() => new ReadyToRunSignatureCursor(bytes, 0.5).byte(), /out of bounds/);
  assert.throws(() => new ReadyToRunSignatureCursor(bytes, NaN).unsigned(), /offset/);
  assert.throws(() => new ReadyToRunSignatureCursor(bytes, -1).unsigned(), /malformed/);
});
