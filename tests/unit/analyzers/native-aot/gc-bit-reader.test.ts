import assert from "node:assert/strict";
import { test } from "node:test";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("reads little-endian fields across byte boundaries including UInt32", () => {
  const bytes = new GcInfoBitsFixture().field(5, 3).field(0xffffffff, 32).bytes();
  const reader = new GcBitReader(bytes);

  assert.equal(reader.bits(0), 0);
  assert.equal(reader.bits(3), 5);
  assert.equal(reader.bits(32), 0xffffffff);
  assert.equal(reader.position, 35);
  assert.equal(reader.at(0).bits(3), 5);
  assert.equal(reader.position, 35);
});

void test("decodes variable unsigned groups and sign-extended signed groups", () => {
  const bytes = new GcInfoBitsFixture().unsigned(0xffffffff, 6).signed(-2147483648, 6)
    .signed(2147483647, 6).signed(-1, 3).unsigned(0, 2).bytes();
  const reader = new GcBitReader(bytes);

  assert.equal(reader.unsigned(6), 0xffffffff);
  assert.equal(reader.signed(6), -2147483648);
  assert.equal(reader.signed(6), 2147483647);
  assert.equal(reader.signed(3), -1);
  assert.equal(reader.unsigned(2), 0);
});

void test("rejects invalid bit ranges and integers outside the encoded UInt32/Int32", () => {
  assert.throws(() => new GcBitReader(new Uint8Array()).bits(1), /truncated/);
  assert.throws(() => new GcBitReader(new Uint8Array()).at(-1).bits(0), /position/);
  assert.throws(() => new GcBitReader(new Uint8Array()).bits(-1), /width/);
  assert.throws(() => new GcBitReader(new GcInfoBitsFixture().unsigned(2 ** 32, 6).bytes())
    .unsigned(6), /UInt32/);
  assert.throws(() => new GcBitReader(new GcInfoBitsFixture().signed(2 ** 31, 6).bytes())
    .signed(6), /Int32/);
  assert.throws(() => new GcBitReader(new Uint8Array(20).fill(255)).unsigned(3), /width/);
  assert.throws(() => new GcBitReader(new Uint8Array()).unsigned(0), /base/);
  assert.throws(() => new GcBitReader(new Uint8Array()).unsigned(32), /base/);
});

void test("accepts wide pointer fields when their value is exactly representable", () => {
  const reader = new GcBitReader(new GcInfoBitsFixture().field(2 ** 40 + 1, 64).bytes());

  assert.equal(reader.bits(64), 2 ** 40 + 1);
  assert.throws(() => new GcBitReader(new GcInfoBitsFixture().field(2 ** 53, 64).bytes())
    .bits(64), /precision/);
  assert.equal(new GcBitReader(new Uint8Array(200)).bits(1600), 0);
  assert.equal(new GcBitReader(new GcInfoBitsFixture().unsigned(7, 31).bytes()).unsigned(31), 7);
  assert.throws(() => new GcBitReader(new GcInfoBitsFixture().signed(-(2 ** 31) - 1, 6).bytes())
    .signed(6), /Int32/);
});

void test("accepts native-word-width integer groups with redundant zero extension", () => {
  // BitStreamReader decodes in size_t on x64; UInt32 applies to the resulting value,
  // not the number of bits consumed from a non-minimal but readable encoding.
  const bytes = new GcInfoBitsFixture().repeatedField(2, 2, 32).field(0, 2).bytes();

  assert.equal(new GcBitReader(bytes).unsigned(1), 0);
});
