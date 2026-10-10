import assert from "node:assert/strict";
import { test } from "node:test";
import { readGcLiveState } from "../../../../analyzers/native-aot/gc-live-state.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes raw live-slot bits", () => {
  const bytes = new GcInfoBitsFixture().field(0, 1).field(0b10101, 5).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(bytes), 5), [0, 2, 4]);
});

void test("decodes both RLE base selections with initial skip and alternating runs", () => {
  const first = new GcInfoBitsFixture().field(1, 1).field(0, 1).unsigned(2, 4)
    .unsigned(1, 2).unsigned(0, 4).unsigned(0, 2).bytes();
  const second = new GcInfoBitsFixture().field(1, 1).field(1, 1).unsigned(2, 2)
    .unsigned(1, 4).unsigned(0, 2).unsigned(0, 4).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(first), 6), [2, 3, 5]);
  assert.deepEqual(readGcLiveState(new GcBitReader(second), 6), [2, 3, 5]);
});

void test("handles an empty live set, first live slot and out-of-range runs", () => {
  assert.deepEqual(readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 1).unsigned(5, 4).bytes()), 5), []);
  assert.deepEqual(readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 1).unsigned(0, 4).unsigned(0, 2).bytes()), 1), [0]);
  assert.throws(() => readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 1).unsigned(6, 4).bytes()), 5), /slot count/);
  assert.throws(() => readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).field(0, 1).unsigned(0, 4).unsigned(5, 2).bytes()), 5), /slot count/);
});

void test("alternates live and dead runs for more than one pair", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).field(0, 1).unsigned(0, 4)
    .unsigned(0, 2).unsigned(0, 4).unsigned(0, 2).unsigned(0, 4).unsigned(1, 2).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(bytes), 6), [0, 2, 4, 5]);
});
