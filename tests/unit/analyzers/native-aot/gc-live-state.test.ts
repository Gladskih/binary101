import assert from "node:assert/strict";
import { test } from "node:test";
import { readGcLiveState } from "../../../../analyzers/native-aot/gc-live-state.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes raw live-slot bits", () => {
  const bytes = new GcInfoBitsFixture().rawLiveSlots(5, [0, 2, 4]).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(bytes), 5), [0, 2, 4]);
});

void test("decodes both RLE base selections with initial skip and alternating runs", () => {
  // Both streams describe six tracked slots with the same live set [2,3,5], using
  // each of the format's RLE base selections and an initial skip of two.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
  const first = new GcInfoBitsFixture().runLengthLiveSlots(4, 2, 2, 1, 1, 1).bytes();
  const second = new GcInfoBitsFixture().runLengthLiveSlots(2, 2, 2, 1, 1, 1).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(first), 6), [2, 3, 5]);
  assert.deepEqual(readGcLiveState(new GcBitReader(second), 6), [2, 3, 5]);
});

void test("handles an empty live set, first live slot and out-of-range runs", () => {
  assert.deepEqual(readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .runLengthLiveSlots(4, 5).bytes()), 5), []);
  assert.deepEqual(readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .runLengthLiveSlots(4, 0, 1).bytes()), 1), [0]);
  assert.throws(() => readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .runLengthLiveSlots(4, 6).bytes()), 5), /slot count/);
  assert.throws(() => readGcLiveState(new GcBitReader(new GcInfoBitsFixture()
    .runLengthLiveSlots(4, 0, 1, 6).bytes()), 5), /slot count/);
});

void test("alternates live and dead runs for more than one pair", () => {
  const bytes = new GcInfoBitsFixture().runLengthLiveSlots(4, 0, 1, 1, 1, 1, 2).bytes();

  assert.deepEqual(readGcLiveState(new GcBitReader(bytes), 6), [0, 2, 4, 5]);
});
