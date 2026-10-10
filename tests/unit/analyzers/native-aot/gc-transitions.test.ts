import assert from "node:assert/strict";
import { test } from "node:test";
import { readGcTransitions } from "../../../../analyzers/native-aot/gc-transitions.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("reconstructs initial live state from final state and transitions", () => {
  // one chunk, pointer width=1, pointer=1, padding=3, couldBeLive raw=[1],
  // final state=dead; one transition at pseudo offset five, then terminator.
  const bytes = new GcInfoBitsFixture().unsigned(1, 3).field(1, 1).field(0, 3)
    .field(0, 1).field(1, 1).field(0, 1).field(1, 1).field(5, 6).field(0, 1).bytes();

  assert.deepEqual(readGcTransitions(new GcBitReader(bytes),
    [{ startOffset: 10, endOffset: 30 }], 1), [
    { offset: 10, slot: 0, live: true }, { offset: 15, slot: 0, live: false }
  ]);
});

void test("maps pseudo offsets across separated interruptible ranges", () => {
  const bytes = new GcInfoBitsFixture().unsigned(1, 3).field(1, 1).field(0, 3)
    .field(0, 1).field(1, 1).field(1, 1).field(1, 1).field(5, 6).field(0, 1).bytes();

  assert.deepEqual(readGcTransitions(new GcBitReader(bytes),
    [{ startOffset: 10, endOffset: 13 }, { startOffset: 40, endOffset: 50 }], 1), [
    { offset: 42, slot: 0, live: true }
  ]);
});

void test("accepts empty transition tables and rejects non-increasing or out-of-range events", () => {
  assert.deepEqual(readGcTransitions(new GcBitReader(new GcInfoBitsFixture().unsigned(0, 3).bytes()),
    [{ startOffset: 0, endOffset: 1 }], 1), []);
  assert.throws(() => readGcTransitions(new GcBitReader(new GcInfoBitsFixture()
    .unsigned(1, 3).field(1, 1).field(0, 3).field(0, 1).field(1, 1).field(1, 1)
    .field(1, 1).field(5, 6).field(1, 1).field(5, 6).field(0, 1).bytes()),
  [{ startOffset: 0, endOffset: 10 }], 1), /increasing/);
  assert.throws(() => readGcTransitions(new GcBitReader(new GcInfoBitsFixture()
    .unsigned(1, 3).field(1, 1).field(0, 3).field(0, 1).field(1, 1).field(1, 1)
    .field(1, 1).field(5, 6).field(0, 1).bytes()),
  [{ startOffset: 0, endOffset: 4 }], 1), /range/);
});

void test("preserves state across empty chunks and reuses shared chunk payloads", () => {
  // Three chunks share one payload at bit offset 0; the middle chunk has no transitions.
  const bytes = new GcInfoBitsFixture().unsigned(1, 3).field(1, 1).field(0, 1).field(1, 1)
    .field(0, 1).field(0, 1).field(1, 1).field(1, 1).field(0, 1).bytes();

  assert.deepEqual(readGcTransitions(new GcBitReader(bytes),
    [{ startOffset: 0, endOffset: 192 }], 1), [{ offset: 0, slot: 0, live: true }]);
});

void test("maps events exactly at range boundaries and sorts changes from different slots", () => {
  const bytes = new GcInfoBitsFixture().unsigned(1, 3).field(1, 1).field(0, 3)
    .field(0, 1).field(3, 2).field(3, 2)
    .field(1, 1).field(9, 6).field(0, 1).field(1, 1).field(2, 6).field(0, 1).bytes();

  assert.deepEqual(readGcTransitions(new GcBitReader(bytes),
    [{ startOffset: 10, endOffset: 12 }, { startOffset: 30, endOffset: 32 },
      { startOffset: 50, endOffset: 60 }], 2), [
    { offset: 30, slot: 1, live: true }, { offset: 55, slot: 0, live: true }
  ]);
  assert.throws(() => readGcTransitions(new GcBitReader(bytes),
    [{ startOffset: 0, endOffset: 9 }], 2), /outside/);
});

void test("places transitions in subsequent chunks and decodes shared bytes only once", () => {
  const bytes = new GcInfoBitsFixture().unsigned(1, 3).field(1, 1).field(1, 1).field(0, 2)
    .field(0, 1).field(1, 1).field(1, 1).field(1, 1).field(5, 6).field(0, 1).bytes();
  const reader = new GcBitReader(bytes);
  const access = test.mock.method(reader, "at");

  assert.deepEqual(readGcTransitions(reader, [{ startOffset: 0, endOffset: 128 }], 1), [
    { offset: 5, slot: 0, live: true }, { offset: 64, slot: 0, live: false },
    { offset: 69, slot: 0, live: true }
  ]);
  assert.equal(access.mock.calls.length, 1);
  assert.equal(reader.position, 6);
});
