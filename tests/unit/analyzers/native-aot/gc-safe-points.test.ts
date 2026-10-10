import assert from "node:assert/strict";
import { test } from "node:test";
import { readGcSafePointStates } from "../../../../analyzers/native-aot/gc-safe-points.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("reads direct per-safepoint live bit vectors", () => {
  const bytes = new GcInfoBitsFixture().field(0, 1).field(5, 3).field(2, 3).bytes();

  assert.deepEqual(readGcSafePointStates(new GcBitReader(bytes),
    [{ offset: 2, liveSlots: [] }, { offset: 7, liveSlots: [] }], 3), [
    { offset: 2, liveSlots: [0, 2] }, { offset: 7, liveSlots: [1] }
  ]);
});

void test("reads shared indirect live states at byte-aligned relative bit offsets", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).unsigned(2, 3)
    .field(0, 3).field(0, 3).field(0, 5).field(0, 1).field(3, 2).bytes();
  const states = readGcSafePointStates(new GcBitReader(bytes),
    [{ offset: 2, liveSlots: [] }, { offset: 7, liveSlots: [] }], 2);

  assert.deepEqual(states, [{ offset: 2, liveSlots: [0, 1] }, { offset: 7, liveSlots: [0, 1] }]);
  assert.equal(states[0]?.liveSlots, states[1]?.liveSlots);
});

void test("untracked-only methods need no liveness payload and invalid pointers fail bounds checks", () => {
  assert.deepEqual(readGcSafePointStates(new GcBitReader(new Uint8Array()), [{ offset: 1, liveSlots: [] }], 0),
    [{ offset: 1, liveSlots: [] }]);
  assert.throws(() => readGcSafePointStates(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).unsigned(31, 3).field(0xffffffff, 32).bytes()),
  [{ offset: 1, liveSlots: [] }], 1), /truncated/);
});
