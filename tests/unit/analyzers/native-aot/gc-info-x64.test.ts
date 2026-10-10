import assert from "node:assert/strict";
import { test } from "node:test";
import { parseX64GcInfo } from "../../../../analyzers/native-aot/gc-info-x64.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes slim GC v4 safepoints, GC slots and per-call liveness", () => {
  // Encoded safepoint offsets 4 and 20 each use five bits; the first state marks
  // the only tracked register live and the second leaves it dead.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
  const bytes = new GcInfoBitsFixture().slimX64V4Header(32).safePointCount(2)
    .safePointOffsets(32, 4, 20).x64SlotCounts(1, 0, 0).x64Register(1, 1)
    .directSafePointStates(1, [0], []).bytes();

  assert.deepEqual(parseX64GcInfo(bytes, 4), {
    header: { flags: 0, codeLength: 32 },
    safePoints: [{ offset: 4, liveSlots: [0] }, { offset: 20, liveSlots: [] }],
    interruptibleRanges: [], slots: [{ kind: "register", register: 1, flags: 1 }], transitions: []
  });
});

void test("retains v3 encoded safepoint offsets without inventing instruction seeds", () => {
  const bytes = new GcInfoBitsFixture().slimX64V3Header(1, 8).safePointCount(1)
    .safePointOffsets(8, 3).x64SlotCounts(0, 0, 0).bytes();

  assert.equal(parseX64GcInfo(bytes, 3)?.safePoints[0]?.offset, 3);
  assert.deepEqual(parseX64GcInfo(bytes, 3)?.safePoints[0]?.liveSlots, []);
});

void test("returns null for unreadable headers and warnings with partial safe points", () => {
  assert.equal(parseX64GcInfo(new Uint8Array(), 4), null);
  // The second encoded safe-point offset is deliberately below the first, so the
  // parser must keep the valid prefix and report the ordering anomaly.
  const bytes = new GcInfoBitsFixture().slimX64V4Header(32).safePointCount(2)
    .safePointOffsets(32, 4, 2).bytes();
  const result = parseX64GcInfo(bytes, 4);

  assert.equal(result?.safePoints[0]?.offset, 4);
  assert.match(result?.warnings?.join() ?? "", /increasing/);
});

void test("rejects conflicting interruptibility modes and out-of-method ranges", () => {
  const conflict = new GcInfoBitsFixture().fatX64V4Header(0, 32)
    .x64OutgoingStackBytes(0).safePointCount(1).interruptibleRangeCount(1).bytes();
  const range = new GcInfoBitsFixture().fatX64V4Header(0, 4)
    .x64OutgoingStackBytes(0).safePointCount(0).interruptibleRangeCount(1)
    .x64InterruptibleRange(0, 3, 5).bytes();

  assert.match(parseX64GcInfo(conflict, 4)?.warnings?.join() ?? "", /both/);
  assert.match(parseX64GcInfo(range, 4)?.warnings?.join() ?? "", /range/);
});

void test("decodes bounded interruptible ranges and validates safe-point storage", () => {
  const range = new GcInfoBitsFixture().fatX64V4Header(0, 8).x64OutgoingStackBytes(0)
    .safePointCount(0).interruptibleRangeCount(1)
    .x64InterruptibleRange(0, 2, 6).x64SlotCounts(0, 0, 0).bytes();
  const tooMany = new GcInfoBitsFixture().slimX64V4Header(1).safePointCount(2).bytes();
  const outside = new GcInfoBitsFixture().slimX64V4Header(3).safePointCount(1)
    .safePointOffsets(3, 3).bytes();

  assert.deepEqual(parseX64GcInfo(range, 4)?.interruptibleRanges, [{ startOffset: 2, endOffset: 6 }]);
  assert.match(parseX64GcInfo(tooMany, 4)?.warnings?.join() ?? "", /count/);
  assert.match(parseX64GcInfo(outside, 4)?.warnings?.join() ?? "", /outside/);
});

void test("retains header failures, repeated safe-point warnings and excludes untracked slots", () => {
  const warnings = new Set<string>();
  assert.equal(parseX64GcInfo(new Uint8Array(), 4, warnings), null);
  assert.match([...warnings].join(), /truncated/);
  const repeated = new GcInfoBitsFixture().slimX64V4Header(4).safePointCount(2)
    .safePointOffsets(4, 0, 0).bytes();
  assert.match(parseX64GcInfo(repeated, 4)?.warnings?.join() ?? "", /increasing/);
  const untracked = new GcInfoBitsFixture().slimX64V4Header(1).safePointCount(1)
    .safePointOffsets(1, 0).x64SlotCounts(0, 0, 1).x64StackSlot(1, 0, 0).bytes();
  const result = parseX64GcInfo(untracked, 4);
  assert.equal(result?.warnings, undefined);
  assert.deepEqual(result?.safePoints, [{ offset: 0, liveSlots: [] }]);
  assert.deepEqual(result?.slots, [{ kind: "stack", base: 1, offset: 0, flags: 4 }]);
});

void test("decodes an interruptible method's tracked-slot transitions without safe-point state bits", () => {
  // A 32-byte method is fully interruptible over [0,20); the final transition delta
  // places the slot's live-to-dead change at offset five.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
  const bytes = new GcInfoBitsFixture().field(1, 1).field(0, 10).unsigned(32, 8)
    .unsigned(0, 3).unsigned(0, 2).unsigned(1, 1).unsigned(0, 6).unsigned(19, 6)
    .field(1, 1).unsigned(1, 2).field(0, 1).unsigned(1, 3).field(0, 2)
    .unsigned(1, 3).field(1, 1).field(0, 5)
    .field(0, 1).field(1, 1).field(0, 1).field(1, 1).field(5, 6).field(0, 1).bytes();

  assert.deepEqual(parseX64GcInfo(bytes, 4), {
    header: { flags: 0, codeLength: 32, outgoingStackBytes: 0 },
    slots: [{ kind: "register", register: 1, flags: 0 }], safePoints: [],
    interruptibleRanges: [{ startOffset: 0, endOffset: 20 }],
    transitions: [{ offset: 0, slot: 0, live: true }, { offset: 5, slot: 0, live: false }]
  });
});
