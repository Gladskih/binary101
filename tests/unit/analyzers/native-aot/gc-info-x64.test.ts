import assert from "node:assert/strict";
import { test } from "node:test";
import { parseX64GcInfo } from "../../../../analyzers/native-aot/gc-info-x64.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes slim GC v4 safepoints, GC slots and per-call liveness", () => {
  const bytes = new GcInfoBitsFixture().field(0, 2).unsigned(32, 8).unsigned(2, 2)
    .field(4, 5).field(20, 5).field(1, 1).unsigned(1, 2).field(0, 1)
    .unsigned(1, 3).field(1, 2).field(0, 1).field(1, 1).field(0, 1).bytes();

  assert.deepEqual(parseX64GcInfo(bytes, 4), {
    header: { flags: 0, codeLength: 32 },
    safePoints: [{ offset: 4, liveSlots: [0] }, { offset: 20, liveSlots: [] }],
    interruptibleRanges: [], slots: [{ kind: "register", register: 1, flags: 1 }], transitions: []
  });
});

void test("retains v3 encoded safepoint offsets without inventing instruction seeds", () => {
  const bytes = new GcInfoBitsFixture().field(0, 2).field(1, 2).unsigned(8, 8)
    .unsigned(1, 2).field(3, 3).field(0, 2).bytes();

  assert.equal(parseX64GcInfo(bytes, 3)?.safePoints[0]?.offset, 3);
  assert.deepEqual(parseX64GcInfo(bytes, 3)?.safePoints[0]?.liveSlots, []);
});

void test("returns null for unreadable headers and warnings with partial safe points", () => {
  assert.equal(parseX64GcInfo(new Uint8Array(), 4), null);
  const bytes = new GcInfoBitsFixture().field(0, 2).unsigned(32, 8).unsigned(2, 2)
    .field(4, 5).field(2, 5).bytes();
  const result = parseX64GcInfo(bytes, 4);

  assert.equal(result?.safePoints[0]?.offset, 4);
  assert.match(result?.warnings?.join() ?? "", /increasing/);
});

void test("rejects conflicting interruptibility modes and out-of-method ranges", () => {
  const conflict = new GcInfoBitsFixture().field(1, 1).field(0, 10).unsigned(32, 8)
    .unsigned(0, 3).unsigned(1, 2).unsigned(1, 1).bytes();
  const range = new GcInfoBitsFixture().field(1, 1).field(0, 10).unsigned(4, 8)
    .unsigned(0, 3).unsigned(0, 2).unsigned(1, 1).unsigned(3, 6).unsigned(1, 6).bytes();

  assert.match(parseX64GcInfo(conflict, 4)?.warnings?.join() ?? "", /both/);
  assert.match(parseX64GcInfo(range, 4)?.warnings?.join() ?? "", /range/);
});

void test("decodes bounded interruptible ranges and validates safe-point storage", () => {
  const range = new GcInfoBitsFixture().field(1, 1).field(0, 10).unsigned(8, 8)
    .unsigned(0, 3).unsigned(0, 2).unsigned(1, 1).unsigned(2, 6).unsigned(3, 6).field(0, 2).bytes();
  const tooMany = new GcInfoBitsFixture().field(0, 2).unsigned(1, 8).unsigned(2, 2).bytes();
  const outside = new GcInfoBitsFixture().field(0, 2).unsigned(3, 8)
    .unsigned(1, 2).field(3, 2).bytes();

  assert.deepEqual(parseX64GcInfo(range, 4)?.interruptibleRanges, [{ startOffset: 2, endOffset: 6 }]);
  assert.match(parseX64GcInfo(tooMany, 4)?.warnings?.join() ?? "", /count/);
  assert.match(parseX64GcInfo(outside, 4)?.warnings?.join() ?? "", /outside/);
});

void test("retains header failures, repeated safe-point warnings and excludes untracked slots", () => {
  const warnings = new Set<string>();
  assert.equal(parseX64GcInfo(new Uint8Array(), 4, warnings), null);
  assert.match([...warnings].join(), /truncated/);
  const repeated = new GcInfoBitsFixture().field(0, 2).unsigned(4, 8).unsigned(2, 2)
    .field(0, 2).field(0, 2).bytes();
  assert.match(parseX64GcInfo(repeated, 4)?.warnings?.join() ?? "", /increasing/);
  const untracked = new GcInfoBitsFixture().field(0, 2).unsigned(1, 8).unsigned(1, 2)
    .field(0, 1).field(1, 1).unsigned(0, 2).unsigned(1, 1)
    .field(1, 2).signed(0, 6).field(0, 2).bytes();
  const result = parseX64GcInfo(untracked, 4);
  assert.equal(result?.warnings, undefined);
  assert.deepEqual(result?.safePoints, [{ offset: 0, liveSlots: [] }]);
  assert.deepEqual(result?.slots, [{ kind: "stack", base: 1, offset: 0, flags: 4 }]);
});

void test("decodes an interruptible method's tracked-slot transitions without safe-point state bits", () => {
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
