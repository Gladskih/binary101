import assert from "node:assert/strict";
import { test } from "node:test";
import { readX64GcSlots } from "../../../../analyzers/native-aot/gc-info-x64-slots.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes register deltas, flagged absolute registers and separate stack groups", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).unsigned(4, 2)
    .field(1, 1).unsigned(2, 2).unsigned(1, 1)
    .unsigned(1, 3).field(0, 2).unsigned(1, 2).unsigned(2, 2).unsigned(3, 2)
    .field(1, 2).signed(-4, 6).field(0, 2).field(2, 2).unsigned(8, 4)
    .field(0, 2).signed(2, 6).field(3, 2).bytes();

  assert.deepEqual(readX64GcSlots(new GcBitReader(bytes)), [
    { kind: "register", register: 1, flags: 0 }, { kind: "register", register: 3, flags: 0 },
    { kind: "register", register: 6, flags: 0 }, { kind: "register", register: 10, flags: 0 },
    { kind: "stack", base: 1, offset: -32, flags: 0 },
    { kind: "stack", base: 2, offset: 32, flags: 0 },
    { kind: "stack", base: 0, offset: 16, flags: 7 }
  ]);
});

void test("flagged slots reset absolute offsets and flags, and registers reset absolute IDs", () => {
  const bytes = new GcInfoBitsFixture().field(1, 1).unsigned(2, 2)
    .field(1, 1).unsigned(2, 2).unsigned(0, 1)
    .unsigned(1, 3).field(1, 2).unsigned(3, 3).field(2, 2)
    .field(1, 2).signed(-2, 6).field(1, 2).field(2, 2).signed(3, 6).field(2, 2).bytes();

  assert.deepEqual(readX64GcSlots(new GcBitReader(bytes)), [
    { kind: "register", register: 1, flags: 1 }, { kind: "register", register: 3, flags: 2 },
    { kind: "stack", base: 1, offset: -16, flags: 1 },
    { kind: "stack", base: 2, offset: 24, flags: 2 }
  ]);
});

void test("accepts empty slot tables and rejects unknown stack bases", () => {
  assert.deepEqual(readX64GcSlots(new GcBitReader(Uint8Array.of(0))), []);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .field(0, 1).field(1, 1).unsigned(1, 2).unsigned(0, 1)
    .field(3, 2).signed(0, 6).field(0, 2).bytes())), /base/);
});

void test("rejects register IDs and scaled stack offsets outside AMD64 storage", () => {
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .field(1, 1).unsigned(1, 2).field(0, 1).unsigned(16, 3).field(0, 2).bytes())), /register/);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .field(0, 1).field(1, 1).unsigned(1, 2).unsigned(0, 1).field(0, 2)
    .signed(-(2 ** 29), 6).field(0, 2).bytes())), /Int32/);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .field(0, 1).field(1, 1).unsigned(1, 2).unsigned(0, 1).field(0, 2)
    .signed(2 ** 28, 6).field(0, 2).bytes())), /Int32/);
  assert.equal(readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .field(0, 1).field(1, 1).unsigned(1, 2).unsigned(0, 1).field(0, 2)
    .signed(-(2 ** 28), 6).field(0, 2).bytes()))[0]?.kind, "stack");
});
