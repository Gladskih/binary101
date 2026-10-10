import assert from "node:assert/strict";
import { test } from "node:test";
import { readX64GcSlots } from "../../../../analyzers/native-aot/gc-info-x64-slots.js";
import { GcBitReader } from "../../../../analyzers/native-aot/gc-bit-reader.js";
import { GcInfoBitsFixture } from "../../../helpers/gc-info-bits-fixture.js";

void test("decodes register deltas, flagged absolute registers and separate stack groups", () => {
  // The fixture starts at AMD64 register 1, then encodes deltas 2/3/4; stack offsets
  // are pointer-scaled (8-byte slots), so -4 and +2 become -32 and +16.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/inc/gcinfotypes.h
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/vm/gcinfodecoder.cpp
  const bytes = new GcInfoBitsFixture().x64SlotCounts(4, 2, 1)
    .x64Register(1, 0).x64RegisterDelta(2).x64RegisterDelta(3).x64RegisterDelta(4)
    .x64StackSlot(1, -32, 0).x64StackSlotDelta(2, 64)
    .x64StackSlot(0, 16, 3).bytes();

  assert.deepEqual(readX64GcSlots(new GcBitReader(bytes)), [
    { kind: "register", register: 1, flags: 0 }, { kind: "register", register: 3, flags: 0 },
    { kind: "register", register: 6, flags: 0 }, { kind: "register", register: 10, flags: 0 },
    { kind: "stack", base: 1, offset: -32, flags: 0 },
    { kind: "stack", base: 2, offset: 32, flags: 0 },
    { kind: "stack", base: 0, offset: 16, flags: 7 }
  ]);
});

void test("flagged slots reset absolute offsets and flags, and registers reset absolute IDs", () => {
  // Flagged entries switch the delta stream to absolute register/stack values; the
  // exact two signed offsets assert reset behavior across the stack-base groups.
  const bytes = new GcInfoBitsFixture().x64SlotCounts(2, 2, 0)
    .x64Register(1, 1).x64Register(3, 2)
    .x64StackSlot(1, -16, 1).x64StackSlot(2, 24, 2).bytes();

  assert.deepEqual(readX64GcSlots(new GcBitReader(bytes)), [
    { kind: "register", register: 1, flags: 1 }, { kind: "register", register: 3, flags: 2 },
    { kind: "stack", base: 1, offset: -16, flags: 1 },
    { kind: "stack", base: 2, offset: 24, flags: 2 }
  ]);
});

void test("accepts empty slot tables and rejects unknown stack bases", () => {
  assert.deepEqual(readX64GcSlots(new GcBitReader(Uint8Array.of(0))), []);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(0, 1, 0).x64StackSlot(3, 0, 0).bytes())), /base/);
});

void test("rejects register IDs and scaled stack offsets outside AMD64 storage", () => {
  // Runtime GetRegisterSlot explicitly forbids regNum=4 (RSP) as a GC root.
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(1, 0, 0).x64Register(4, 0).bytes())), /register/);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(1, 0, 0).x64Register(16, 0).bytes())), /register/);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(0, 1, 0).x64StackSlot(0, -(2 ** 32), 0).bytes())), /Int32/);
  assert.throws(() => readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(0, 1, 0).x64StackSlot(0, 2 ** 31, 0).bytes())), /Int32/);
  assert.equal(readX64GcSlots(new GcBitReader(new GcInfoBitsFixture()
    .x64SlotCounts(0, 1, 0).x64StackSlot(0, -(2 ** 31), 0).bytes()))[0]?.kind, "stack");
});
