"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { copyMovsMemory } from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/movs-memory-copy.js";
import {
  collectKnownValues,
  createEmulationState,
  importReturn,
  joinEmulatedValues,
  known,
  type EmulationState,
  type KnownValueBits
} from "../../../../../../../analyzers/pe/disassembly/entrypoint/emulation/state.js";
import {
  bitsOf, bytesOf, distantFixtureDestination, fixtureAddressPair, fixtureValue, lowBits,
  sparseElementCount
} from "../../../../../../helpers/pe-entrypoint-emulation-values.js";

const IMPORT_LABEL = "fixture import return";

const sourceBase = (): bigint => fixtureAddressPair().source;

const destinationBase = (): bigint => distantFixtureDestination();

const byteValue = (slot: number): bigint => fixtureValue(slot, bitsOf("UInt8"));

const dwordValue = (slot: number): bigint => fixtureValue(slot, bitsOf("UInt32"));

const qwordValue = (slot: number): bigint => fixtureValue(slot, bitsOf("UInt64"));

// 64-bit mode matches the PE entrypoint emulator state used by MOVS integration tests.
const createX64State = (): EmulationState => createEmulationState(64);

const setMemory = (
  state: EmulationState,
  address: bigint,
  value: bigint,
  bits: KnownValueBits
): void => {
  state.memory.set(address.toString(), known(value, bits));
};

const expectKnownMemory = (
  state: EmulationState,
  address: bigint,
  value: bigint,
  bits: KnownValueBits
): void => {
  assert.deepEqual(state.memory.get(address.toString()), { kind: "known", value, bits });
};

void test("copyMovsMemory leaves zero-count moves unchanged", () => {
  const state = createX64State();
  const source = sourceBase();
  const destination = destinationBase();
  const staleValue = dwordValue(1);

  setMemory(state, destination, staleValue, bitsOf("UInt32"));
  copyMovsMemory(state, source, destination, 0n, bitsOf("UInt32"), true);

  expectKnownMemory(state, destination, staleValue, bitsOf("UInt32"));
});

void test("copyMovsMemory leaves same-source moves unchanged", () => {
  const state = createX64State();
  const source = sourceBase();
  const staleValue = dwordValue(2);

  setMemory(state, source, staleValue, bitsOf("UInt32"));
  copyMovsMemory(state, source, source, sparseElementCount(), bitsOf("UInt32"), true);

  expectKnownMemory(state, source, staleValue, bitsOf("UInt32"));
});

void test("copyMovsMemory sparsely copies only aligned cells inside the source range", () => {
  const state = createX64State();
  const source = sourceBase();
  const destination = destinationBase();
  const count = sparseElementCount();
  const wideSourceValue = qwordValue(1);
  const ignoredValue = dwordValue(3);
  const lastValue = dwordValue(4);
  const staleValue = dwordValue(5);
  const middleOffset = (count / 2n) * bytesOf("UInt32");
  const lastOffset = (count - 1n) * bytesOf("UInt32");
  const afterOffset = count * bytesOf("UInt32");
  const finalByteOffset = afterOffset - bytesOf("UInt8");

  setMemory(state, source, wideSourceValue, bitsOf("UInt64"));
  setMemory(state, source + bytesOf("UInt8"), ignoredValue, bitsOf("UInt32"));
  setMemory(state, source - bytesOf("UInt32"), ignoredValue, bitsOf("UInt32"));
  setMemory(state, source + lastOffset, lastValue, bitsOf("UInt32"));
  setMemory(state, source + afterOffset, ignoredValue, bitsOf("UInt32"));
  setMemory(state, destination, staleValue, bitsOf("UInt32"));
  setMemory(state, destination + middleOffset, staleValue, bitsOf("UInt32"));
  setMemory(state, destination + lastOffset, staleValue, bitsOf("UInt32"));
  setMemory(
    state,
    destination + finalByteOffset,
    lowBits(staleValue, bitsOf("UInt8")),
    bitsOf("UInt8")
  );
  setMemory(state, destination + afterOffset, staleValue, bitsOf("UInt32"));

  copyMovsMemory(state, source, destination, count, bitsOf("UInt32"), true);

  expectKnownMemory(
    state,
    destination,
    lowBits(wideSourceValue, bitsOf("UInt32")),
    bitsOf("UInt32")
  );
  expectKnownMemory(state, destination + lastOffset, lastValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination + afterOffset, staleValue, bitsOf("UInt32"));
  assert.equal(state.memory.get((destination - bytesOf("UInt32")).toString()), undefined);
  assert.equal(state.memory.get((destination + middleOffset).toString()), undefined);
  assert.equal(state.memory.get((destination + finalByteOffset).toString()), undefined);
  assert.ok(BigInt(state.memory.size) < count);
});

void test("copyMovsMemory preserves sparse values that are not plain known integers", () => {
  const state = createX64State();
  const source = sourceBase();
  const destination = destinationBase();
  const firstValue = qwordValue(2);
  const secondValue = qwordValue(3);
  const alternatives = joinEmulatedValues(
    known(firstValue, bitsOf("UInt64")),
    known(secondValue, bitsOf("UInt64"))
  );

  state.memory.set(source.toString(), importReturn(IMPORT_LABEL));
  state.memory.set((source + bytesOf("UInt8")).toString(), alternatives);
  copyMovsMemory(state, source, destination, BigInt(state.memory.size), bitsOf("UInt8"), true);

  assert.deepEqual(state.memory.get(destination.toString()), importReturn(IMPORT_LABEL));
  assert.deepEqual(
    collectKnownValues(state.memory.get((destination + bytesOf("UInt8")).toString()))
      .map(value => value.value),
    [lowBits(firstValue, bitsOf("UInt8")), lowBits(secondValue, bitsOf("UInt8"))]
  );
});

void test("copyMovsMemory sparsely copies backward ranges and clears bounds", () => {
  const state = createX64State();
  const source = sourceBase();
  const destination = destinationBase();
  // Three dwords cover first, middle, and last positions in a backward sparse range.
  const count = 3n;
  const startOffset = bytesOf("UInt32") * (count - 1n);
  const sourceStart = source + startOffset;
  const destinationStart = destination + startOffset;
  const firstValue = dwordValue(6);
  const lastValue = dwordValue(7);
  const staleValue = dwordValue(8);

  setMemory(state, sourceStart, firstValue, bitsOf("UInt32"));
  setMemory(state, source, lastValue, bitsOf("UInt32"));
  setMemory(state, destinationStart, staleValue, bitsOf("UInt32"));
  setMemory(state, destination + bytesOf("UInt32"), staleValue, bitsOf("UInt32"));
  setMemory(state, destination, staleValue, bitsOf("UInt32"));
  setMemory(state, destination - bytesOf("UInt32"), staleValue, bitsOf("UInt32"));
  copyMovsMemory(state, sourceStart, destinationStart, count, bitsOf("UInt32"), false);

  expectKnownMemory(state, destinationStart, firstValue, bitsOf("UInt32"));
  expectKnownMemory(state, destination, lastValue, bitsOf("UInt32"));
  assert.equal(state.memory.get((destination + bytesOf("UInt32")).toString()), undefined);
  expectKnownMemory(state, destination - bytesOf("UInt32"), staleValue, bitsOf("UInt32"));
});

void test("copyMovsMemory preserves forward overlap instruction order", () => {
  const state = createX64State();
  const source = sourceBase();
  // Three byte moves are the smallest forward-overlap case where the value cascades twice.
  const count = 3n;
  const firstValue = byteValue(1);
  const secondValue = byteValue(2);
  const thirdValue = byteValue(3);
  const thirdOffset = bytesOf("UInt8") * 2n;
  const afterOffset = bytesOf("UInt8") * count;

  setMemory(state, source, firstValue, bitsOf("UInt8"));
  setMemory(state, source + bytesOf("UInt8"), secondValue, bitsOf("UInt8"));
  setMemory(state, source + thirdOffset, thirdValue, bitsOf("UInt8"));
  copyMovsMemory(state, source, source + bytesOf("UInt8"), count, bitsOf("UInt8"), true);

  expectKnownMemory(state, source + bytesOf("UInt8"), firstValue, bitsOf("UInt8"));
  expectKnownMemory(state, source + thirdOffset, firstValue, bitsOf("UInt8"));
  expectKnownMemory(state, source + afterOffset, firstValue, bitsOf("UInt8"));
  assert.equal(
    state.memory.get((source + afterOffset + bytesOf("UInt8")).toString()),
    undefined
  );
});

void test("copyMovsMemory preserves boundary-overlap instruction order", () => {
  const state = createX64State();
  const source = sourceBase();
  // Three byte moves make destination start at the last source cell and still extend past it.
  const count = 3n;
  const firstValue = byteValue(4);
  const secondValue = byteValue(5);
  const thirdValue = byteValue(6);
  const thirdOffset = bytesOf("UInt8") * 2n;

  setMemory(state, source, firstValue, bitsOf("UInt8"));
  setMemory(state, source + bytesOf("UInt8"), secondValue, bitsOf("UInt8"));
  setMemory(state, source + thirdOffset, thirdValue, bitsOf("UInt8"));
  copyMovsMemory(state, source, source + thirdOffset, count, bitsOf("UInt8"), true);

  expectKnownMemory(state, source + thirdOffset + bytesOf("UInt8"), secondValue, bitsOf("UInt8"));
  expectKnownMemory(state, source + thirdOffset + thirdOffset, firstValue, bitsOf("UInt8"));
});

void test("copyMovsMemory invalidates large overlapping moves", () => {
  const state = createX64State();
  const source = sourceBase();
  const firstValue = byteValue(7);
  const staleValue = byteValue(8);
  const outsideRange = source + sparseElementCount() * bytesOf("UInt8");

  setMemory(state, source, firstValue, bitsOf("UInt8"));
  setMemory(state, source + bytesOf("UInt8"), staleValue, bitsOf("UInt8"));
  setMemory(state, outsideRange, staleValue, bitsOf("UInt8"));
  const count = BigInt(state.memory.size) + 1n;

  copyMovsMemory(state, source, source + bytesOf("UInt8"), count, bitsOf("UInt8"), true);

  expectKnownMemory(state, source, firstValue, bitsOf("UInt8"));
  assert.equal(state.memory.get((source + bytesOf("UInt8")).toString()), undefined);
  expectKnownMemory(state, outsideRange, staleValue, bitsOf("UInt8"));
});

void test("copyMovsMemory invalidates boundary-overlap before source", () => {
  const state = createX64State();
  const source = sourceBase();
  const firstValue = byteValue(9);

  setMemory(state, source, firstValue, bitsOf("UInt8"));
  const count = BigInt(state.memory.size) + 1n;
  const destination = source - bytesOf("UInt8") * (count - 1n);
  copyMovsMemory(state, source, destination, count, bitsOf("UInt8"), true);

  assert.equal(state.memory.get(destination.toString()), undefined);
});

void test("copyMovsMemory copies non-overlap ranges before source", () => {
  const state = createX64State();
  const source = sourceBase();
  const firstValue = byteValue(10);

  setMemory(state, source, firstValue, bitsOf("UInt8"));
  const count = BigInt(state.memory.size) + 1n;
  const destination = source - bytesOf("UInt8") * count;
  copyMovsMemory(state, source, destination, count, bitsOf("UInt8"), true);

  expectKnownMemory(state, destination, firstValue, bitsOf("UInt8"));
});

void test("copyMovsMemory deletes stale overlap destinations when source is unknown", () => {
  const state = createX64State();
  const source = sourceBase();
  const staleValue = byteValue(11);
  const thirdOffset = bytesOf("UInt8") * 2n;

  setMemory(state, source + bytesOf("UInt8"), staleValue, bitsOf("UInt8"));
  setMemory(state, source + thirdOffset, staleValue, bitsOf("UInt8"));
  const count = BigInt(state.memory.size);
  copyMovsMemory(
    state, source, source + bytesOf("UInt8"), count, bitsOf("UInt8"), true
  );

  assert.equal(state.memory.get((source + bytesOf("UInt8")).toString()), undefined);
  assert.equal(state.memory.get((source + thirdOffset).toString()), undefined);
});
