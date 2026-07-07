"use strict";

import {
  UNKNOWN,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./state.js";

type MemoryRange = {
  firstByte: bigint;
  lastByte: bigint;
};

export const movsElementBytes = (bits: KnownValueBits): bigint => BigInt(bits / 8);

export const copyMovsMemory = (
  state: EmulationState,
  source: bigint,
  destination: bigint,
  count: bigint,
  elementBits: KnownValueBits,
  forward: boolean
): void => {
  if (source === destination) return;
  const bytes = movsElementBytes(elementBits);
  if (rangesOverlap(
    stringByteRange(source, count, bytes, forward),
    stringByteRange(destination, count, bytes, forward)
  )) {
    copyOverlappingStringMemory(state, source, destination, count, elementBits, forward);
    return;
  }
  copySparseKnownStringMemory(state, source, destination, count, elementBits, forward);
};

const copyOverlappingStringMemory = (
  state: EmulationState,
  source: bigint,
  destination: bigint,
  count: bigint,
  elementBits: KnownValueBits,
  forward: boolean
): void => {
  if (count > exactOverlapCellBudget(state)) {
    invalidateDestinationRange(state, destination, count, movsElementBytes(elementBits), forward);
    return;
  }
  for (let index = 0n; index < count; index += 1n) {
    const offset = stringOffset(index, movsElementBytes(elementBits), forward);
    writeMemory(
      state,
      destination + offset,
      elementBits,
      readMemory(state, source + offset, elementBits)
    );
  }
};

const exactOverlapCellBudget = (state: EmulationState): bigint =>
  BigInt(Math.max(1, state.memory.size));

// Non-overlapping MOVS can be modeled as a sparse transfer: copy only materialized
// source cells and clear materialized destination cells in range. Unknown bytes
// stay implicit instead of becoming millions of explicit UNKNOWN entries.
const copySparseKnownStringMemory = (
  state: EmulationState,
  source: bigint,
  destination: bigint,
  count: bigint,
  elementBits: KnownValueBits,
  forward: boolean
): void => {
  const copies = Array.from(state.memory.entries())
    .map(([address, value]) => ({
      address: copiedDestinationAddress(address, source, destination, count, elementBits, forward),
      value
    }))
    .filter((copy): copy is { address: bigint; value: EmulatedValue } => copy.address != null);
  invalidateDestinationRange(state, destination, count, movsElementBytes(elementBits), forward);
  for (const copy of copies) writeMemory(state, copy.address, elementBits, copy.value);
};

const copiedDestinationAddress = (
  sourceKey: string,
  source: bigint,
  destination: bigint,
  count: bigint,
  elementBits: KnownValueBits,
  forward: boolean
): bigint | null => {
  const address = parsedMemoryKey(sourceKey);
  if (address == null) return null;
  const bytes = movsElementBytes(elementBits);
  const offset = forward ? address - source : source - address;
  if (offset < 0n || offset % bytes !== 0n) return null;
  const index = offset / bytes;
  return index < count ? destination + stringOffset(index, bytes, forward) : null;
};

const stringOffset = (
  index: bigint,
  bytes: bigint,
  forward: boolean
): bigint => forward ? index * bytes : -index * bytes;

const readMemory = (
  state: EmulationState,
  address: bigint,
  bits: KnownValueBits
): EmulatedValue => coerceMemoryValue(state.memory.get(address.toString()) ?? UNKNOWN, bits);

const writeMemory = (
  state: EmulationState,
  address: bigint,
  bits: KnownValueBits,
  value: EmulatedValue
): void => {
  const stored = coerceMemoryValue(value, bits);
  if (stored.kind === "unknown") state.memory.delete(address.toString());
  else state.memory.set(address.toString(), stored);
};

const coerceMemoryValue = (
  value: EmulatedValue,
  bits: KnownValueBits
): EmulatedValue =>
  value.kind === "known" || value.kind === "value-set"
    ? mapKnownValues(value, bits, data => data)
    : value;

const invalidateDestinationRange = (
  state: EmulationState,
  destination: bigint,
  count: bigint,
  bytes: bigint,
  forward: boolean
): void => {
  const range = stringByteRange(destination, count, bytes, forward);
  for (const key of Array.from(state.memory.keys())) {
    const address = parsedMemoryKey(key);
    if (address != null && containsAddress(range, address)) state.memory.delete(key);
  }
};

const stringByteRange = (
  start: bigint,
  count: bigint,
  bytes: bigint,
  forward: boolean
): MemoryRange => {
  const firstElement = forward ? start : start - (count - 1n) * bytes;
  const lastElement = forward ? start + (count - 1n) * bytes : start;
  return { firstByte: firstElement, lastByte: lastElement + bytes - 1n };
};

const rangesOverlap = (left: MemoryRange, right: MemoryRange): boolean =>
  left.firstByte <= right.lastByte && right.firstByte <= left.lastByte;

const containsAddress = (range: MemoryRange, address: bigint): boolean =>
  address >= range.firstByte && address <= range.lastByte;

const parsedMemoryKey = (key: string): bigint | null => {
  try {
    return BigInt(key);
  } catch {
    return null;
  }
};
