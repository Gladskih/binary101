"use strict";

import type { CpuIdOutputRegister } from "../cpuid-notes.js";
import type {
  CanonicalRegister,
  RegisterAccess
} from "./registers.js";

export type KnownValueBits = 8 | 16 | 32 | 64;
export type KnownValue = { kind: "known"; value: bigint; bits: KnownValueBits };
export type CpuFlag = "CF" | "PF" | "AF" | "ZF" | "SF" | "OF" | "DF";
export type EmulationFlags = Partial<Record<CpuFlag, boolean>>;
type UnknownValue = { kind: "unknown" };
type ImportReturnValue = { kind: "import-return"; label: string };
type CpuIdOutputValue = {
  kind: "cpuid-output";
  leaf: number;
  subleaf?: number;
  register: CpuIdOutputRegister;
};
type ValueSetValue = { kind: "value-set"; values: KnownValue[] };

export type EmulatedValue =
  | KnownValue
  | UnknownValue
  | ImportReturnValue
  | CpuIdOutputValue
  | ValueSetValue;

export type EmulationState = {
  bitness: 32 | 64;
  registers: Map<CanonicalRegister, EmulatedValue>;
  memory: Map<string, EmulatedValue>;
  flags: EmulationFlags;
};

export const UNKNOWN: UnknownValue = { kind: "unknown" };
const MAX_VALUE_SET_VALUES = 4;

// Synthetic stack anchors: only relative stack slots matter for this local model.
const STACK_BASE_32 = 0x10000000n;
const STACK_BASE_64 = 0x100000000000n;
type RegisterStorageBits = 32 | 64;

export const known = (value: bigint, bits: KnownValueBits): KnownValue => ({
  kind: "known",
  value: BigInt.asUintN(bits, value),
  bits
});

export const importReturn = (label: string): ImportReturnValue => ({
  kind: "import-return",
  label
});

const knownValueKey = (value: KnownValue): string =>
  `${value.bits}:${value.value.toString(16)}`;

const sameSpecialValue = (left: EmulatedValue, right: EmulatedValue): boolean =>
  (left.kind === "unknown" && right.kind === "unknown") ||
  (left.kind === "import-return" && right.kind === "import-return" && left.label === right.label) ||
  (
    left.kind === "cpuid-output" &&
    right.kind === "cpuid-output" &&
    left.leaf === right.leaf &&
    left.subleaf === right.subleaf &&
    left.register === right.register
  );

export const collectKnownValues = (value: EmulatedValue | undefined): KnownValue[] => {
  if (!value || value.kind === "unknown") return [];
  if (value.kind === "known") return [value];
  return value.kind === "value-set" ? value.values : [];
};

const valueSet = (values: KnownValue[]): EmulatedValue => {
  const out = new Map<string, KnownValue>();
  for (const value of values) out.set(knownValueKey(value), value);
  const merged = Array.from(out.values())
    .sort((left, right) => left.bits - right.bits || (left.value < right.value ? -1 : 1));
  if (merged.length === 0 || merged.length > MAX_VALUE_SET_VALUES) return UNKNOWN;
  return merged.length === 1 ? merged[0] as EmulatedValue : { kind: "value-set", values: merged };
};

export const joinEmulatedValues = (
  left: EmulatedValue | undefined,
  right: EmulatedValue | undefined
): EmulatedValue => {
  if (!left || !right) return UNKNOWN;
  const leftKnownValues = collectKnownValues(left);
  const rightKnownValues = collectKnownValues(right);
  if (leftKnownValues.length || rightKnownValues.length) {
    return leftKnownValues.length && rightKnownValues.length
      ? valueSet([...leftKnownValues, ...rightKnownValues])
      : UNKNOWN;
  }
  return sameSpecialValue(left, right) ? left : UNKNOWN;
};

export const mapKnownValues = (
  value: EmulatedValue,
  bits: KnownValueBits,
  op: (value: bigint, bits: KnownValueBits) => bigint
): EmulatedValue => {
  const values = collectKnownValues(value);
  if (!values.length) return UNKNOWN;
  return valueSet(values.map(candidate => known(op(candidate.value, candidate.bits), bits)));
};

const readKnownValue = (value: KnownValue, access: RegisterAccess): KnownValue =>
  known(value.value >> BigInt(access.bitOffset), access.accessBits);

const readKnownValues = (
  values: KnownValue[],
  access: RegisterAccess
): EmulatedValue =>
  valueSet(values.map(value => readKnownValue(value, access)));

export const readRegister = (
  state: EmulationState,
  access: RegisterAccess | null
): EmulatedValue => {
  if (!access) return UNKNOWN;
  const value = state.registers.get(access.canonical) ?? UNKNOWN;
  if (value.kind === "value-set") return readKnownValues(value.values, access);
  if (value.kind !== "known" && (access.accessBits < 32 || access.bitOffset !== 0)) return UNKNOWN;
  if (value.kind !== "known") return value;
  return readKnownValue(value, access);
};

export const writeRegister = (
  state: EmulationState,
  access: RegisterAccess | null,
  value: EmulatedValue
): void => {
  if (!access) return;
  if (value.kind === "known") {
    writeKnownRegister(state, access, value);
    return;
  }
  if (value.kind === "value-set" && access.accessBits >= 32 && access.bitOffset === 0) {
    writeValueSetRegister(state, access, value);
    return;
  }
  if (access.accessBits < 32) {
    state.registers.set(access.canonical, UNKNOWN);
    return;
  }
  state.registers.set(access.canonical, value);
};

const writeKnownRegister = (
  state: EmulationState,
  access: RegisterAccess,
  value: KnownValue
): void => {
  if (access.accessBits < 32) {
    const current = state.registers.get(access.canonical);
    if (current?.kind !== "known") {
      state.registers.set(access.canonical, UNKNOWN);
      return;
    }
    state.registers.set(
      access.canonical,
      known(replaceBits(current, access, value.value), current.bits)
    );
    return;
  }
  state.registers.set(
    access.canonical,
    known(known(value.value, access.accessBits).value, writeStorageBits(state, access))
  );
};

const writeValueSetRegister = (
  state: EmulationState,
  access: RegisterAccess,
  value: ValueSetValue
): void => {
  const storageBits = writeStorageBits(state, access);
  state.registers.set(
    access.canonical,
    valueSet(value.values.map(candidate =>
      known(known(candidate.value, access.accessBits).value, storageBits)
    ))
  );
};

const writeStorageBits = (
  state: EmulationState,
  access: RegisterAccess
): RegisterStorageBits => {
  if (access.accessBits === 64) return 64;
  return state.bitness === 64 ? 64 : 32;
};

const replaceBits = (
  current: KnownValue,
  access: RegisterAccess,
  value: bigint
): bigint => {
  const accessMask = (1n << BigInt(access.accessBits)) - 1n;
  const shiftedMask = accessMask << BigInt(access.bitOffset);
  return (current.value & ~shiftedMask) |
    ((value & accessMask) << BigInt(access.bitOffset));
};

export const binaryKnown = (
  left: EmulatedValue,
  right: EmulatedValue,
  op: (a: bigint, b: bigint) => bigint
): EmulatedValue => {
  const leftValues = collectKnownValues(left);
  const rightValues = collectKnownValues(right);
  if (!leftValues.length || !rightValues.length) return UNKNOWN;
  if (leftValues.length * rightValues.length > MAX_VALUE_SET_VALUES) return UNKNOWN;
  return valueSet(leftValues.flatMap(leftValue =>
    rightValues.map(rightValue => known(op(leftValue.value, rightValue.value), leftValue.bits))
  ));
};

export const createEmulationState = (bitness: 32 | 64): EmulationState => {
  const registers = new Map<CanonicalRegister, EmulatedValue>();
  registers.set("RSP", known(bitness === 64 ? STACK_BASE_64 : STACK_BASE_32, bitness));
  return { bitness, registers, memory: new Map(), flags: {} };
};

export const cloneEmulationState = (state: EmulationState): EmulationState => ({
  bitness: state.bitness,
  registers: new Map(state.registers),
  memory: new Map(state.memory),
  flags: { ...state.flags }
});

const mergeValueMap = <Key>(
  left: Map<Key, EmulatedValue>,
  right: Map<Key, EmulatedValue>
): Map<Key, EmulatedValue> => {
  const merged = new Map<Key, EmulatedValue>();
  for (const key of new Set([...left.keys(), ...right.keys()])) {
    const value = joinEmulatedValues(left.get(key), right.get(key));
    if (value.kind !== "unknown") merged.set(key, value);
  }
  return merged;
};

export const mergeEmulationStates = (
  left: EmulationState,
  right: EmulationState
): EmulationState => ({
  bitness: left.bitness,
  registers: mergeValueMap(left.registers, right.registers),
  memory: mergeValueMap(left.memory, right.memory),
  flags: mergeFlags(left.flags, right.flags)
});

const mergeFlags = (left: EmulationFlags, right: EmulationFlags): EmulationFlags => {
  const merged: EmulationFlags = {};
  for (const flag of new Set([...Object.keys(left), ...Object.keys(right)]) as Set<CpuFlag>) {
    if (left[flag] === right[flag] && left[flag] != null) merged[flag] = left[flag];
  }
  return merged;
};
