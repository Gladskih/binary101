"use strict";

import type { CpuIdOutputRegister } from "./cpuid-notes.js";
import type {
  CanonicalRegister,
  RegisterAccess
} from "./emulation-registers.js";

type KnownValueBits = 8 | 16 | 32 | 64;
type KnownValue = { kind: "known"; value: bigint; bits: KnownValueBits };
type UnknownValue = { kind: "unknown" };
type CpuIdOutputValue = {
  kind: "cpuid-output";
  leaf: number;
  subleaf?: number;
  register: CpuIdOutputRegister;
};

export type EmulatedValue = KnownValue | UnknownValue | CpuIdOutputValue;

export type EmulationState = {
  bitness: 32 | 64;
  registers: Map<CanonicalRegister, EmulatedValue>;
  memory: Map<string, EmulatedValue>;
};

export const UNKNOWN: UnknownValue = { kind: "unknown" };

// Synthetic stack anchors: only relative stack slots matter for this local model.
const STACK_BASE_32 = 0x10000000n;
const STACK_BASE_64 = 0x100000000000n;
type RegisterStorageBits = 32 | 64;

export const known = (value: bigint, bits: KnownValueBits): KnownValue => ({
  kind: "known",
  value: BigInt.asUintN(bits, value),
  bits
});

export const readRegister = (
  state: EmulationState,
  access: RegisterAccess | null
): EmulatedValue => {
  if (!access) return UNKNOWN;
  const value = state.registers.get(access.canonical) ?? UNKNOWN;
  if (value.kind !== "known" && (access.accessBits < 32 || access.bitOffset !== 0)) return UNKNOWN;
  if (value.kind !== "known") return value;
  return known(value.value >> BigInt(access.bitOffset), access.accessBits);
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
    state.registers.set(access.canonical, known(replaceBits(current, access, value.value), current.bits));
    return;
  }
  state.registers.set(access.canonical, known(value.value, writeStorageBits(state, access)));
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
): EmulatedValue =>
  left.kind === "known" && right.kind === "known" ? known(op(left.value, right.value), left.bits) : UNKNOWN;

export const createEmulationState = (bitness: 32 | 64): EmulationState => {
  const registers = new Map<CanonicalRegister, EmulatedValue>();
  registers.set("RSP", known(bitness === 64 ? STACK_BASE_64 : STACK_BASE_32, bitness));
  return { bitness, registers, memory: new Map() };
};

export const cloneEmulationState = (state: EmulationState): EmulationState => ({
  bitness: state.bitness,
  registers: new Map(state.registers),
  memory: new Map(state.memory)
});
