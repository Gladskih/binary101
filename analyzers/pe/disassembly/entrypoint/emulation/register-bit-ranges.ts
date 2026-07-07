"use strict";

import type { KnownValueBits } from "./state.js";
import type { RegisterAccess } from "./registers.js";

export type RegisterStorageBits = 32 | 64;

export type PartialKnownValue = {
  kind: "partial-known";
  value: bigint;
  mask: bigint;
  bits: RegisterStorageBits;
};

export const bitMask = (bits: KnownValueBits | RegisterStorageBits): bigint =>
  (1n << BigInt(bits)) - 1n;

export const accessMask = (access: RegisterAccess): bigint =>
  bitMask(access.accessBits) << BigInt(access.bitOffset);

export const readPartialKnownBits = (
  value: PartialKnownValue,
  access: RegisterAccess
): bigint | null => {
  const mask = accessMask(access);
  if ((value.mask & mask) !== mask) return null;
  return (value.value & mask) >> BigInt(access.bitOffset);
};

export const replaceRegisterBits = (
  currentValue: bigint,
  access: RegisterAccess,
  value: bigint
): bigint => {
  const mask = accessMask(access);
  return (currentValue & ~mask) | ((value << BigInt(access.bitOffset)) & mask);
};
