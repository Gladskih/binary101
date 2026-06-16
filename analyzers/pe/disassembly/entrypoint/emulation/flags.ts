"use strict";

import type { IcedModule } from "../iced.js";
import {
  collectKnownValues,
  type CpuFlag,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./state.js";
import { maskForBits } from "./integer/common.js";

const FLAGS: readonly CpuFlag[] = ["CF", "PF", "AF", "ZF", "SF", "OF"];

type Condition =
  | "a"
  | "ae"
  | "b"
  | "be"
  | "e"
  | "g"
  | "ge"
  | "l"
  | "le"
  | "ne"
  | "no"
  | "np"
  | "ns"
  | "o"
  | "p"
  | "s";

const CONDITION_NAMES: readonly { condition: Condition; names: readonly string[] }[] = [
  { condition: "a", names: ["Cmova", "Seta", "Ja"] },
  { condition: "ae", names: ["Cmovae", "Setae", "Jae"] },
  { condition: "b", names: ["Cmovb", "Setb", "Jb"] },
  { condition: "be", names: ["Cmovbe", "Setbe", "Jbe"] },
  { condition: "e", names: ["Cmove", "Sete", "Je"] },
  { condition: "g", names: ["Cmovg", "Setg", "Jg"] },
  { condition: "ge", names: ["Cmovge", "Setge", "Jge"] },
  { condition: "l", names: ["Cmovl", "Setl", "Jl"] },
  { condition: "le", names: ["Cmovle", "Setle", "Jle"] },
  { condition: "ne", names: ["Cmovne", "Setne", "Jne"] },
  { condition: "no", names: ["Cmovno", "Setno", "Jno"] },
  { condition: "np", names: ["Cmovnp", "Setnp", "Jnp"] },
  { condition: "ns", names: ["Cmovns", "Setns", "Jns"] },
  { condition: "o", names: ["Cmovo", "Seto", "Jo"] },
  { condition: "p", names: ["Cmovp", "Setp", "Jp"] },
  { condition: "s", names: ["Cmovs", "Sets", "Js"] }
];

export const clearFlags = (
  state: EmulationState,
  flags: readonly CpuFlag[] = FLAGS
): void => {
  for (const flag of flags) delete state.flags[flag];
};

export const writeKnownFlags = (
  state: EmulationState,
  flags: Partial<Record<CpuFlag, boolean>>
): void => {
  for (const flag of FLAGS) {
    const value = flags[flag];
    if (value != null) state.flags[flag] = value;
  }
};

export const readFlag = (state: EmulationState, flag: CpuFlag): boolean | null =>
  state.flags[flag] ?? null;

const isMnemonic = (iced: IcedModule, mnemonic: number, name: string): boolean =>
  iced.Mnemonic?.[name] === mnemonic;

export const conditionForMnemonic = (
  iced: IcedModule,
  mnemonic: number
): Condition | null =>
  CONDITION_NAMES.find(entry => entry.names.some(name => isMnemonic(iced, mnemonic, name)))
    ?.condition ?? null;

const inverted = (value: boolean | null): boolean | null =>
  value == null ? null : !value;

const andFlags = (
  left: boolean | null,
  right: boolean | null
): boolean | null => {
  if (left === false || right === false) return false;
  return left == null || right == null ? null : true;
};

const orFlags = (
  left: boolean | null,
  right: boolean | null
): boolean | null => {
  if (left === true || right === true) return true;
  return left == null || right == null ? null : false;
};

const equalFlags = (
  left: boolean | null,
  right: boolean | null
): boolean | null =>
  left == null || right == null ? null : left === right;

const differentFlags = (
  left: boolean | null,
  right: boolean | null
): boolean | null =>
  left == null || right == null ? null : left !== right;

export const evaluateCondition = (
  iced: IcedModule,
  mnemonic: number,
  state: EmulationState
): boolean | null => {
  const condition = conditionForMnemonic(iced, mnemonic);
  if (condition == null) return null;
  return evaluateKnownCondition(condition, state);
};

const evaluateKnownCondition = (
  condition: Condition,
  state: EmulationState
): boolean | null => {
  const cf = readFlag(state, "CF");
  const zf = readFlag(state, "ZF");
  const sf = readFlag(state, "SF");
  const of = readFlag(state, "OF");
  const pf = readFlag(state, "PF");
  if (condition === "a") return andFlags(inverted(cf), inverted(zf));
  if (condition === "ae") return inverted(cf);
  if (condition === "b") return cf;
  if (condition === "be") return orFlags(cf, zf);
  if (condition === "e") return zf;
  if (condition === "g") return andFlags(inverted(zf), equalFlags(sf, of));
  if (condition === "ge") return equalFlags(sf, of);
  if (condition === "l") return differentFlags(sf, of);
  if (condition === "le") return orFlags(zf, differentFlags(sf, of));
  if (condition === "ne") return inverted(zf);
  if (condition === "no") return inverted(of);
  if (condition === "np") return inverted(pf);
  if (condition === "ns") return inverted(sf);
  if (condition === "o") return of;
  if (condition === "p") return pf;
  return sf;
};

const knownSingleValue = (value: EmulatedValue): bigint | null => {
  const values = collectKnownValues(value);
  return values.length === 1 ? values[0]?.value ?? null : null;
};

const evenParityLowByte = (value: bigint): boolean => {
  let count = 0;
  for (let bit = 0n; bit < 8n; bit += 1n) {
    if ((value & (1n << bit)) !== 0n) count += 1;
  }
  return count % 2 === 0;
};

const signBitSet = (value: bigint, bits: KnownValueBits): boolean =>
  ((value >> BigInt(bits - 1)) & 1n) !== 0n;

const signedValue = (value: bigint, bits: KnownValueBits): bigint =>
  BigInt.asIntN(bits, BigInt.asUintN(bits, value));

const signedMinimum = (bits: KnownValueBits): bigint =>
  -(1n << BigInt(bits - 1));

const signedMaximum = (bits: KnownValueBits): bigint =>
  (1n << BigInt(bits - 1)) - 1n;

const signedOverflowed = (value: bigint, bits: KnownValueBits): boolean =>
  value < signedMinimum(bits) || value > signedMaximum(bits);

const commonResultFlags = (
  result: bigint,
  bits: KnownValueBits
): Pick<Record<CpuFlag, boolean>, "PF" | "ZF" | "SF"> => {
  const masked = BigInt.asUintN(bits, result);
  return {
    PF: evenParityLowByte(masked),
    ZF: masked === 0n,
    SF: signBitSet(masked, bits)
  };
};

export const writeLogicalFlags = (
  state: EmulationState,
  result: EmulatedValue,
  bits: KnownValueBits
): void => {
  const value = knownSingleValue(result);
  clearFlags(state, ["AF", "PF", "ZF", "SF"]);
  writeKnownFlags(state, { CF: false, OF: false });
  if (value != null) writeKnownFlags(state, commonResultFlags(value, bits));
};

export const writeAddFlags = (
  state: EmulationState,
  bits: KnownValueBits,
  left: EmulatedValue,
  right: EmulatedValue,
  result: EmulatedValue
): void => writeAddWithCarryFlags(state, bits, left, right, false, result);

export const writeAddWithCarryFlags = (
  state: EmulationState,
  bits: KnownValueBits,
  left: EmulatedValue,
  right: EmulatedValue,
  carry: boolean,
  result: EmulatedValue
): void => {
  const leftValue = knownSingleValue(left);
  const rightValue = knownSingleValue(right);
  const resultValue = knownSingleValue(result);
  if (leftValue == null || rightValue == null || resultValue == null) {
    clearFlags(state);
    return;
  }
  const leftMasked = BigInt.asUintN(bits, leftValue);
  const rightMasked = BigInt.asUintN(bits, rightValue);
  const rightWithCarry = rightMasked + (carry ? 1n : 0n);
  const resultMasked = BigInt.asUintN(bits, resultValue);
  writeKnownFlags(state, {
    ...commonResultFlags(resultMasked, bits),
    CF: leftMasked + rightWithCarry > maskForBits(bits),
    AF: ((leftMasked ^ rightWithCarry ^ resultMasked) & 0x10n) !== 0n,
    OF: signedOverflowed(
      signedValue(leftMasked, bits) + signedValue(rightMasked, bits) + (carry ? 1n : 0n),
      bits
    )
  });
};

export const writeSubFlags = (
  state: EmulationState,
  bits: KnownValueBits,
  left: EmulatedValue,
  right: EmulatedValue,
  result: EmulatedValue
): void => writeSubWithBorrowFlags(state, bits, left, right, false, result);

export const writeSubWithBorrowFlags = (
  state: EmulationState,
  bits: KnownValueBits,
  left: EmulatedValue,
  right: EmulatedValue,
  borrow: boolean,
  result: EmulatedValue
): void => {
  const leftValue = knownSingleValue(left);
  const rightValue = knownSingleValue(right);
  const resultValue = knownSingleValue(result);
  if (leftValue == null || rightValue == null || resultValue == null) {
    clearFlags(state);
    return;
  }
  const leftMasked = BigInt.asUintN(bits, leftValue);
  const rightMasked = BigInt.asUintN(bits, rightValue);
  const rightWithBorrow = rightMasked + (borrow ? 1n : 0n);
  const resultMasked = BigInt.asUintN(bits, resultValue);
  writeKnownFlags(state, {
    ...commonResultFlags(resultMasked, bits),
    CF: leftMasked < rightWithBorrow,
    AF: ((leftMasked ^ rightWithBorrow ^ resultMasked) & 0x10n) !== 0n,
    OF: signedOverflowed(
      signedValue(leftMasked, bits) - signedValue(rightMasked, bits) - (borrow ? 1n : 0n),
      bits
    )
  });
};

export const writeBitCarryFlag = (
  state: EmulationState,
  value: EmulatedValue,
  bitIndex: bigint
): void => {
  const knownValue = knownSingleValue(value);
  if (knownValue == null) {
    clearFlags(state, ["CF"]);
    return;
  }
  writeKnownFlags(state, { CF: ((knownValue >> bitIndex) & 1n) !== 0n });
};
