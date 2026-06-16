"use strict";

import type { IcedInstructionObject, IcedModule } from "../../iced.js";
import { readOperand, writeOperand } from "../operands.js";
import {
  UNKNOWN,
  collectKnownValues,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "../state.js";
import {
  isAnyMnemonic,
  maskForBits
} from "./common.js";
import {
  clearFlags,
  readFlag,
  writeKnownFlags
} from "../flags.js";

type RotateResult = {
  carry: boolean;
  value: bigint;
};

// Intel SDM Vol. 2 RCL/RCR/ROL/ROR defines 5-bit counts, or 6-bit counts for
// 64-bit operands, and through-carry rotation rings of operand size plus CF.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const countMask = (bits: KnownValueBits): bigint => bits === 64 ? 0x3fn : 0x1fn;

const rotateLeft = (value: bigint, bits: KnownValueBits, count: bigint): bigint => {
  const maskedCount = count % BigInt(bits);
  if (maskedCount === 0n) return value;
  return ((value << maskedCount) | (value >> (BigInt(bits) - maskedCount))) & maskForBits(bits);
};

const rotateRight = (value: bigint, bits: KnownValueBits, count: bigint): bigint => {
  const maskedCount = count % BigInt(bits);
  if (maskedCount === 0n) return value;
  return ((value >> maskedCount) | (value << (BigInt(bits) - maskedCount))) & maskForBits(bits);
};

const rotateThroughCarryCount = (
  bits: KnownValueBits,
  maskedCount: bigint
): bigint => {
  if (bits === 8) return maskedCount % 9n;
  if (bits === 16) return maskedCount % 17n;
  return maskedCount;
};

const rotateThroughCarry = (
  value: bigint,
  bits: KnownValueBits,
  carry: boolean,
  rotate: (combined: bigint, ringBits: bigint, ringMask: bigint) => bigint
): RotateResult => {
  const ringBits = BigInt(bits + 1);
  const ringMask = (1n << ringBits) - 1n;
  const combined = (value & maskForBits(bits)) | ((carry ? 1n : 0n) << BigInt(bits));
  const rotated = rotate(combined, ringBits, ringMask);
  return {
    carry: ((rotated >> BigInt(bits)) & 1n) !== 0n,
    value: rotated & maskForBits(bits)
  };
};

const rotateThroughCarryLeft = (
  value: bigint,
  bits: KnownValueBits,
  count: bigint,
  carry: boolean
): RotateResult => rotateThroughCarry(value, bits, carry, (combined, ringBits, ringMask) =>
  ((combined << count) | (combined >> (ringBits - count))) & ringMask
);

const rotateThroughCarryRight = (
  value: bigint,
  bits: KnownValueBits,
  count: bigint,
  carry: boolean
): RotateResult => rotateThroughCarry(value, bits, carry, (combined, ringBits, ringMask) =>
  ((combined >> count) | (combined << (ringBits - count))) & ringMask
);

const rotateThroughCarryByMnemonic = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  value: bigint,
  bits: KnownValueBits,
  count: bigint,
  carry: boolean
): RotateResult =>
  instruction.mnemonic === iced.Mnemonic?.["Rcl"]
    ? rotateThroughCarryLeft(value, bits, count, carry)
    : rotateThroughCarryRight(value, bits, count, carry);

const commonBoolean = (values: readonly boolean[]): boolean | null => {
  if (!values.length) return null;
  return values.every(value => value === values[0]) ? values[0] ?? null : null;
};

const rotateOverflow = (
  iced: IcedModule,
  mnemonic: number,
  bits: KnownValueBits,
  result: RotateResult
): boolean => {
  const mostSignificant = ((result.value >> BigInt(bits - 1)) & 1n) !== 0n;
  if (mnemonic === iced.Mnemonic?.["Rcr"]) {
    return mostSignificant !== (((result.value >> BigInt(bits - 2)) & 1n) !== 0n);
  }
  return mostSignificant !== result.carry;
};

const writeRotateFlags = (
  iced: IcedModule,
  state: EmulationState,
  mnemonic: number,
  bits: KnownValueBits,
  maskedCount: bigint,
  results: readonly RotateResult[]
): void => {
  const carry = commonBoolean(results.map(result => result.carry));
  if (carry == null) clearFlags(state, ["CF"]);
  else writeKnownFlags(state, { CF: carry });
  if (maskedCount !== 1n) {
    clearFlags(state, ["OF"]);
    return;
  }
  const overflow = commonBoolean(results.map(result =>
    rotateOverflow(iced, mnemonic, bits, result)
  ));
  if (overflow == null) clearFlags(state, ["OF"]);
  else writeKnownFlags(state, { OF: overflow });
};

const writeUnknownRotateThroughCarry = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  effectiveCount: bigint
): void => {
  if (effectiveCount !== 0n) writeOperand(iced, state, instruction, 0, UNKNOWN);
  clearFlags(state, ["CF", "OF"]);
};

const collectRotateThroughCarryResults = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  bits: KnownValueBits,
  count: bigint,
  carry: boolean,
  source: EmulatedValue
): RotateResult[] => collectKnownValues(source).map(value =>
  rotateThroughCarryByMnemonic(iced, instruction, value.value, bits, count, carry)
);

const executeRotateThroughCarry = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bits: KnownValueBits,
  maskedCount: bigint
): true => {
  const effectiveCount = rotateThroughCarryCount(bits, maskedCount);
  const carry = readFlag(state, "CF");
  if (maskedCount === 0n) return true;
  if (carry == null) {
    writeUnknownRotateThroughCarry(iced, state, instruction, effectiveCount);
    return true;
  }
  if (effectiveCount === 0n) {
    clearFlags(state, ["OF"]);
    return true;
  }
  const source = readOperand(iced, state, instruction, 0);
  const results = collectRotateThroughCarryResults(
    iced,
    instruction,
    bits,
    effectiveCount,
    carry,
    source
  );
  writeOperand(
    iced,
    state,
    instruction,
    0,
    mapKnownValues(source, bits, value =>
      rotateThroughCarryByMnemonic(iced, instruction, value, bits, effectiveCount, carry).value
    )
  );
  writeRotateFlags(iced, state, instruction.mnemonic, bits, maskedCount, results);
  return true;
};

const plainLeftRotateCarry = (value: bigint): boolean => (value & 1n) !== 0n;

const plainRightRotateCarry = (
  value: bigint,
  bits: KnownValueBits
): boolean => ((value >> BigInt(bits - 1)) & 1n) !== 0n;

const executePlainRotate = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bits: KnownValueBits,
  maskedCount: bigint
): true => {
  if (maskedCount === 0n) return true;
  const source = readOperand(iced, state, instruction, 0);
  const effectiveCount = maskedCount % BigInt(bits);
  const resultValue = (value: bigint): bigint =>
    instruction.mnemonic === iced.Mnemonic?.["Rol"]
      ? rotateLeft(value, bits, effectiveCount)
      : rotateRight(value, bits, effectiveCount);
  if (effectiveCount !== 0n) {
    writeOperand(iced, state, instruction, 0, mapKnownValues(source, bits, resultValue));
  }
  const results = collectKnownValues(source).map(value => {
    const rotated = resultValue(value.value);
    return {
      carry: instruction.mnemonic === iced.Mnemonic?.["Rol"]
        ? plainLeftRotateCarry(rotated)
        : plainRightRotateCarry(rotated, bits),
      value: rotated
    };
  });
  writeRotateFlags(iced, state, instruction.mnemonic, bits, maskedCount, results);
  return true;
};

export const isRotateInstruction = (
  iced: IcedModule,
  mnemonic: number
): boolean => isAnyMnemonic(iced, mnemonic, ["Rol", "Ror", "Rcl", "Rcr"]);

export const executeRotate = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bits: KnownValueBits,
  count: EmulatedValue
): true => {
  if (count.kind !== "known") {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    clearFlags(state, ["CF", "OF"]);
    return true;
  }
  const maskedCount = count.value & countMask(bits);
  if (isAnyMnemonic(iced, instruction.mnemonic, ["Rcl", "Rcr"])) {
    return executeRotateThroughCarry(iced, state, instruction, bits, maskedCount);
  }
  return executePlainRotate(iced, state, instruction, bits, maskedCount);
};
