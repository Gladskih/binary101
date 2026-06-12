"use strict";

import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { operandBits, readOperand, writeOperand } from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
  known,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./emulation-state.js";
import {
  accumulatorName,
  highAccumulatorName,
  writeAccumulatorPair
} from "./emulation-integer-effects.js";
import {
  bitsOrState,
  maskForBits,
  registerValue,
  writeRegisterByName
} from "./emulation-integer-common.js";
import { clearFlags } from "./emulation-flags.js";

export const executeMultiplyDivide = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Mul"]) {
    executeUnsignedAccumulatorMultiply(iced, state, instruction);
    clearFlags(state);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Imul"]) {
    executeSignedMultiply(iced, state, instruction);
    clearFlags(state);
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Div"] && mnemonic !== iced.Mnemonic?.["Idiv"]) return false;
  executeDivide(iced, state, instruction, mnemonic === iced.Mnemonic?.["Idiv"]);
  clearFlags(state);
  return true;
};

const executeSignedMultiply = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => {
  if (instruction.opCount === 1) {
    executeSignedAccumulatorMultiply(iced, state, instruction);
    return;
  }
  const bits = bitsOrState(iced, state, instruction, 0);
  const product = binaryKnown(
    readOperand(iced, state, instruction, instruction.opCount === 2 ? 0 : 1),
    readOperand(iced, state, instruction, instruction.opCount === 2 ? 1 : 2),
    (left, right) => BigInt.asIntN(bits, left) * BigInt.asIntN(bits, right)
  );
  writeOperand(iced, state, instruction, 0, mapKnownValues(product, bits, value => value));
};

const executeSignedAccumulatorMultiply = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeAccumulatorMultiply(iced, state, instruction, (bits, left, right) =>
  BigInt.asIntN(bits, left) * BigInt.asIntN(bits, right)
);

const executeUnsignedAccumulatorMultiply = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeAccumulatorMultiply(iced, state, instruction, (bits, left, right) =>
  BigInt.asUintN(bits, left) * BigInt.asUintN(bits, right)
);

const executeAccumulatorMultiply = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  multiply: (bits: number, left: bigint, right: bigint) => bigint
): void => {
  const bits = operandBits(iced, instruction, 0) ?? state.bitness;
  const product = binaryKnown(
    registerValue(iced, state, accumulatorName(bits)),
    readOperand(iced, state, instruction, 0),
    (left, right) => multiply(bits, left, right)
  );
  writeProductPair(iced, state, bits, product);
};

const writeProductPair = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits,
  product: EmulatedValue
): void => {
  if (bits === 8) {
    writeAccumulatorPair(iced, state, bits, mapKnownValues(product, 16, value => value), UNKNOWN);
    return;
  }
  writeAccumulatorPair(
    iced,
    state,
    bits,
    mapKnownValues(product, bits, value => value & maskForBits(bits)),
    mapKnownValues(product, bits, value => value >> BigInt(bits))
  );
};

const invalidateAccumulatorPair = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits
): void => {
  if (bits === 8) {
    writeRegisterByName(iced, state, "AX", UNKNOWN);
    return;
  }
  writeRegisterByName(iced, state, accumulatorName(bits), UNKNOWN);
  writeRegisterByName(iced, state, highAccumulatorName(bits), UNKNOWN);
};

const executeDivide = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  signed: boolean
): void => {
  const bits = operandBits(iced, instruction, 0) ?? state.bitness;
  const divisor = readOperand(iced, state, instruction, 0);
  const quotientAndRemainder = signed
    ? signedQuotientAndRemainder(iced, state, bits, divisor)
    : unsignedQuotientAndRemainder(iced, state, bits, divisor);
  if (!quotientAndRemainder) {
    invalidateAccumulatorPair(iced, state, bits);
    return;
  }
  writeDivideResult(iced, state, bits, quotientAndRemainder);
};

const writeDivideResult = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits,
  result: { quotient: bigint; remainder: bigint }
): void => {
  if (bits === 8) {
    writeRegisterByName(iced, state, "AL", known(result.quotient, 8));
    writeRegisterByName(iced, state, "AH", known(result.remainder, 8));
    return;
  }
  writeRegisterByName(iced, state, accumulatorName(bits), known(result.quotient, bits));
  writeRegisterByName(iced, state, highAccumulatorName(bits), known(result.remainder, bits));
};

const unsignedQuotientAndRemainder = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits,
  divisor: EmulatedValue
): { quotient: bigint; remainder: bigint } | null => {
  const dividend = unsignedDividend(iced, state, bits);
  if (dividend == null || divisor.kind !== "known" || divisor.value === 0n) return null;
  const quotient = dividend / divisor.value;
  if (quotient > maskForBits(bits)) return null;
  return { quotient, remainder: dividend % divisor.value };
};

const signedQuotientAndRemainder = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits,
  divisor: EmulatedValue
): { quotient: bigint; remainder: bigint } | null => {
  const dividend = signedDividend(iced, state, bits);
  if (dividend == null || divisor.kind !== "known") return null;
  const signedDivisor = BigInt.asIntN(bits, divisor.value);
  if (signedDivisor === 0n) return null;
  const quotient = dividend / signedDivisor;
  if (!signedQuotientFits(quotient, bits)) return null;
  return { quotient, remainder: dividend % signedDivisor };
};

const unsignedDividend = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits
): bigint | null => {
  if (bits === 8) return knownRegisterValue(iced, state, "AX");
  const high = knownRegisterValue(iced, state, highAccumulatorName(bits));
  const low = knownRegisterValue(iced, state, accumulatorName(bits));
  return high == null || low == null ? null : (high << BigInt(bits)) | low;
};

const signedDividend = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits
): bigint | null => {
  const unsigned = unsignedDividend(iced, state, bits);
  return unsigned == null ? null : BigInt.asIntN(bits * 2, unsigned);
};

const knownRegisterValue = (
  iced: IcedModule,
  state: EmulationState,
  name: string
): bigint | null => {
  const value = registerValue(iced, state, name);
  return value.kind === "known" ? value.value : null;
};

const signedQuotientFits = (quotient: bigint, bits: KnownValueBits): boolean => {
  const minimum = -(1n << BigInt(bits - 1));
  const maximum = (1n << BigInt(bits - 1)) - 1n;
  return quotient >= minimum && quotient <= maximum;
};
