"use strict";

import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { operandBits, readOperand, writeOperand } from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
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

export const executeMultiplyDivide = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Mul"]) {
    executeUnsignedAccumulatorMultiply(iced, state, instruction);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Imul"]) {
    executeSignedMultiply(iced, state, instruction);
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Div"] && mnemonic !== iced.Mnemonic?.["Idiv"]) return false;
  invalidateAccumulatorPair(iced, state, operandBits(iced, instruction, 0) ?? state.bitness);
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
