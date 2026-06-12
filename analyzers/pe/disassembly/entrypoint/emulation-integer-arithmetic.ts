"use strict";

import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { readOperand, writeOperand } from "./emulation-operands.js";
import {
  binaryKnown,
  joinEmulatedValues,
  known,
  mapKnownValues,
  type EmulationState
} from "./emulation-state.js";
import { bitsOrState } from "./emulation-integer-common.js";
import {
  clearFlags,
  readFlag,
  writeAddFlags,
  writeAddWithCarryFlags,
  writeSubFlags,
  writeSubWithBorrowFlags
} from "./emulation-flags.js";

export const executeArithmetic = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Add"]) return executeAdd(iced, state, instruction);
  if (mnemonic === iced.Mnemonic?.["Sub"]) return executeSub(iced, state, instruction, true);
  if (mnemonic === iced.Mnemonic?.["Cmp"]) return executeSub(iced, state, instruction, false);
  if (mnemonic === iced.Mnemonic?.["Inc"]) return executeIncDec(iced, state, instruction, 1n);
  if (mnemonic === iced.Mnemonic?.["Dec"]) return executeIncDec(iced, state, instruction, -1n);
  if (mnemonic === iced.Mnemonic?.["Neg"]) return executeNeg(iced, state, instruction);
  if (mnemonic !== iced.Mnemonic?.["Adc"] && mnemonic !== iced.Mnemonic?.["Sbb"]) return false;
  executeCarryArithmetic(iced, state, instruction, mnemonic === iced.Mnemonic?.["Adc"]);
  return true;
};

const executeAdd = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): true => {
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  const result = binaryKnown(left, right, (a, b) => a + b);
  writeOperand(iced, state, instruction, 0, result);
  writeAddFlags(state, bitsOrState(iced, state, instruction, 0), left, right, result);
  return true;
};

const executeSub = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  writeResult: boolean
): true => {
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  const result = binaryKnown(left, right, (a, b) => a - b);
  if (writeResult) writeOperand(iced, state, instruction, 0, result);
  writeSubFlags(state, bitsOrState(iced, state, instruction, 0), left, right, result);
  return true;
};

const executeIncDec = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  delta: 1n | -1n
): true => {
  const bits = bitsOrState(iced, state, instruction, 0);
  const carry = readFlag(state, "CF");
  const left = readOperand(iced, state, instruction, 0);
  const result = mapKnownValues(left, bits, value => value + delta);
  writeOperand(iced, state, instruction, 0, result);
  if (delta === 1n) writeAddFlags(state, bits, left, known(1n, bits), result);
  else writeSubFlags(state, bits, left, known(1n, bits), result);
  if (carry == null) delete state.flags.CF;
  else state.flags.CF = carry;
  return true;
};

const executeNeg = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): true => {
  const bits = bitsOrState(iced, state, instruction, 0);
  const left = known(0n, bits);
  const right = readOperand(iced, state, instruction, 0);
  const result = mapKnownValues(right, bits, value => -value);
  writeOperand(iced, state, instruction, 0, result);
  writeSubFlags(state, bits, left, right, result);
  return true;
};

const executeCarryArithmetic = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  add: boolean
): void => {
  const carry = readFlag(state, "CF");
  if (carry == null) {
    executeUnknownCarryArithmetic(iced, state, instruction, add);
    return;
  }
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  const carryValue = carry ? 1n : 0n;
  const result = binaryKnown(
    left,
    right,
    add ? (a, b) => a + b + carryValue : (a, b) => a - b - carryValue
  );
  writeOperand(iced, state, instruction, 0, result);
  if (add) {
    writeAddWithCarryFlags(
      state,
      bitsOrState(iced, state, instruction, 0),
      left,
      right,
      carry,
      result
    );
  } else {
    writeSubWithBorrowFlags(
      state,
      bitsOrState(iced, state, instruction, 0),
      left,
      right,
      carry,
      result
    );
  }
};

const executeUnknownCarryArithmetic = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  add: boolean
): void => {
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  const base = binaryKnown(left, right, add ? (a, b) => a + b : (a, b) => a - b);
  const carry = mapKnownValues(
    base,
    bitsOrState(iced, state, instruction, 0),
    value => add ? value + 1n : value - 1n
  );
  writeOperand(iced, state, instruction, 0, joinEmulatedValues(base, carry));
  clearFlags(state);
};
