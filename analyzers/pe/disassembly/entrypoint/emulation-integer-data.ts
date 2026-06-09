"use strict";

import type { PeEntrypointInstruction } from "../types.js";
import { describeCpuIdFeatureBits } from "./cpuid-notes.js";
import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { isSameRegisterOperand, readOperand, resolveMemoryAddress, writeOperand } from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
  joinEmulatedValues,
  known,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";
import { bitsOrState, writeMappedOperand, writeBinaryOperand } from "./emulation-integer-common.js";

const appendNotes = (instruction: PeEntrypointInstruction, notes: string[]): void => {
  if (notes.length) instruction.notes = [...(instruction.notes ?? []), ...notes];
};

const collectFeatureNotes = (value: EmulatedValue, mask: EmulatedValue): string[] => {
  if (value.kind !== "cpuid-output" || mask.kind !== "known" || mask.value > 0xffffffffn) return [];
  const bits = Array.from({ length: 32 }, (_, bit) => bit)
    .filter(bit => (mask.value & (1n << BigInt(bit))) !== 0n);
  const note = describeCpuIdFeatureBits(value.leaf, value.subleaf, value.register, bits);
  return note ? [note] : [];
};

const collectBitTestNotes = (value: EmulatedValue, bitIndex: EmulatedValue): string[] => {
  if (value.kind !== "cpuid-output" || bitIndex.kind !== "known" || bitIndex.value > 31n) return [];
  const note = describeCpuIdFeatureBits(
    value.leaf,
    value.subleaf,
    value.register,
    [Number(bitIndex.value)]
  );
  return note ? [note] : [];
};

export const executeDataMovement = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Mov"]) {
    writeOperand(iced, state, instruction, 0, readOperand(iced, state, instruction, 1));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Lea"]) {
    const address = resolveMemoryAddress(iced, state, instruction);
    writeOperand(iced, state, instruction, 0, address == null ? UNKNOWN : known(address, state.bitness));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Movzx"] || mnemonic === iced.Mnemonic?.["Movsx"]) {
    if (mnemonic === iced.Mnemonic?.["Movsx"]) executeSignExtendMove(iced, state, instruction);
    else executeZeroExtendMove(iced, state, instruction);
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Movsxd"]) return false;
  executeSignExtendMove(iced, state, instruction);
  return true;
};

const executeSignExtendMove = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeExtendMove(iced, state, instruction, BigInt.asIntN);

const executeZeroExtendMove = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeExtendMove(iced, state, instruction, BigInt.asUintN);

const executeExtendMove = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  extend: (bits: number, value: bigint) => bigint
): void => {
  const sourceBits = bitsOrState(iced, state, instruction, 1);
  writeOperand(
    iced,
    state,
    instruction,
    0,
    mapKnownValues(
      readOperand(iced, state, instruction, 1),
      bitsOrState(iced, state, instruction, 0),
      value => extend(sourceBits, value)
    )
  );
};

export const executeLogical = (
  iced: IcedModule,
  state: EmulationState,
  rendered: PeEntrypointInstruction,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Xor"] && isSameRegisterOperand(iced, instruction)) {
    writeOperand(iced, state, instruction, 0, known(0n, bitsOrState(iced, state, instruction, 0)));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Xor"]) {
    return executeBinary(iced, state, instruction, (left, right) => left ^ right);
  }
  if (mnemonic === iced.Mnemonic?.["Or"]) return executeBinary(iced, state, instruction, (left, right) => left | right);
  if (mnemonic === iced.Mnemonic?.["And"]) {
    const left = readOperand(iced, state, instruction, 0);
    const right = readOperand(iced, state, instruction, 1);
    appendNotes(rendered, collectFeatureNotes(left, right));
    writeOperand(iced, state, instruction, 0, binaryKnown(left, right, (a, b) => a & b));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Not"]) {
    writeMappedOperand(iced, state, instruction, value => ~value);
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Test"] && mnemonic !== iced.Mnemonic?.["Bt"]) return false;
  appendNotes(rendered, mnemonic === iced.Mnemonic?.["Test"]
    ? collectFeatureNotes(readOperand(iced, state, instruction, 0), readOperand(iced, state, instruction, 1))
    : collectBitTestNotes(readOperand(iced, state, instruction, 0), readOperand(iced, state, instruction, 1)));
  return true;
};

const executeBinary = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  op: (left: bigint, right: bigint) => bigint
): boolean => {
  writeBinaryOperand(iced, state, instruction, op);
  return true;
};

export const executeArithmetic = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Add"]) {
    return executeBinary(iced, state, instruction, (left, right) => left + right);
  }
  if (mnemonic === iced.Mnemonic?.["Sub"]) {
    return executeBinary(iced, state, instruction, (left, right) => left - right);
  }
  if (mnemonic === iced.Mnemonic?.["Inc"]) return executeUnary(iced, state, instruction, value => value + 1n);
  if (mnemonic === iced.Mnemonic?.["Dec"]) return executeUnary(iced, state, instruction, value => value - 1n);
  if (mnemonic === iced.Mnemonic?.["Neg"]) return executeUnary(iced, state, instruction, value => -value);
  if (mnemonic !== iced.Mnemonic?.["Adc"] && mnemonic !== iced.Mnemonic?.["Sbb"]) return false;
  if (mnemonic === iced.Mnemonic?.["Adc"]) executeAdc(iced, state, instruction);
  else executeSbb(iced, state, instruction);
  return true;
};

const executeUnary = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  op: (value: bigint) => bigint
): boolean => {
  writeMappedOperand(iced, state, instruction, op);
  return true;
};

const executeAdc = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeCarryArithmetic(iced, state, instruction, (left, right) => left + right, value => value + 1n);

const executeSbb = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeCarryArithmetic(iced, state, instruction, (left, right) => left - right, value => value - 1n);

const executeCarryArithmetic = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  baseOp: (left: bigint, right: bigint) => bigint,
  carryOp: (value: bigint) => bigint
): void => {
  const base = binaryKnown(
    readOperand(iced, state, instruction, 0),
    readOperand(iced, state, instruction, 1),
    baseOp
  );
  const carry = mapKnownValues(base, bitsOrState(iced, state, instruction, 0), carryOp);
  writeOperand(iced, state, instruction, 0, joinEmulatedValues(base, carry));
};
