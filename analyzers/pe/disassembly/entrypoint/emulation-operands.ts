"use strict";

import type { IcedModule, IcedInstructionObject } from "./iced.js";
import { collectImmediateOperands } from "./immediate-operands.js";
import {
  type RegisterAccess,
  resolveRegister
} from "./emulation-registers.js";
import {
  UNKNOWN,
  known,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";

const immediateValue = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number
): EmulatedValue => {
  const value = collectImmediateOperands(iced, instruction)
    .find(candidate => candidate.operand === operand)?.value;
  return value == null ? UNKNOWN : known(value, 64);
};

const opKindName = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number
): string | undefined => iced.OpKind[instruction.opKind(operand)];

const isRegisterOperand = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number
): boolean => opKindName(iced, instruction, operand) === "Register";

const isMemoryOperand = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number
): boolean => opKindName(iced, instruction, operand) === "Memory";

const readMemoryAddressRegister = (
  iced: IcedModule,
  state: EmulationState,
  register: number
): EmulatedValue | null => {
  if (register === (iced.Register?.["None"] ?? 0)) return known(0n, state.bitness);
  const access = resolveRegister(iced, register);
  return access ? readRegister(state, access) : null;
};

export const resolveMemoryAddress = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): bigint | null => {
  const baseValue = readMemoryAddressRegister(iced, state, instruction.memoryBase);
  const indexValue = readMemoryAddressRegister(iced, state, instruction.memoryIndex);
  if (baseValue == null || indexValue == null) return null;
  if (baseValue.kind !== "known" || indexValue.kind !== "known") return null;
  return baseValue.value +
    indexValue.value * BigInt(instruction.memoryIndexScale) +
    instruction.memoryDisplacement;
};

export const readOperand = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  operand: number
): EmulatedValue => {
  if (isRegisterOperand(iced, instruction, operand)) {
    return readRegister(state, resolveRegister(iced, instruction.opRegister(operand)));
  }
  if (isMemoryOperand(iced, instruction, operand)) {
    const address = resolveMemoryAddress(iced, state, instruction);
    return address == null ? UNKNOWN : state.memory.get(address.toString()) ?? UNKNOWN;
  }
  return immediateValue(iced, instruction, operand);
};

export const writeOperand = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  operand: number,
  value: EmulatedValue
): void => {
  if (isRegisterOperand(iced, instruction, operand)) {
    writeRegister(state, resolveRegister(iced, instruction.opRegister(operand)), value);
    return;
  }
  if (isMemoryOperand(iced, instruction, operand)) {
    const address = resolveMemoryAddress(iced, state, instruction);
    if (address != null) state.memory.set(address.toString(), value);
  }
};

export const isSameRegisterOperand = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): boolean => {
  if (!isRegisterOperand(iced, instruction, 0) || !isRegisterOperand(iced, instruction, 1)) return false;
  return instruction.opRegister(0) === instruction.opRegister(1);
};

export const resolveStackPointer = (
  iced: IcedModule,
  state: EmulationState
): RegisterAccess | null =>
  resolveRegister(iced, iced.Register?.[state.bitness === 64 ? "RSP" : "ESP"] ?? 0);
