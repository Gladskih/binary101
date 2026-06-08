"use strict";

import type { IcedModule, IcedInstructionObject } from "./iced.js";
import { collectImmediateOperands } from "./immediate-operands.js";
import {
  type RegisterAccess,
  resolveRegister
} from "./emulation-registers.js";
import {
  UNKNOWN,
  collectKnownValues,
  joinEmulatedValues,
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

const MAX_MEMORY_ADDRESS_ALTERNATIVES = 4;

export const resolveMemoryAddresses = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): bigint[] | null => {
  const baseValue = readMemoryAddressRegister(iced, state, instruction.memoryBase);
  const indexValue = readMemoryAddressRegister(iced, state, instruction.memoryIndex);
  if (baseValue == null || indexValue == null) return null;
  const baseValues = collectKnownValues(baseValue);
  const indexValues = collectKnownValues(indexValue);
  if (!baseValues.length || !indexValues.length) return null;
  const addresses = new Set<bigint>();
  for (const base of baseValues) {
    for (const index of indexValues) {
      addresses.add(
        base.value +
        index.value * BigInt(instruction.memoryIndexScale) +
        instruction.memoryDisplacement
      );
      if (addresses.size > MAX_MEMORY_ADDRESS_ALTERNATIVES) return null;
    }
  }
  return Array.from(addresses);
};

export const resolveMemoryAddress = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): bigint | null => {
  const addresses = resolveMemoryAddresses(iced, state, instruction);
  return addresses?.length === 1 ? addresses[0] ?? null : null;
};

const joinReadValues = (values: EmulatedValue[]): EmulatedValue =>
  values.reduce((left, right) => joinEmulatedValues(left, right));

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
    const addresses = resolveMemoryAddresses(iced, state, instruction);
    return addresses == null
      ? UNKNOWN
      : joinReadValues(addresses.map(address => state.memory.get(address.toString()) ?? UNKNOWN));
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
    const addresses = resolveMemoryAddresses(iced, state, instruction);
    if (addresses != null) {
      for (const address of addresses) state.memory.set(address.toString(), value);
    }
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
