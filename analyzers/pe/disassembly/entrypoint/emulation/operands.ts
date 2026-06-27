"use strict";

import type { IcedModule, IcedInstructionObject } from "../iced.js";
import { collectImmediateOperands } from "../immediate-operands.js";
import {
  type RegisterAccess,
  resolveRegister
} from "./registers.js";
import {
  UNKNOWN,
  collectKnownValues,
  joinEmulatedValues,
  known,
  mapKnownValues,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./state.js";

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
): string | undefined => {
  if (!Number.isInteger(operand) || operand < 0 || operand >= instruction.opCount) return undefined;
  return iced.OpKind[instruction.opKind(operand)];
};

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

const memorySizeBits = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): KnownValueBits | null => {
  const name = iced.MemorySize?.[instruction.memorySize];
  if (name === "UInt8" || name === "Int8") return 8;
  if (name === "UInt16" || name === "Int16") return 16;
  if (name === "UInt32" || name === "Int32") return 32;
  if (name === "UInt64" || name === "Int64") return 64;
  return null;
};

export const operandBits = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number
): KnownValueBits | null => {
  if (isRegisterOperand(iced, instruction, operand)) {
    return resolveRegister(iced, instruction.opRegister(operand))?.accessBits ?? null;
  }
  return isMemoryOperand(iced, instruction, operand) ? memorySizeBits(iced, instruction) : null;
};

const coerceOperandValue = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number,
  value: EmulatedValue
): EmulatedValue => {
  const bits = operandBits(iced, instruction, operand);
  if (bits == null || (value.kind !== "known" && value.kind !== "value-set")) return value;
  return mapKnownValues(value, bits, data => data);
};

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

const memoryAddressRegisterAccess = (
  iced: IcedModule,
  register: number
): RegisterAccess | null =>
  register === (iced.Register?.["None"] ?? 0) ? null : resolveRegister(iced, register);

const addressBitsFromAccess = (access: RegisterAccess | null): KnownValueBits | null => {
  if (access?.accessBits === 16) return 16;
  if (access?.accessBits === 32) return 32;
  if (access?.accessBits === 64) return 64;
  return null;
};

const memoryAddressBits = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): KnownValueBits =>
  addressBitsFromAccess(memoryAddressRegisterAccess(iced, instruction.memoryBase)) ??
  addressBitsFromAccess(memoryAddressRegisterAccess(iced, instruction.memoryIndex)) ??
  state.bitness;

const effectiveMemoryAddress = (
  instruction: IcedInstructionObject,
  base: bigint,
  index: bigint,
  addressBits: KnownValueBits
): bigint =>
  // Intel SDM Vol. 1, 3.7.5: effective-address computation uses the active
  // address size. iced-x86 can expose 32-bit negative displacements as their
  // unsigned form, so wrap the final sum to the modeled address width.
  BigInt.asUintN(
    addressBits,
    base + index * BigInt(instruction.memoryIndexScale) + instruction.memoryDisplacement
  );

export const resolveMemoryAddresses = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): bigint[] | null => {
  // iced-x86 already exposes EIP/RIP-relative operands as absolute addresses.
  if (instruction.isIpRelMemoryOperand) {
    return [known(instruction.ipRelMemoryAddress, state.bitness).value];
  }
  const baseValue = readMemoryAddressRegister(iced, state, instruction.memoryBase);
  const indexValue = readMemoryAddressRegister(iced, state, instruction.memoryIndex);
  if (baseValue == null || indexValue == null) return null;
  const baseValues = collectKnownValues(baseValue);
  const indexValues = collectKnownValues(indexValue);
  if (!baseValues.length || !indexValues.length) return null;
  const addresses = new Set<bigint>();
  const addressBits = memoryAddressBits(iced, state, instruction);
  for (const base of baseValues) {
    for (const index of indexValues) {
      addresses.add(effectiveMemoryAddress(instruction, base.value, index.value, addressBits));
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
      : coerceOperandValue(
        iced,
        instruction,
        operand,
        joinReadValues(addresses.map(address => state.memory.get(address.toString()) ?? UNKNOWN))
      );
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
      const stored = coerceOperandValue(iced, instruction, operand, value);
      for (const address of addresses) state.memory.set(address.toString(), stored);
    }
  }
};

export const isSameRegisterOperand = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): boolean => {
  if (
    !isRegisterOperand(iced, instruction, 0) ||
    !isRegisterOperand(iced, instruction, 1)
  ) return false;
  return instruction.opRegister(0) === instruction.opRegister(1);
};

export const resolveStackPointer = (
  iced: IcedModule,
  state: EmulationState
): RegisterAccess | null =>
  resolveRegister(iced, iced.Register?.[state.bitness === 64 ? "RSP" : "ESP"] ?? 0);
