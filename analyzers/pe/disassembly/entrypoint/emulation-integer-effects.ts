"use strict";

import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { operandBits, readOperand, writeOperand } from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
  collectKnownValues,
  joinEmulatedValues,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./emulation-state.js";
import {
  isAnyMnemonic,
  knownBooleanByte,
  maskForBits,
  registerValue,
  writeRegisterByName
} from "./emulation-integer-common.js";

export const executeExchange = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Xchg"]) {
    const left = readOperand(iced, state, instruction, 0);
    const right = readOperand(iced, state, instruction, 1);
    writeOperand(iced, state, instruction, 0, right);
    writeOperand(iced, state, instruction, 1, left);
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Xadd"]) return false;
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  writeOperand(iced, state, instruction, 0, binaryKnown(left, right, (a, b) => a + b));
  writeOperand(iced, state, instruction, 1, left);
  return true;
};

export const executeConditionalWrites = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (isAnyMnemonic(iced, mnemonic, [
    "Cmova", "Cmovae", "Cmovb", "Cmovbe", "Cmove", "Cmovg", "Cmovge", "Cmovl",
    "Cmovle", "Cmovne", "Cmovno", "Cmovnp", "Cmovns", "Cmovo", "Cmovp", "Cmovs"
  ])) {
    writeOperand(
      iced,
      state,
      instruction,
      0,
      joinEmulatedValues(readOperand(iced, state, instruction, 0), readOperand(iced, state, instruction, 1))
    );
    return true;
  }
  if (!isAnyMnemonic(iced, mnemonic, [
    "Seta", "Setae", "Setb", "Setbe", "Sete", "Setg", "Setge", "Setl",
    "Setle", "Setne", "Setno", "Setnp", "Setns", "Seto", "Setp", "Sets"
  ])) return false;
  writeOperand(iced, state, instruction, 0, knownBooleanByte());
  return true;
};

export const executeCompareExchange = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  if (instruction.mnemonic !== iced.Mnemonic?.["Cmpxchg"]) return false;
  const bits = operandBits(iced, instruction, 0) ?? state.bitness;
  const accumulator = registerValue(iced, state, accumulatorName(bits));
  const destination = readOperand(iced, state, instruction, 0);
  const accumulatorValues = collectKnownValues(accumulator);
  const destinationValues = collectKnownValues(destination);
  if (accumulatorValues.length === 1 && destinationValues.length === 1) {
    if (accumulatorValues[0]?.value === destinationValues[0]?.value) {
      writeOperand(iced, state, instruction, 0, readOperand(iced, state, instruction, 1));
      return true;
    }
    writeRegisterByName(iced, state, accumulatorName(bits), destination);
    return true;
  }
  writeOperand(iced, state, instruction, 0, joinEmulatedValues(destination, readOperand(iced, state, instruction, 1)));
  writeRegisterByName(iced, state, accumulatorName(bits), joinEmulatedValues(accumulator, destination));
  return true;
};

const writeSignExtendedRegister = (
  iced: IcedModule,
  state: EmulationState,
  sourceName: string,
  destinationName: string,
  sourceBits: KnownValueBits,
  destinationBits: KnownValueBits
): void => {
  writeRegisterByName(
    iced,
    state,
    destinationName,
    mapKnownValues(registerValue(iced, state, sourceName), destinationBits, value =>
      BigInt.asIntN(sourceBits, value)
    )
  );
};

export const executeAccumulatorExtension = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Cbw"]) return writeAccumulatorExtension(iced, state, "AL", "AX", 8, 16);
  if (mnemonic === iced.Mnemonic?.["Cwde"]) return writeAccumulatorExtension(iced, state, "AX", "EAX", 16, 32);
  if (mnemonic === iced.Mnemonic?.["Cdqe"]) return writeAccumulatorExtension(iced, state, "EAX", "RAX", 32, 64);
  if (mnemonic === iced.Mnemonic?.["Cwd"]) return writeHighSignExtension(iced, state, "AX", "DX", 16);
  if (mnemonic === iced.Mnemonic?.["Cdq"]) return writeHighSignExtension(iced, state, "EAX", "EDX", 32);
  if (mnemonic === iced.Mnemonic?.["Cqo"]) return writeHighSignExtension(iced, state, "RAX", "RDX", 64);
  if (mnemonic === iced.Mnemonic?.["Lahf"]) {
    writeRegisterByName(iced, state, "AH", UNKNOWN);
    return true;
  }
  return mnemonic === iced.Mnemonic?.["Sahf"];
};

const writeAccumulatorExtension = (
  iced: IcedModule,
  state: EmulationState,
  sourceName: string,
  destinationName: string,
  sourceBits: KnownValueBits,
  destinationBits: KnownValueBits
): true => {
  writeSignExtendedRegister(iced, state, sourceName, destinationName, sourceBits, destinationBits);
  return true;
};

const writeHighSignExtension = (
  iced: IcedModule,
  state: EmulationState,
  sourceName: string,
  destinationName: string,
  bits: KnownValueBits
): true => {
  writeRegisterByName(
    iced,
    state,
    destinationName,
    mapKnownValues(registerValue(iced, state, sourceName), bits, value =>
      BigInt.asIntN(bits, value) < 0n ? maskForBits(bits) : 0n
    )
  );
  return true;
};

export const writeAccumulatorPair = (
  iced: IcedModule,
  state: EmulationState,
  bits: KnownValueBits,
  low: EmulatedValue,
  high: EmulatedValue
): void => {
  if (bits === 8) {
    writeRegisterByName(iced, state, "AX", low);
    return;
  }
  writeRegisterByName(iced, state, accumulatorName(bits), low);
  writeRegisterByName(iced, state, highAccumulatorName(bits), high);
};

export const accumulatorName = (bits: KnownValueBits): string => {
  if (bits === 8) return "AL";
  if (bits === 16) return "AX";
  if (bits === 32) return "EAX";
  return "RAX";
};

export const highAccumulatorName = (bits: KnownValueBits): string => {
  if (bits === 16) return "DX";
  if (bits === 32) return "EDX";
  return "RDX";
};
