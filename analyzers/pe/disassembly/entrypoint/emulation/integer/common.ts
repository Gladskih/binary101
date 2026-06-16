"use strict";

import type { IcedInstructionObject, IcedModule } from "../../iced.js";
import { operandBits, readOperand, writeOperand } from "../operands.js";
import { resolveRegister } from "../registers.js";
import {
  binaryKnown,
  known,
  mapKnownValues,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "../state.js";

export const isMnemonic = (iced: IcedModule, mnemonic: number, name: string): boolean =>
  iced.Mnemonic?.[name] === mnemonic;

export const isAnyMnemonic = (
  iced: IcedModule,
  mnemonic: number,
  names: readonly string[]
): boolean => names.some(name => isMnemonic(iced, mnemonic, name));

export const bitsOrState = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  operand: number
): KnownValueBits => operandBits(iced, instruction, operand) ?? state.bitness;

export const maskForBits = (bits: KnownValueBits): bigint => (1n << BigInt(bits)) - 1n;

export const writeMappedOperand = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  op: (value: bigint, bits: KnownValueBits) => bigint
): void => {
  writeOperand(
    iced,
    state,
    instruction,
    0,
    mapKnownValues(
      readOperand(iced, state, instruction, 0),
      bitsOrState(iced, state, instruction, 0),
      op
    )
  );
};

export const writeBinaryOperand = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  op: (left: bigint, right: bigint) => bigint
): void => {
  writeOperand(
    iced,
    state,
    instruction,
    0,
    binaryKnown(readOperand(iced, state, instruction, 0), readOperand(iced, state, instruction, 1), op)
  );
};

export const registerValue = (
  iced: IcedModule,
  state: EmulationState,
  name: string
): EmulatedValue => readRegister(state, resolveRegister(iced, iced.Register?.[name] ?? 0));

export const writeRegisterByName = (
  iced: IcedModule,
  state: EmulationState,
  name: string,
  value: EmulatedValue
): void => writeRegister(state, resolveRegister(iced, iced.Register?.[name] ?? 0), value);

export const knownBooleanByte = (): EmulatedValue => ({
  kind: "value-set",
  values: [known(0n, 8), known(1n, 8)]
});
