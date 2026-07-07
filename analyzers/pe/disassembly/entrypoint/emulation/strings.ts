"use strict";

import type { IcedInstructionObject, IcedModule } from "../iced.js";
import { readFlag } from "./flags.js";
import {
  UNKNOWN,
  collectKnownValues,
  known,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./state.js";
import {
  copyMovsMemory,
  movsElementBytes
} from "./movs-memory-copy.js";
import {
  isAnyMnemonic,
  registerValue,
  writeRegisterByName
} from "./integer/common.js";

const MOVS_MNEMONICS = ["Movsb", "Movsw", "Movsd", "Movsq"] as const;
// MOVS uses implicit SI/DI memory operands; REP consumes CX/ECX/RCX and DF
// selects whether those pointers advance or retreat. Intel SDM Vol. 2 MOVS.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

type StringPointer = {
  registerName: string;
  bits: KnownValueBits;
};

type StringMove = {
  source: StringPointer;
  destination: StringPointer;
  elementBits: KnownValueBits;
};

type RepeatCounter = {
  name: string;
  bits: KnownValueBits;
  repeated: boolean;
};

export const executeStringInstruction = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  if (!isAnyMnemonic(iced, instruction.mnemonic, MOVS_MNEMONICS)) return false;
  const move = stringMove(iced, instruction);
  if (!move) return false;
  executeMoveString(iced, state, instruction, move);
  return true;
};

const stringMove = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): StringMove | null => {
  const destination = stringPointer(iced, instruction, 0, "DI");
  const source = stringPointer(iced, instruction, 1, "SI");
  const elementBits = memorySizeBits(iced, instruction);
  return source && destination && elementBits ? { source, destination, elementBits } : null;
};

const stringPointer = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  operand: number,
  suffix: "DI" | "SI"
): StringPointer | null => {
  const name = iced.OpKind[instruction.opKind(operand)];
  if (!name?.endsWith(suffix)) return null;
  if (name.endsWith(`E${suffix}`)) return { registerName: `E${suffix}`, bits: 32 };
  if (name.endsWith(`R${suffix}`)) return { registerName: `R${suffix}`, bits: 64 };
  return { registerName: suffix, bits: 16 };
};

const memorySizeBits = (
  iced: IcedModule,
  instruction: IcedInstructionObject
): KnownValueBits | null => {
  const name = iced.MemorySize?.[instruction.memorySize];
  if (name === "UInt8") return 8;
  if (name === "UInt16") return 16;
  if (name === "UInt32") return 32;
  if (name === "UInt64") return 64;
  return null;
};

const executeMoveString = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  move: StringMove
): void => {
  const counter = repeatCounter(move.source.bits, instruction);
  const count = repeatedCount(iced, state, counter);
  const source = knownSingleValue(registerValue(iced, state, move.source.registerName));
  const destination = knownSingleValue(registerValue(iced, state, move.destination.registerName));
  const forward = readFlag(state, "DF") === false;
  if (count == null || source == null || destination == null || readFlag(state, "DF") == null) {
    invalidateMoveString(iced, state, counter, move);
    return;
  }
  copyMovsMemory(state, source, destination, count, move.elementBits, forward);
  writeMovedStringRegisters(iced, state, counter, move, source, destination, count, forward);
};

const repeatCounter = (
  addressBits: KnownValueBits,
  instruction: IcedInstructionObject
): RepeatCounter => ({
  name: addressBits === 16 ? "CX" : addressBits === 32 ? "ECX" : "RCX",
  bits: addressBits,
  repeated: instruction.hasRepePrefix || instruction.hasRepnePrefix
});

const repeatedCount = (
  iced: IcedModule,
  state: EmulationState,
  counter: RepeatCounter
): bigint | null =>
  counter.repeated ? knownSingleValue(registerValue(iced, state, counter.name)) : 1n;

const knownSingleValue = (value: EmulatedValue): bigint | null => {
  const values = collectKnownValues(value);
  return values.length === 1 ? values[0]?.value ?? null : null;
};

const invalidateMoveString = (
  iced: IcedModule,
  state: EmulationState,
  counter: RepeatCounter,
  move: StringMove
): void => {
  if (counter.repeated) writeRegisterByName(iced, state, counter.name, UNKNOWN);
  writeRegisterByName(iced, state, move.source.registerName, UNKNOWN);
  writeRegisterByName(iced, state, move.destination.registerName, UNKNOWN);
};

const writeMovedStringRegisters = (
  iced: IcedModule,
  state: EmulationState,
  counter: RepeatCounter,
  move: StringMove,
  source: bigint,
  destination: bigint,
  count: bigint,
  forward: boolean
): void => {
  const elementDelta = forward ? movsElementBytes(move.elementBits) : -movsElementBytes(move.elementBits);
  const delta = count * elementDelta;
  writeRegisterByName(
    iced,
    state,
    move.source.registerName,
    known(source + delta, move.source.bits)
  );
  writeRegisterByName(
    iced,
    state,
    move.destination.registerName,
    known(destination + delta, move.destination.bits)
  );
  if (counter.repeated) writeRegisterByName(iced, state, counter.name, known(0n, counter.bits));
};
