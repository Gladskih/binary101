"use strict";

import type { PeEntrypointInstruction } from "../../../types.js";
import { describeCpuIdFeatureBits } from "../../cpuid-notes.js";
import type { IcedInstructionObject, IcedModule } from "../../iced.js";
import {
  isSameRegisterOperand,
  readOperand,
  resolveMemoryAddress,
  writeOperand
} from "../operands.js";
import {
  UNKNOWN,
  binaryKnown,
  collectKnownValues,
  known,
  mapKnownValues,
  type EmulatedValue,
  type EmulationState
} from "../state.js";
import { bitsOrState, writeMappedOperand } from "./common.js";
import {
  clearFlags,
  writeBitCarryFlag,
  writeLogicalFlags
} from "../flags.js";

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
  if (mnemonic === iced.Mnemonic?.["Crc32"]) {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Lea"]) {
    const address = resolveMemoryAddress(iced, state, instruction);
    writeOperand(
      iced,
      state,
      instruction,
      0,
      address == null ? UNKNOWN : known(address, state.bitness)
    );
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Movzx"] || mnemonic === iced.Mnemonic?.["Movsx"]) {
    if (mnemonic === iced.Mnemonic?.["Movsx"]) executeSignExtendMove(iced, state, instruction);
    else executeZeroExtendMove(iced, state, instruction);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Movbe"]) {
    writeOperand(
      iced,
      state,
      instruction,
      0,
      mapKnownValues(
        readOperand(iced, state, instruction, 1),
        bitsOrState(iced, state, instruction, 0),
        reversedBytes
      )
    );
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Movsxd"]) return false;
  executeSignExtendMove(iced, state, instruction);
  return true;
};

const reversedBytes = (value: bigint, bits: 8 | 16 | 32 | 64): bigint => {
  let out = 0n;
  for (let offset = 0n; offset < BigInt(bits); offset += 8n) {
    out = (out << 8n) | ((value >> offset) & 0xffn);
  }
  return out;
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
    const result = known(0n, bitsOrState(iced, state, instruction, 0));
    writeOperand(iced, state, instruction, 0, result);
    writeLogicalFlags(state, result, bitsOrState(iced, state, instruction, 0));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Xor"]) {
    return executeLogicalBinary(iced, state, instruction, (left, right) => left ^ right);
  }
  if (mnemonic === iced.Mnemonic?.["Or"]) {
    return executeLogicalBinary(iced, state, instruction, (left, right) => left | right);
  }
  if (mnemonic === iced.Mnemonic?.["And"]) {
    const left = readOperand(iced, state, instruction, 0);
    const right = readOperand(iced, state, instruction, 1);
    const result = binaryKnown(left, right, (a, b) => a & b);
    appendNotes(rendered, collectFeatureNotes(left, right));
    writeOperand(iced, state, instruction, 0, result);
    writeLogicalFlags(state, result, bitsOrState(iced, state, instruction, 0));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Not"]) {
    writeMappedOperand(iced, state, instruction, value => ~value);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Test"]) return executeTest(iced, state, rendered, instruction);
  if (
    mnemonic !== iced.Mnemonic?.["Bt"] &&
    mnemonic !== iced.Mnemonic?.["Btc"] &&
    mnemonic !== iced.Mnemonic?.["Btr"] &&
    mnemonic !== iced.Mnemonic?.["Bts"]
  ) return false;
  executeBitTest(iced, state, rendered, instruction);
  return true;
};

const executeLogicalBinary = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  op: (left: bigint, right: bigint) => bigint
): true => {
  const result = binaryKnown(
    readOperand(iced, state, instruction, 0),
    readOperand(iced, state, instruction, 1),
    op
  );
  writeOperand(iced, state, instruction, 0, result);
  writeLogicalFlags(state, result, bitsOrState(iced, state, instruction, 0));
  return true;
};

const executeTest = (
  iced: IcedModule,
  state: EmulationState,
  rendered: PeEntrypointInstruction,
  instruction: IcedInstructionObject
): true => {
  const left = readOperand(iced, state, instruction, 0);
  const right = readOperand(iced, state, instruction, 1);
  appendNotes(rendered, collectFeatureNotes(left, right));
  writeLogicalFlags(
    state,
    binaryKnown(left, right, (a, b) => a & b),
    bitsOrState(iced, state, instruction, 0)
  );
  return true;
};

const executeBitTest = (
  iced: IcedModule,
  state: EmulationState,
  rendered: PeEntrypointInstruction,
  instruction: IcedInstructionObject
): void => {
  const value = readOperand(iced, state, instruction, 0);
  const bitIndex = readOperand(iced, state, instruction, 1);
  appendNotes(rendered, collectBitTestNotes(value, bitIndex));
  const normalized = normalizedBitIndex(iced, state, instruction, bitIndex);
  if (normalized == null) {
    clearFlags(state, ["CF"]);
    if (instruction.mnemonic !== iced.Mnemonic?.["Bt"]) {
      writeOperand(iced, state, instruction, 0, UNKNOWN);
    }
    return;
  }
  writeBitCarryFlag(state, value, normalized);
  writeBitTestDestination(iced, state, instruction, normalized);
};

const normalizedBitIndex = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bitIndex: EmulatedValue
): bigint | null => {
  const bits = bitsOrState(iced, state, instruction, 0);
  const values = collectKnownValues(bitIndex);
  if (values.length !== 1) return null;
  const value = values[0]?.value;
  if (value == null) return null;
  if (instruction.op0Kind === iced.OpKind?.["Memory"] && value >= BigInt(bits)) return null;
  return value % BigInt(bits);
};

const writeBitTestDestination = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bitIndex: bigint
): void => {
  if (instruction.mnemonic === iced.Mnemonic?.["Bt"]) return;
  const mask = 1n << bitIndex;
  if (instruction.mnemonic === iced.Mnemonic?.["Bts"]) {
    writeMappedOperand(iced, state, instruction, value => value | mask);
  } else if (instruction.mnemonic === iced.Mnemonic?.["Btr"]) {
    writeMappedOperand(iced, state, instruction, value => value & ~mask);
  } else {
    writeMappedOperand(iced, state, instruction, value => value ^ mask);
  }
};
