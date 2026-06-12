"use strict";

import type { IcedInstructionObject, IcedModule } from "./iced.js";
import { readOperand, writeOperand } from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
  collectKnownValues,
  mapKnownValues,
  type EmulationState,
  type KnownValueBits
} from "./emulation-state.js";
import {
  bitsOrState,
  isAnyMnemonic,
  maskForBits,
  writeMappedOperand
} from "./emulation-integer-common.js";
import { clearFlags, writeKnownFlags } from "./emulation-flags.js";

// Shift and rotate counts are masked by operand size on modern x86.
// Intel SDM Vol. 1, section 7.3.1 and Vol. 2 shift/rotate instruction refs.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const countMask = (bits: KnownValueBits): bigint => bits === 64 ? 0x3fn : 0x1fn;

const rotateLeft = (value: bigint, bits: KnownValueBits, count: bigint): bigint => {
  const maskedCount = count % BigInt(bits);
  if (maskedCount === 0n) return value;
  return ((value << maskedCount) | (value >> (BigInt(bits) - maskedCount))) & maskForBits(bits);
};

const rotateRight = (value: bigint, bits: KnownValueBits, count: bigint): bigint => {
  const maskedCount = count % BigInt(bits);
  if (maskedCount === 0n) return value;
  return ((value >> maskedCount) | (value << (BigInt(bits) - maskedCount))) & maskForBits(bits);
};

const shiftedValue = (
  mnemonic: number,
  iced: IcedModule,
  value: bigint,
  bits: KnownValueBits,
  count: bigint
): bigint => {
  const maskedCount = count & countMask(bits);
  if (maskedCount === 0n) return value;
  if (mnemonic === iced.Mnemonic?.["Sar"]) return BigInt.asIntN(bits, value) >> maskedCount;
  if (mnemonic === iced.Mnemonic?.["Shr"]) return BigInt.asUintN(bits, value) >> maskedCount;
  if (mnemonic === iced.Mnemonic?.["Rol"]) return rotateLeft(value, bits, maskedCount);
  if (mnemonic === iced.Mnemonic?.["Ror"]) return rotateRight(value, bits, maskedCount);
  return value << maskedCount;
};

export const executeShift = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (!isAnyMnemonic(iced, mnemonic, [
    "Sal", "Sar", "Shl", "Shr", "Rol", "Ror", "Rcl", "Rcr"
  ])) return false;
  const count = readOperand(iced, state, instruction, 1);
  const bits = bitsOrState(iced, state, instruction, 0);
  if (count.kind !== "known") {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    clearFlags(state);
    return true;
  }
  const maskedCount = count.value & countMask(bits);
  if (isAnyMnemonic(iced, mnemonic, ["Rcl", "Rcr"]) && maskedCount !== 0n) {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    clearFlags(state);
    return true;
  }
  writeMappedOperand(iced, state, instruction, value =>
    shiftedValue(mnemonic, iced, value, bits, count.value)
  );
  if (maskedCount !== 0n) clearFlags(state);
  return true;
};

export const executeDoubleShift = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic !== iced.Mnemonic?.["Shld"] && mnemonic !== iced.Mnemonic?.["Shrd"]) return false;
  const bits = bitsOrState(iced, state, instruction, 0);
  const count = readOperand(iced, state, instruction, 2);
  if (count.kind !== "known") {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    clearFlags(state);
    return true;
  }
  const maskedCount = count.value & countMask(bits);
  if (maskedCount === 0n) return true;
  writeDoubleShiftResult(iced, state, instruction, bits, maskedCount);
  clearFlags(state);
  return true;
};

const writeDoubleShiftResult = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  bits: KnownValueBits,
  count: bigint
): void => {
  writeOperand(iced, state, instruction, 0, binaryKnown(
    readOperand(iced, state, instruction, 0),
    readOperand(iced, state, instruction, 1),
    (left, right) => instruction.mnemonic === iced.Mnemonic?.["Shld"]
      ? (left << count) | (right >> (BigInt(bits) - count))
      : (left >> count) | (right << (BigInt(bits) - count))
  ));
};

const reversedBytes = (value: bigint, bits: KnownValueBits): bigint => {
  let out = 0n;
  for (let offset = 0n; offset < BigInt(bits); offset += 8n) {
    out = (out << 8n) | ((value >> offset) & 0xffn);
  }
  return out;
};

const leastSignificantBitIndex = (value: bigint): bigint => {
  let index = 0n;
  for (let shifted = value; (shifted & 1n) === 0n; shifted >>= 1n) index += 1n;
  return index;
};

const mostSignificantBitIndex = (value: bigint): bigint =>
  BigInt(value.toString(2).length - 1);

const populationCount = (value: bigint): bigint => {
  let count = 0n;
  for (let shifted = value; shifted !== 0n; shifted >>= 1n) count += shifted & 1n;
  return count;
};

export const executeBitScanAndCount = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Bswap"]) {
    writeMappedOperand(iced, state, instruction, (value, bits) => reversedBytes(value, bits));
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Bsf"] || mnemonic === iced.Mnemonic?.["Bsr"]) {
    if (mnemonic === iced.Mnemonic?.["Bsr"]) executeReverseBitScan(iced, state, instruction);
    else executeForwardBitScan(iced, state, instruction);
    return true;
  }
  if (!isAnyMnemonic(iced, mnemonic, ["Popcnt", "Lzcnt", "Tzcnt"])) return false;
  executeBitCount(iced, state, instruction, mnemonic);
  return true;
};

const executeForwardBitScan = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeBitScan(iced, state, instruction, leastSignificantBitIndex);

const executeReverseBitScan = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => executeBitScan(iced, state, instruction, mostSignificantBitIndex);

const executeBitScan = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  scan: (value: bigint) => bigint
): void => {
  const values = collectKnownValues(readOperand(iced, state, instruction, 1));
  if (!values.length || values.some(value => value.value === 0n)) {
    writeOperand(iced, state, instruction, 0, UNKNOWN);
    if (values.length === 1 && values[0]?.value === 0n) writeKnownFlags(state, { ZF: true });
    else clearFlags(state, ["ZF"]);
    return;
  }
  writeOperand(
    iced,
    state,
    instruction,
    0,
    mapKnownValues(
      readOperand(iced, state, instruction, 1),
      bitsOrState(iced, state, instruction, 0),
      scan
    )
  );
  writeKnownFlags(state, { ZF: false });
};

const executeBitCount = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  mnemonic: number
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
      value => countKnownBits(iced, mnemonic, value, sourceBits)
    )
  );
  writeBitCountFlags(iced, state, instruction, mnemonic);
};

const writeBitCountFlags = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject,
  mnemonic: number
): void => {
  const values = collectKnownValues(readOperand(iced, state, instruction, 1));
  if (values.length !== 1) {
    clearFlags(state);
    return;
  }
  if (mnemonic === iced.Mnemonic?.["Popcnt"]) {
    writeKnownFlags(state, {
      CF: false,
      PF: false,
      AF: false,
      ZF: values[0]?.value === 0n,
      SF: false,
      OF: false
    });
    return;
  }
  clearFlags(state, ["OF", "SF", "AF", "PF"]);
  writeKnownFlags(state, {
    CF: values[0]?.value === 0n,
    ZF: countKnownBits(
      iced,
      mnemonic,
      values[0]?.value ?? 0n,
      bitsOrState(iced, state, instruction, 1)
    ) === 0n
  });
};

const countKnownBits = (
  iced: IcedModule,
  mnemonic: number,
  value: bigint,
  sourceBits: KnownValueBits
): bigint => {
  if (mnemonic === iced.Mnemonic?.["Popcnt"]) return populationCount(value);
  if (mnemonic === iced.Mnemonic?.["Lzcnt"]) {
    return value === 0n
      ? BigInt(sourceBits)
      : BigInt(sourceBits) - BigInt(value.toString(2).length);
  }
  return value === 0n ? BigInt(sourceBits) : leastSignificantBitIndex(value);
};
