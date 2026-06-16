"use strict";

import type { IcedInstructionObject, IcedModule } from "../iced.js";
import {
  operandBits,
  readOperand,
  resolveStackPointer,
  writeOperand
} from "./operands.js";
import { resolveRegister } from "./registers.js";
import {
  UNKNOWN,
  known,
  mapKnownValues,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState,
  type KnownValueBits
} from "./state.js";
import { clearFlags } from "./flags.js";

const isMnemonic = (
  iced: IcedModule,
  mnemonic: number,
  name: string
): boolean => iced.Mnemonic?.[name] === mnemonic;

const byteCountBits = (byteCount: bigint): KnownValueBits | null => {
  if (byteCount === 1n) return 8;
  if (byteCount === 2n) return 16;
  if (byteCount === 4n) return 32;
  if (byteCount === 8n) return 64;
  return null;
};

export const pointerBytes = (state: EmulationState): bigint => BigInt(state.bitness / 8);

const coerceStackValue = (value: EmulatedValue, byteCount: bigint): EmulatedValue => {
  const bits = byteCountBits(byteCount);
  if (bits == null || (value.kind !== "known" && value.kind !== "value-set")) return value;
  return mapKnownValues(value, bits, data => data);
};

export const pushStackValue = (
  iced: IcedModule,
  state: EmulationState,
  value: EmulatedValue,
  byteCount: bigint
): void => {
  const stackPointer = resolveStackPointer(iced, state);
  const current = readRegister(state, stackPointer);
  if (current.kind !== "known") {
    writeRegister(state, stackPointer, UNKNOWN);
    return;
  }
  const next = known(current.value - byteCount, state.bitness);
  writeRegister(state, stackPointer, next);
  state.memory.set(next.value.toString(), coerceStackValue(value, byteCount));
};

export const popStackValue = (
  iced: IcedModule,
  state: EmulationState,
  byteCount: bigint
): EmulatedValue => {
  const stackPointer = resolveStackPointer(iced, state);
  const current = readRegister(state, stackPointer);
  if (current.kind !== "known") {
    writeRegister(state, stackPointer, UNKNOWN);
    return UNKNOWN;
  }
  const stackSlot = current.value.toString();
  const value = state.memory.get(stackSlot) ?? UNKNOWN;
  state.memory.delete(stackSlot);
  writeRegister(state, stackPointer, known(current.value + byteCount, state.bitness));
  return value;
};

// PUSHF/PUSHFD/PUSHFQ and POPF/POPFD/POPFQ stack widths follow the instruction
// operand size. Intel SDM Vol. 2 PUSHF/PUSHFD/PUSHFQ and POPF/POPFD/POPFQ.
// https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
const flagPushBytes = (iced: IcedModule, mnemonic: number): bigint | null => {
  if (isMnemonic(iced, mnemonic, "Pushf")) return 2n;
  if (isMnemonic(iced, mnemonic, "Pushfd")) return 4n;
  if (isMnemonic(iced, mnemonic, "Pushfq")) return 8n;
  return null;
};

const flagPopBytes = (iced: IcedModule, mnemonic: number): bigint | null => {
  if (isMnemonic(iced, mnemonic, "Popf")) return 2n;
  if (isMnemonic(iced, mnemonic, "Popfd")) return 4n;
  if (isMnemonic(iced, mnemonic, "Popfq")) return 8n;
  return null;
};

const codeName = (iced: IcedModule, instruction: IcedInstructionObject): string =>
  iced.Code[instruction.code] ?? "";

const stackOperandBytes = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): bigint => {
  const bits = operandBits(iced, instruction, 0);
  if (bits != null) return BigInt(bits / 8);
  const name = codeName(iced, instruction);
  if (name.includes("q_") || name.includes("_r64") || name.includes("_rm64")) return 8n;
  if (name.includes("d_") || name.includes("_r32") || name.includes("_rm32")) return 4n;
  if (name.includes("_imm16") || name.includes("_r16") || name.includes("_rm16")) return 2n;
  return pointerBytes(state);
};

const registerValue = (
  iced: IcedModule,
  state: EmulationState,
  name: string
): EmulatedValue => readRegister(state, resolveRegister(iced, iced.Register?.[name] ?? 0));

const writeRegisterByName = (
  iced: IcedModule,
  state: EmulationState,
  name: string,
  value: EmulatedValue
): void => writeRegister(state, resolveRegister(iced, iced.Register?.[name] ?? 0), value);

const pushAllRegisterNames = (bytes: bigint): readonly string[] =>
  bytes === 2n
    ? ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"]
    : ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"];

const popAllRegisterNames = (bytes: bigint): readonly (string | null)[] =>
  bytes === 2n
    ? ["DI", "SI", "BP", null, "BX", "DX", "CX", "AX"]
    : ["EDI", "ESI", "EBP", null, "EBX", "EDX", "ECX", "EAX"];

const executePushAll = (iced: IcedModule, state: EmulationState, bytes: bigint): void => {
  const values = pushAllRegisterNames(bytes)
    .map(name => registerValue(iced, state, name));
  for (const value of values) pushStackValue(iced, state, value, bytes);
};

const executePopAll = (iced: IcedModule, state: EmulationState, bytes: bigint): void => {
  for (const name of popAllRegisterNames(bytes)) {
    const value = popStackValue(iced, state, bytes);
    if (name) writeRegisterByName(iced, state, name, value);
  }
};

const frameRegisterName = (bytes: bigint): string => {
  if (bytes === 2n) return "BP";
  if (bytes === 4n) return "EBP";
  return "RBP";
};

const enterFrameBytes = (iced: IcedModule, instruction: IcedInstructionObject): bigint => {
  const name = codeName(iced, instruction);
  if (name.startsWith("Enterw")) return 2n;
  if (name.startsWith("Enterd")) return 4n;
  return 8n;
};

const executeEnter = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => {
  const allocation = readOperand(iced, state, instruction, 0);
  const nesting = readOperand(iced, state, instruction, 1);
  const bytes = enterFrameBytes(iced, instruction);
  if (allocation.kind !== "known" || nesting.kind !== "known" || nesting.value !== 0n) {
    writeRegister(state, resolveStackPointer(iced, state), UNKNOWN);
    writeRegisterByName(iced, state, frameRegisterName(bytes), UNKNOWN);
    return;
  }
  pushStackValue(iced, state, registerValue(iced, state, frameRegisterName(bytes)), bytes);
  writeRegisterByName(
    iced,
    state,
    frameRegisterName(bytes),
    readRegister(state, resolveStackPointer(iced, state))
  );
  const current = readRegister(state, resolveStackPointer(iced, state));
  writeRegister(
    state,
    resolveStackPointer(iced, state),
    current.kind === "known" ? known(current.value - allocation.value, state.bitness) : UNKNOWN
  );
};

const leaveFrameBytes = (iced: IcedModule, instruction: IcedInstructionObject): bigint => {
  const name = codeName(iced, instruction);
  if (name.startsWith("Leavew")) return 2n;
  if (name.startsWith("Leaved")) return 4n;
  return 8n;
};

const executeLeave = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): void => {
  const bytes = leaveFrameBytes(iced, instruction);
  writeRegister(
    state,
    resolveStackPointer(iced, state),
    registerValue(iced, state, frameRegisterName(bytes))
  );
  writeRegisterByName(iced, state, frameRegisterName(bytes), popStackValue(iced, state, bytes));
};

export const executeStackInstruction = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  const pushedFlagsBytes = flagPushBytes(iced, mnemonic);
  if (pushedFlagsBytes != null) {
    pushStackValue(iced, state, UNKNOWN, pushedFlagsBytes);
    return true;
  }
  const poppedFlagsBytes = flagPopBytes(iced, mnemonic);
  if (poppedFlagsBytes != null) {
    popStackValue(iced, state, poppedFlagsBytes);
    clearFlags(state);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Push"]) {
    pushStackValue(
      iced,
      state,
      readOperand(iced, state, instruction, 0),
      stackOperandBytes(iced, state, instruction)
    );
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Pop"]) {
    writeOperand(
      iced,
      state,
      instruction,
      0,
      popStackValue(iced, state, stackOperandBytes(iced, state, instruction))
    );
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Pushad"] || mnemonic === iced.Mnemonic?.["Pusha"]) {
    executePushAll(iced, state, mnemonic === iced.Mnemonic?.["Pusha"] ? 2n : 4n);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Popad"] || mnemonic === iced.Mnemonic?.["Popa"]) {
    executePopAll(iced, state, mnemonic === iced.Mnemonic?.["Popa"] ? 2n : 4n);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Enter"]) {
    executeEnter(iced, state, instruction);
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Leave"]) {
    executeLeave(iced, state, instruction);
    return true;
  }
  return false;
};
