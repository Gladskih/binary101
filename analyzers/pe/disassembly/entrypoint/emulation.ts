"use strict";

import type { PeEntrypointInstruction } from "../types.js";
import type { IcedModule, IcedInstructionObject } from "./iced.js";
import {
  type CpuIdOutputRegister,
  collectCpuIdVendorChunkNotes,
  describeCpuIdFeatureBits,
  describeCpuIdLeaf
} from "./cpuid-notes.js";
import { resolveRegister } from "./emulation-registers.js";
import {
  isSameRegisterOperand,
  readOperand,
  resolveMemoryAddress,
  resolveStackPointer,
  writeOperand
} from "./emulation-operands.js";
import {
  UNKNOWN,
  binaryKnown,
  createEmulationState,
  known,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";

export {
  createEmulationState,
  type EmulatedValue,
  type EmulationState
};

const appendNotes = (instruction: PeEntrypointInstruction, notes: string[]): void => {
  if (notes.length) instruction.notes = [...(instruction.notes ?? []), ...notes];
};

const cpuIdOutput = (
  leaf: number,
  subleaf: number | undefined,
  register: CpuIdOutputRegister
): EmulatedValue => ({
  kind: "cpuid-output",
  leaf,
  ...(subleaf != null ? { subleaf } : {}),
  register
});

const readKnown32 = (value: EmulatedValue): number | null =>
  value.kind === "known" && value.value <= 0xffffffffn ? Number(value.value) : null;

const executeCpuId = (
  iced: IcedModule,
  state: EmulationState,
  instruction: PeEntrypointInstruction
): void => {
  const leaf = readKnown32(readRegister(state, resolveRegister(iced, iced.Register?.["EAX"] ?? 0)));
  const subleafValue = readKnown32(
    readRegister(state, resolveRegister(iced, iced.Register?.["ECX"] ?? 0))
  );
  if (leaf == null) {
    for (const register of ["EAX", "EBX", "ECX", "EDX"] as const) {
      writeRegister(state, resolveRegister(iced, iced.Register?.[register] ?? 0), UNKNOWN);
    }
    return;
  }
  const description = describeCpuIdLeaf(leaf);
  if (description) appendNotes(instruction, [description]);
  for (const register of ["EAX", "EBX", "ECX", "EDX"] as const) {
    writeRegister(
      state,
      resolveRegister(iced, iced.Register?.[register] ?? 0),
      cpuIdOutput(leaf, subleafValue ?? undefined, register)
    );
  }
};

const collectFeatureNotes = (
  value: EmulatedValue,
  mask: EmulatedValue
): string[] => {
  if (value.kind !== "cpuid-output" || mask.kind !== "known" || mask.value > 0xffffffffn) return [];
  const bits = Array.from({ length: 32 }, (_, bit) => bit)
    .filter(bit => (mask.value & (1n << BigInt(bit))) !== 0n);
  const note = describeCpuIdFeatureBits(value.leaf, value.subleaf, value.register, bits);
  return note ? [note] : [];
};

const collectBitTestNotes = (
  value: EmulatedValue,
  bitIndex: EmulatedValue
): string[] => {
  if (value.kind !== "cpuid-output" || bitIndex.kind !== "known" || bitIndex.value > 31n) return [];
  const note = describeCpuIdFeatureBits(
    value.leaf,
    value.subleaf,
    value.register,
    [Number(bitIndex.value)]
  );
  return note ? [note] : [];
};

const pointerBytes = (state: EmulationState): bigint => BigInt(state.bitness / 8);

const pushStackValue = (
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
  state.memory.set(next.value.toString(), value);
};

const popStackValue = (
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

const isMnemonic = (
  iced: IcedModule,
  mnemonic: number,
  name: string
): boolean =>
  iced.Mnemonic?.[name] === mnemonic;

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

export const emulateInstruction = (
  iced: IcedModule,
  decoded: IcedInstructionObject,
  instruction: PeEntrypointInstruction,
  state: EmulationState
): void => {
  appendNotes(instruction, collectCpuIdVendorChunkNotes(iced, decoded));
  if (!iced.Mnemonic || !iced.Register) return;
  const mnemonic = decoded.mnemonic;
  if (mnemonic === iced.Mnemonic["Cpuid"]) {
    executeCpuId(iced, state, instruction);
    return;
  }
  if (mnemonic === iced.Mnemonic["Mov"]) {
    writeOperand(iced, state, decoded, 0, readOperand(iced, state, decoded, 1));
    return;
  }
  if (mnemonic === iced.Mnemonic["Lea"]) {
    const address = resolveMemoryAddress(iced, state, decoded);
    writeOperand(
      iced,
      state,
      decoded,
      0,
      address == null ? UNKNOWN : known(address, state.bitness)
    );
    return;
  }
  if (mnemonic === iced.Mnemonic["Xor"] && isSameRegisterOperand(iced, decoded)) {
    writeOperand(iced, state, decoded, 0, known(0n, state.bitness));
    return;
  }
  if (mnemonic === iced.Mnemonic["Xor"]) {
    const value = binaryKnown(
      readOperand(iced, state, decoded, 0),
      readOperand(iced, state, decoded, 1),
      (left, right) => left ^ right
    );
    writeOperand(iced, state, decoded, 0, value);
    return;
  }
  if (mnemonic === iced.Mnemonic["Or"]) {
    const value = binaryKnown(
      readOperand(iced, state, decoded, 0),
      readOperand(iced, state, decoded, 1),
      (left, right) => left | right
    );
    writeOperand(iced, state, decoded, 0, value);
    return;
  }
  if (mnemonic === iced.Mnemonic["And"]) {
    const left = readOperand(iced, state, decoded, 0);
    const right = readOperand(iced, state, decoded, 1);
    appendNotes(instruction, collectFeatureNotes(left, right));
    writeOperand(iced, state, decoded, 0, binaryKnown(left, right, (a, b) => a & b));
    return;
  }
  if (mnemonic === iced.Mnemonic["Test"]) {
    appendNotes(
      instruction,
      collectFeatureNotes(
        readOperand(iced, state, decoded, 0),
        readOperand(iced, state, decoded, 1)
      )
    );
    return;
  }
  if (mnemonic === iced.Mnemonic["Bt"]) {
    appendNotes(
      instruction,
      collectBitTestNotes(
        readOperand(iced, state, decoded, 0),
        readOperand(iced, state, decoded, 1)
      )
    );
    return;
  }
  const addMnemonic = iced.Mnemonic["Add"];
  const subMnemonic = iced.Mnemonic["Sub"];
  if (mnemonic === addMnemonic || mnemonic === subMnemonic) {
    const right = readOperand(iced, state, decoded, 1);
    const isAdd = mnemonic === addMnemonic;
    const value = binaryKnown(readOperand(iced, state, decoded, 0), right, (left, operand) =>
      isAdd ? left + operand : left - operand
    );
    writeOperand(iced, state, decoded, 0, value);
    return;
  }
  const pushedFlagsBytes = flagPushBytes(iced, mnemonic);
  if (pushedFlagsBytes != null) {
    pushStackValue(iced, state, UNKNOWN, pushedFlagsBytes);
    return;
  }
  const poppedFlagsBytes = flagPopBytes(iced, mnemonic);
  if (poppedFlagsBytes != null) {
    popStackValue(iced, state, poppedFlagsBytes);
    return;
  }
  if (mnemonic === iced.Mnemonic["Push"]) {
    pushStackValue(iced, state, readOperand(iced, state, decoded, 0), pointerBytes(state));
    return;
  }
  if (mnemonic === iced.Mnemonic["Pop"]) {
    writeOperand(iced, state, decoded, 0, popStackValue(iced, state, pointerBytes(state)));
  }
};
