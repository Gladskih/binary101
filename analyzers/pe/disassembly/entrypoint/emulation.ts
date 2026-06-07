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
  if (mnemonic === iced.Mnemonic["Push"]) {
    const stackPointer = resolveStackPointer(iced, state);
    const current = readRegister(state, stackPointer);
    if (current.kind !== "known") {
      writeRegister(state, stackPointer, UNKNOWN);
      return;
    }
    const next = known(current.value - BigInt(state.bitness / 8), state.bitness);
    writeRegister(state, stackPointer, next);
    state.memory.set(next.value.toString(), readOperand(iced, state, decoded, 0));
    return;
  }
  if (mnemonic === iced.Mnemonic["Pop"]) {
    const stackPointer = resolveStackPointer(iced, state);
    const current = readRegister(state, stackPointer);
    if (current.kind === "known") {
      const stackSlot = current.value.toString();
      writeOperand(iced, state, decoded, 0, state.memory.get(stackSlot) ?? UNKNOWN);
      state.memory.delete(stackSlot);
      writeRegister(
        state,
        stackPointer,
        known(current.value + BigInt(state.bitness / 8), state.bitness)
      );
    } else {
      writeOperand(iced, state, decoded, 0, UNKNOWN);
      writeRegister(state, stackPointer, UNKNOWN);
    }
  }
};
