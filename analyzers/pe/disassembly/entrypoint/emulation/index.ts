"use strict";

import type { PeEntrypointInstruction } from "../../types.js";
import type { IcedModule, IcedInstructionObject } from "../iced.js";
import {
  type CpuIdOutputRegister,
  collectCpuIdVendorChunkNotes,
  describeCpuIdLeaf
} from "../cpuid-notes.js";
import { resolveRegister } from "./registers.js";
import { executeIntegerInstruction } from "./integer/index.js";
import { executeStackInstruction } from "./stack.js";
import {
  UNKNOWN,
  createEmulationState,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./state.js";

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
  if (executeIntegerInstruction(iced, state, decoded, instruction)) return;
  executeStackInstruction(iced, state, decoded);
};
