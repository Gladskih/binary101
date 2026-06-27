"use strict";

import type { ImportTarget } from "./import-targets.js";
import type { IcedModule } from "./iced.js";
import { resolveRegister } from "./emulation/registers.js";
import {
  UNKNOWN,
  importReturn,
  known,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./emulation/state.js";
import { resolveStackPointer } from "./emulation/operands.js";

const VOLATILE_REGISTERS_32 = ["EAX", "ECX", "EDX"] as const;
const VOLATILE_REGISTERS_64 = ["RAX", "RCX", "RDX", "R8", "R9", "R10", "R11"] as const;

type ReturningImportTarget = Pick<ImportTarget, "apiMetadata" | "label">;

const writeRegisterByName = (
  iced: IcedModule,
  state: EmulationState,
  name: string,
  value: EmulatedValue
): void => {
  writeRegister(state, resolveRegister(iced, iced.Register?.[name] ?? 0), value);
};

const volatileRegisters = (state: EmulationState): readonly string[] =>
  state.bitness === 64 ? VOLATILE_REGISTERS_64 : VOLATILE_REGISTERS_32;

const returnRegister = (state: EmulationState): string =>
  state.bitness === 64 ? "RAX" : "EAX";

const stackCleanupConvention = (callingConvention: string): boolean =>
  callingConvention === "winapi" || callingConvention === "stdcall";

const isStackByteCount = (value: number | null): value is number =>
  value != null;

const x86CalleeCleanupBytes = (
  importTarget: Pick<ImportTarget, "apiMetadata">
): bigint => {
  const metadata = importTarget.apiMetadata;
  if (!metadata || metadata.variadic || !stackCleanupConvention(metadata.callingConvention)) return 0n;
  const sizes = metadata.parameters.map(parameter => parameter.x86StackBytes);
  if (!sizes.every(isStackByteCount)) return 0n;
  return BigInt(sizes.reduce((total, size) => total + size, 0));
};

const cleanX86CalleeArguments = (
  iced: IcedModule,
  state: EmulationState,
  importTarget: Pick<ImportTarget, "apiMetadata">
): void => {
  // Microsoft x86 __stdcall: the callee pops its fixed arguments before
  // returning. https://learn.microsoft.com/cpp/cpp/stdcall
  if (state.bitness !== 32) return;
  const bytes = x86CalleeCleanupBytes(importTarget);
  if (bytes === 0n) return;
  const stackPointer = resolveStackPointer(iced, state);
  const current = readRegister(state, stackPointer);
  if (current.kind !== "known") return;
  for (let offset = 0n; offset < bytes; offset += 4n) {
    state.memory.delete((current.value + offset).toString());
  }
  writeRegister(state, stackPointer, known(current.value + bytes, 32));
};

export const applyReturningImportEffects = (
  iced: IcedModule,
  state: EmulationState,
  importTarget: ReturningImportTarget
): void => {
  // Microsoft x64 ABI: integer/pointer returns use RAX and RAX/RCX/RDX/R8-R11
  // are volatile. x86 return values are widened and returned in EAX.
  // https://learn.microsoft.com/cpp/build/x64-software-conventions
  // https://learn.microsoft.com/cpp/cpp/argument-passing-and-naming-conventions
  for (const register of volatileRegisters(state)) {
    writeRegisterByName(iced, state, register, UNKNOWN);
  }
  cleanX86CalleeArguments(iced, state, importTarget);
  writeRegisterByName(iced, state, returnRegister(state), importReturn(importTarget.label));
};
