"use strict";

import type { ImportTarget } from "./import-targets.js";
import type { IcedModule } from "./iced.js";
import { resolveRegister } from "./emulation-registers.js";
import {
  UNKNOWN,
  importReturn,
  known,
  readRegister,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";
import { resolveStackPointer } from "./emulation-operands.js";

const VOLATILE_REGISTERS_32 = ["EAX", "ECX", "EDX"] as const;
const VOLATILE_REGISTERS_64 = ["RAX", "RCX", "RDX", "R8", "R9", "R10", "R11"] as const;

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

const STDCALL_ARGUMENT_COUNTS = new Map<string, number>([
  ["KERNEL32.dll!FreeLibrary", 1],
  ["KERNEL32.dll!GetCurrentProcessId", 0],
  ["KERNEL32.dll!GetCurrentThreadId", 0],
  ["KERNEL32.dll!GetLastError", 0],
  ["KERNEL32.dll!GetProcAddress", 2],
  ["KERNEL32.dll!GetSystemTimeAsFileTime", 1],
  ["KERNEL32.dll!InitializeCriticalSectionAndSpinCount", 2],
  ["KERNEL32.dll!LoadLibraryExW", 3],
  ["KERNEL32.dll!QueryPerformanceCounter", 1]
]);

const x86StdcallArgumentBytes = (label: string): bigint => {
  const count = STDCALL_ARGUMENT_COUNTS.get(label);
  return count == null ? 0n : BigInt(count * 4);
};

const cleanX86StdcallArguments = (
  iced: IcedModule,
  state: EmulationState,
  importTarget: ImportTarget
): void => {
  // Microsoft x86 __stdcall: the callee pops its fixed arguments before
  // returning. https://learn.microsoft.com/cpp/cpp/stdcall
  if (state.bitness !== 32) return;
  const bytes = x86StdcallArgumentBytes(importTarget.label);
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
  importTarget: ImportTarget
): void => {
  // Microsoft x64 ABI: integer/pointer returns use RAX and RAX/RCX/RDX/R8-R11
  // are volatile. x86 return values are widened and returned in EAX.
  // https://learn.microsoft.com/cpp/build/x64-software-conventions
  // https://learn.microsoft.com/cpp/cpp/argument-passing-and-naming-conventions
  for (const register of volatileRegisters(state)) {
    writeRegisterByName(iced, state, register, UNKNOWN);
  }
  cleanX86StdcallArguments(iced, state, importTarget);
  writeRegisterByName(iced, state, returnRegister(state), importReturn(importTarget.label));
};
