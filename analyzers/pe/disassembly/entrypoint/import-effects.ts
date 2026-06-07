"use strict";

import type { ImportTarget } from "./import-targets.js";
import type { IcedModule } from "./iced.js";
import { resolveRegister } from "./emulation-registers.js";
import {
  UNKNOWN,
  importReturn,
  writeRegister,
  type EmulatedValue,
  type EmulationState
} from "./emulation-state.js";

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
  writeRegisterByName(iced, state, returnRegister(state), importReturn(importTarget.label));
};
