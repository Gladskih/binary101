"use strict";

import type { IcedInstructionObject, IcedModule } from "../iced.js";
import {
  mapKnownValues,
  type EmulationState,
  type KnownValueBits
} from "./state.js";
import {
  isAnyMnemonic,
  registerValue,
  writeRegisterByName
} from "./integer/common.js";

export const executeCounterControlFlow = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  if (!isAnyMnemonic(iced, instruction.mnemonic, ["Loop", "Loope", "Loopne"])) return false;
  const name = loopCounterRegisterName(iced, state, instruction);
  writeRegisterByName(
    iced,
    state,
    name,
    mapKnownValues(registerValue(iced, state, name), loopCounterBits(name), value => value - 1n)
  );
  return true;
};

const loopCounterRegisterName = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): string => {
  const name = iced.Code[instruction.code] ?? "";
  if (name.includes("_RCX")) return "RCX";
  if (name.includes("_ECX")) return "ECX";
  if (name.includes("_CX")) return "CX";
  return state.bitness === 64 ? "RCX" : "ECX";
};

const loopCounterBits = (name: string): KnownValueBits => {
  if (name === "CX") return 16;
  if (name === "ECX") return 32;
  return 64;
};
