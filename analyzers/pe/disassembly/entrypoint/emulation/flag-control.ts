"use strict";

import type { IcedInstructionObject, IcedModule } from "../iced.js";
import type { EmulationState } from "./state.js";
import {
  clearFlags,
  readFlag,
  writeKnownFlags
} from "./flags.js";

export const executeFlagControl = (
  iced: IcedModule,
  state: EmulationState,
  instruction: IcedInstructionObject
): boolean => {
  const mnemonic = instruction.mnemonic;
  if (mnemonic === iced.Mnemonic?.["Clc"]) {
    writeKnownFlags(state, { CF: false });
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Cld"]) {
    writeKnownFlags(state, { DF: false });
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Stc"]) {
    writeKnownFlags(state, { CF: true });
    return true;
  }
  if (mnemonic === iced.Mnemonic?.["Std"]) {
    writeKnownFlags(state, { DF: true });
    return true;
  }
  if (mnemonic !== iced.Mnemonic?.["Cmc"]) return false;
  const carry = readFlag(state, "CF");
  if (carry == null) clearFlags(state, ["CF"]);
  else writeKnownFlags(state, { CF: !carry });
  return true;
};
