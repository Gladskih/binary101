"use strict";

import type { PeEntrypointInstruction } from "../types.js";
import type { IcedModule, IcedFormatter, IcedInstructionObject } from "./iced.js";
import { collectSecurityCookieOperandNotes } from "./security-cookie-notes.js";
import {
  emulateInstruction,
  type EmulationState
} from "./emulation.js";

export const createInstruction = (
  iced: IcedModule,
  instruction: IcedInstructionObject,
  formatter: IcedFormatter,
  rva: number,
  fileOffset: number,
  noteState?: EmulationState
): PeEntrypointInstruction => {
  const notes = collectSecurityCookieOperandNotes(iced, instruction);
  const out = {
    rva,
    fileOffset,
    text: formatter.format(instruction),
    ...(notes.length ? { notes } : {})
  };
  if (noteState) emulateInstruction(iced, instruction, out, noteState);
  return out;
};
