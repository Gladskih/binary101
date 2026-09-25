"use strict";

import type { PeEntrypointInstruction } from "../types.js";
import type { Instruction } from "iced-x86-disasm";
import type { IcedModule, IcedFormatter } from "./iced.js";
import { collectSecurityCookieOperandNotes } from "./security-cookie-notes.js";
import {
  emulateInstruction,
  type EmulationState
} from "./emulation/index.js";

export const createInstruction = (
  iced: IcedModule,
  instruction: Instruction,
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
