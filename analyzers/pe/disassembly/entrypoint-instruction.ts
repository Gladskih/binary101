"use strict";

import type { PeEntrypointInstruction } from "./types.js";
import type { EntrypointIcedModule, IcedFormatter, IcedInstruction } from "./entrypoint-iced.js";
import { collectSecurityCookieOperandNotes } from "./entrypoint-security-cookie-notes.js";
import {
  createCpuIdNoteState,
  updateCpuIdInstructionNotes,
  type CpuIdNoteState
} from "./entrypoint-cpuid-notes.js";

export const createEntrypointNoteState = (): CpuIdNoteState => createCpuIdNoteState();

export const createEntrypointInstruction = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction,
  formatter: IcedFormatter,
  rva: number,
  fileOffset: number,
  noteState: CpuIdNoteState = createEntrypointNoteState()
): PeEntrypointInstruction => {
  const notes = collectSecurityCookieOperandNotes(iced, instruction);
  const out = {
    rva,
    fileOffset,
    text: formatter.format(instruction),
    ...(notes.length ? { notes } : {})
  };
  updateCpuIdInstructionNotes(iced, instruction, out, noteState);
  return out;
};
