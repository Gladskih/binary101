"use strict";

import type { PeEntrypointInstruction } from "./types.js";
import type { EntrypointIcedModule, IcedFormatter, IcedInstruction } from "./entrypoint-iced.js";
import { collectSecurityCookieOperandNotes } from "./entrypoint-security-cookie-notes.js";

export const createEntrypointInstruction = (
  iced: EntrypointIcedModule,
  instruction: IcedInstruction,
  formatter: IcedFormatter,
  rva: number,
  fileOffset: number
): PeEntrypointInstruction => {
  const notes = collectSecurityCookieOperandNotes(iced, instruction);
  return {
    rva,
    fileOffset,
    text: formatter.format(instruction),
    ...(notes.length ? { notes } : {})
  };
};
