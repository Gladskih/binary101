"use strict";

import type { ElfProgramHeader } from "./types.js";

const PT_LOAD = 1;

export const vaddrToFileOffset = (
  programHeaders: ElfProgramHeader[],
  vaddr: bigint
): bigint | null => {
  for (const ph of programHeaders) {
    if (ph.type !== PT_LOAD) continue;
    if (ph.filesz <= 0n) continue;
    const start = ph.vaddr;
    const end = start + ph.filesz;
    if (vaddr < start || vaddr >= end) continue;
    return ph.offset + (vaddr - start);
  }
  return null;
};

