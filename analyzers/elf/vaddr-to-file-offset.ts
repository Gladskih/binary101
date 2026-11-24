import type { ElfProgramHeader } from "./types.js";
import { elfLoadFileSpan } from "./range-coverage.js";

export const vaddrToFileOffset = (
  programHeaders: ElfProgramHeader[],
  vaddr: bigint
): bigint | null => elfLoadFileSpan(programHeaders, vaddr, 1n)?.offset ?? null;

