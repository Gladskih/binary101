"use strict";

import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { isRvaField } from "../analyzers/pe/layout/rva-limits.js";
import {
  findSectionContainingRva, isMemoryExecutableSection
} from "../analyzers/pe/disassembly/sampling.js";

export const isMappedExecutablePeRva = (
  pe: PeWindowsParseResult,
  fileSize: number,
  rva: number
): boolean => {
  if (!isRvaField(rva) || rva === 0 || rva >= pe.opt.SizeOfImage) return false;
  const section = findSectionContainingRva(pe.sections, rva);
  if (!section || !isMemoryExecutableSection(section)) return false;
  if (rva - section.virtualAddress >= section.sizeOfRawData) return false;
  const offset = pe.rvaToOff(rva);
  return offset != null && Number.isSafeInteger(offset) && offset >= 0 && offset < fileSize;
};
