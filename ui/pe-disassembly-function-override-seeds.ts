"use strict";

import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { isRvaField } from "../analyzers/pe/layout/rva-limits.js";
import {
  findSectionContainingRva, isMemoryExecutableSection
} from "../analyzers/pe/disassembly/sampling.js";

type FunctionSeedGroup = { source: string; rvas: number[] };

export const collectFunctionOverrideEntrypoints = (
  pe: PeWindowsParseResult,
  fileSize: number
): FunctionSeedGroup[] => {
  const entries = pe.loadcfg?.dynamicRelocations?.entries ?? [];
  const originals = new Set<number>();
  const overrides = new Set<number>();
  const isMappedCode = (rva: number): boolean => {
    if (!isRvaField(rva) || rva === 0 || rva >= pe.opt.SizeOfImage) return false;
    const section = findSectionContainingRva(pe.sections, rva);
    if (!section || !isMemoryExecutableSection(section)) return false;
    if (rva - section.virtualAddress >= section.sizeOfRawData) return false;
    const offset = pe.rvaToOff(rva);
    return offset != null && Number.isSafeInteger(offset) && offset >= 0 && offset < fileSize;
  };
  // Windows SDK winnt.h: IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE is 7.
  for (const entry of entries) {
    if (entry.symbol !== 7n || !entry.fixup) continue;
    for (const record of entry.fixup.functions) {
      if (isMappedCode(record.originalRva)) originals.add(record.originalRva);
      for (const rva of record.overridingRvas) {
        if (isMappedCode(rva)) overrides.add(rva);
      }
    }
  }
  return [
    ...(originals.size ? [{ source: "DVRT original function", rvas: [...originals] }] : []),
    ...(overrides.size ? [{ source: "DVRT override function", rvas: [...overrides] }] : [])
  ];
};
