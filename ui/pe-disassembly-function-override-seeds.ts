"use strict";

import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { isMappedExecutablePeRva } from "./pe-disassembly-mapped-code.js";

type FunctionSeedGroup = { source: string; rvas: number[] };

export const collectFunctionOverrideEntrypoints = (
  pe: PeWindowsParseResult,
  fileSize: number
): FunctionSeedGroup[] => {
  const entries = pe.loadcfg?.dynamicRelocations?.entries ?? [];
  const originals = new Set<number>();
  const overrides = new Set<number>();
  // Windows SDK winnt.h: IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE is 7.
  for (const entry of entries) {
    if (entry.symbol !== 7n || !entry.fixup) continue;
    for (const record of entry.fixup.functions) {
      if (isMappedExecutablePeRva(pe, fileSize, record.originalRva)) {
        originals.add(record.originalRva);
      }
      for (const rva of record.overridingRvas) {
        if (isMappedExecutablePeRva(pe, fileSize, rva)) overrides.add(rva);
      }
    }
  }
  return [
    ...(originals.size ? [{ source: "DVRT original function", rvas: [...originals] }] : []),
    ...(overrides.size ? [{ source: "DVRT override function", rvas: [...overrides] }] : [])
  ];
};
