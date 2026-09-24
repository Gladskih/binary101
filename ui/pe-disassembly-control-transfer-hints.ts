"use strict";

import type { PeWindowsParseResult } from "../analyzers/pe/core/parse-result.js";
import { isMappedExecutablePeRva } from "./pe-disassembly-mapped-code.js";

export const collectControlTransferInstructionRvas = (
  pe: PeWindowsParseResult,
  fileSize: number
): number[] => {
  const rvas = new Set<number>();
  for (const entry of pe.loadcfg?.dynamicRelocations?.entries ?? []) {
    for (const record of entry.controlTransfers ?? []) {
      if (isMappedExecutablePeRva(pe, fileSize, record.rva)) rvas.add(record.rva);
    }
  }
  return [...rvas];
};
