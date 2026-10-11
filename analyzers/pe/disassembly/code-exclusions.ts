import { createCodeExclusionIndex, type CodeExclusion } from "../../code-exclusions.js";
import type { AnalyzePeInstructionSetOptions } from "./types.js";
import { isRvaField } from "../layout/rva-limits.js";
import { getIatSlotRva } from "./import-references.js";

export const collectPeCodeExclusions = (opts: AnalyzePeInstructionSetOptions): CodeExclusion[] => {
  // Export directories provide addresses, not object sizes. Mark only the known byte.
  const ranges = (opts.dataRvas ?? []).filter(rva => isRvaField(rva) && rva > 0).map(rva => ({
    start: opts.imageBase + BigInt(rva), end: opts.imageBase + BigInt(rva) + 1n
  }));
  const addSlots = (startRva: number, count: number): void => {
    const width = opts.is64Bit ? 8 : 4;
    for (let index = 0; index < count; index += 1) {
      const rva = getIatSlotRva(startRva, index, width);
      if (rva == null) continue;
      // IAT entries are address-sized data even when they refer to imported functions.
      // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#import-address-table
      ranges.push({ start: opts.imageBase + BigInt(rva),
        end: opts.imageBase + BigInt(rva + width) });
    }
  };
  for (const entry of opts.imports?.entries ?? []) addSlots(entry.firstThunkRva, entry.functions.length);
  for (const entry of opts.delayImports?.entries ?? []) {
    addSlots(entry.ImportAddressTableRVA, entry.functions.length);
  }
  return ranges;
};

export const createPeCodeExclusionIndex = (opts: AnalyzePeInstructionSetOptions) =>
  createCodeExclusionIndex(collectPeCodeExclusions(opts));
