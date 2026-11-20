import type { ElfProgramHeader } from "./types.js";
import { elfVirtualRange } from "./relocation-reader.js";

// gABI 8.3: DT_SYMTABSZ covers the complete DT_SYMTAB, in bytes.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
export const declaredDynamicSymbolRange = (
  headers: ElfProgramHeader[], address: bigint, size: bigint, stride: number,
  fileSize: number, issues: string[]
): { offset: number; size: number } | null => {
  if (size <= 0n || size % BigInt(stride) !== 0n) {
    issues.push("DT_SYMTABSZ must contain a whole number of symbol entries, including symbol zero.");
    return null;
  }
  const range = elfVirtualRange(headers, address, size, fileSize);
  if (!range) issues.push("DT_SYMTABSZ extends DT_SYMTAB outside a file-backed PT_LOAD range.");
  return range;
};
