import { ELF_SYMBOL_INDEX } from "./abi-constants.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";

// gABI 3.1 and 5.5: reserved values belong to the raw halfword. An SHN_XINDEX
// entry refers to a real section through a separate Elf32_Word.
// https://gabi.xinuos.com/elf/05-symtab.html#section-index
export const elfSymbolSectionReference = (
  sectionIndex: number, rawSectionIndex?: number
): number | null => {
  if (rawSectionIndex === ELF_SYMBOL_INDEX.XINDEX) {
    return sectionIndex >= 0xff00 ? sectionIndex : null; // SHN_LORESERVE, gABI 3.1.
  }
  return sectionIndex > 0 && sectionIndex < 0xff00 ? sectionIndex : null;
};

export const elfSymbolSectionFields = (rawIndex: number, resolvedIndex: number | null):
Pick<ElfRelocationSymbol, "sectionIndex" | "rawSectionIndex"> => ({
  sectionIndex: resolvedIndex ?? rawIndex,
  ...(rawIndex === ELF_SYMBOL_INDEX.XINDEX && resolvedIndex != null ? { rawSectionIndex: rawIndex } : {})
});
