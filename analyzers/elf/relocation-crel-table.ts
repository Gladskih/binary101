import type { ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import { ELF_DYNAMIC_TAG } from "./abi-constants.js";
import { elfVirtualExtent } from "./relocation-reader.js";

// DT_CREL has no DT_CRELSZ: the header count terminates decoding. Bound the
// cursor by its file-backed extent, then replace this provisional size with
// the consumed byte count. Prefer an exact section alias when one is present.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/BinaryFormat/DynamicTags.def
export const collectElfCrelDynamicTable = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[]
): ElfRelocationTable | null => {
  const address = tags.get(ELF_DYNAMIC_TAG.CREL);
  if (address == null) return null;
  const range = elfVirtualExtent(elf.programHeaders, address, elf.fileSize);
  if (!range) {
    issues.push("ELF DT_CREL has an invalid PT_LOAD mapping.");
    return null;
  }
  return { ...range, entrySize: 1, encoding: "CREL", sources: ["DT_CREL"],
    sectionIndex: null, symbolTableIndex: null, targetSectionIndex: null };
};
