import type { ElfRelocationImage, ElfRelocationTable } from "./relocation-types.js";
import { ELF_DYNAMIC_TAG, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfVirtualRange } from "./relocation-reader.js";

// DT_CREL has no DT_CRELSZ: the header count terminates decoding. Bound the
// cursor by its file-backed segment, then replace this provisional size with
// the consumed byte count. Prefer an exact section alias when one is present.
// https://github.com/llvm/llvm-project/blob/llvmorg-23.1.3/llvm/include/llvm/BinaryFormat/DynamicTags.def
export const collectElfCrelDynamicTable = (
  elf: ElfRelocationImage, tags: Map<number, bigint>, issues: string[]
): ElfRelocationTable | null => {
  const address = tags.get(ELF_DYNAMIC_TAG.CREL);
  if (address == null) return null;
  const segment = elf.programHeaders.find(header => header.type === ELF_SEGMENT_TYPE.LOAD &&
    address >= header.vaddr && address < header.vaddr + header.filesz);
  const range = segment ? elfVirtualRange(elf.programHeaders, address,
    segment.vaddr + segment.filesz - address, elf.fileSize) : null;
  if (!range) {
    issues.push("ELF DT_CREL has an invalid PT_LOAD mapping.");
    return null;
  }
  return { ...range, entrySize: 1, encoding: "CREL", sources: ["DT_CREL"],
    sectionIndex: null, symbolTableIndex: null, targetSectionIndex: null };
};
