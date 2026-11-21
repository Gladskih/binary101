import { ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfFileRange } from "./relocation-reader.js";
import type { ElfProgramHeader } from "./types.js";

// ELF gABI 7: file data occupies the first p_filesz bytes of a PT_LOAD.
// https://gabi.xinuos.com/elf/07-pheader.html
export const elfLoadFileTail = (
  headers: ElfProgramHeader[], address: bigint, fileSize: number
): { offset: number; size: number } | null => {
  const ranges = headers.flatMap(header => {
    if (header.type !== ELF_SEGMENT_TYPE.LOAD || header.filesz > header.memsz) return [];
    const displacement = address - header.vaddr;
    if (displacement < 0n || displacement >= header.filesz) return [];
    const range = elfFileRange(header.offset + displacement, header.filesz - displacement, fileSize);
    return range ? [range] : [];
  });
  const first = ranges[0];
  if (!first || ranges.some(range => range.offset !== first.offset)) return null;
  return { offset: first.offset, size: ranges.reduce((size, range) => Math.min(size, range.size), first.size) };
};
