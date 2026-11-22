import { ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { elfFileRange } from "./relocation-reader.js";
import type { ElfProgramHeader } from "./types.js";

const loadFileTails = (headers: ElfProgramHeader[], address: bigint) => headers.flatMap(header => {
  if (header.type !== ELF_SEGMENT_TYPE.LOAD || header.filesz > header.memsz) return [];
  const displacement = address - header.vaddr;
  if (displacement < 0n || displacement >= header.filesz) return [];
  return [{ offset: header.offset + displacement, size: header.filesz - displacement }];
});

const commonFileRange = (
  ranges: { offset: number; size: number }[]
): { offset: number; size: number } | null => {
  const first = ranges[0];
  if (!first || ranges.some(range => range.offset !== first.offset)) return null;
  return { offset: first.offset, size: ranges.reduce((size, range) => Math.min(size, range.size), first.size) };
};

// ELF gABI 7: file data occupies the first p_filesz bytes of a PT_LOAD.
// https://gabi.xinuos.com/elf/07-pheader.html
export const elfLoadFileTail = (
  headers: ElfProgramHeader[], address: bigint, fileSize: number
): { offset: number; size: number } | null =>
  commonFileRange(loadFileTails(headers, address).flatMap(({ offset, size }) => {
    const range = elfFileRange(offset, size, fileSize);
    return range ? [range] : [];
  }));

// Fixed-size record readers can keep complete records in a truncated prefix.
export const elfLoadFilePrefix = (
  headers: ElfProgramHeader[], address: bigint, requestedSize: bigint, fileSize: number
): { offset: number; size: number } | null =>
  commonFileRange(loadFileTails(headers, address).flatMap(({ offset, size }) => {
    const length = [size, requestedSize, BigInt(fileSize) - offset].reduce(
      (smallest, limit) => smallest < limit ? smallest : limit);
    const range = length > 0n ? elfFileRange(offset, length, fileSize) : null;
    return range ? [range] : [];
  }));
