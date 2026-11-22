import type { ElfProgramHeader } from "./types.js";
import { ELF_SEGMENT_TYPE } from "./abi-constants.js";

type Range = { start: bigint; end: bigint };

export const createElfRangeCoverage = (ranges: Range[]) => {
  const ordered = [...ranges].sort((left, right) =>
    left.start < right.start ? -1 : Number(left.start > right.start));
  return (start: bigint, end: bigint): boolean => {
    if (start >= end) return start === end;
    let covered = start;
    for (const range of ordered) {
      if (range.start > covered) break;
      if (range.end > covered) covered = range.end;
      if (covered >= end) return true;
    }
    return false;
  };
};

export const elfRangesCover = (ranges: Range[], start: bigint, end: bigint): boolean =>
  createElfRangeCoverage(ranges)(start, end);

// Consecutive PT_LOAD ranges can cover one structure only when they map
// its file bytes to the same virtual addresses (gABI 7.1 and 7.2).
// https://gabi.xinuos.com/elf/07-pheader.html
export const elfLoadMappingCovers = (
  headers: ElfProgramHeader[], offset: bigint, address: bigint, size: bigint
): boolean => {
  const translation = address - offset;
  const ranges = headers.filter(load => load.type === ELF_SEGMENT_TYPE.LOAD &&
    load.filesz <= load.memsz && load.vaddr - load.offset === translation)
    .map(load => ({ start: load.offset, end: load.offset + load.filesz }));
  return elfRangesCover(ranges, offset, offset + size);
};
