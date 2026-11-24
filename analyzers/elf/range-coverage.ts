import type { ElfProgramHeader } from "./types.js";
import { ELF_SEGMENT_TYPE } from "./abi-constants.js";

type Range = { start: bigint; end: bigint };

// Sort uses only the sign of the difference, including for ELF64 addresses.
const orderRanges = (ranges: Range[]): Range[] => [...ranges].sort((left, right) => Number(left.start - right.start));

const coveredEnd = (ordered: Range[], start: bigint, limit: bigint | null): bigint => {
  let covered = start;
  for (const range of ordered) {
    if (range.start > covered) break;
    if (range.end > covered) covered = range.end;
    if (limit !== null && covered >= limit) return limit;
  }
  return covered;
};

export const createElfRangeCoverage = (ranges: Range[]) => {
  const ordered = orderRanges(ranges);
  return (start: bigint, end: bigint): boolean =>
    start <= end && coveredEnd(ordered, start, end) === end;
};

export const elfRangesCover = (ranges: Range[], start: bigint, end: bigint): boolean =>
  createElfRangeCoverage(ranges)(start, end);

const fileBackedLoad = (header: ElfProgramHeader): boolean =>
  header.type === ELF_SEGMENT_TYPE.LOAD && header.filesz <= header.memsz;

const emptyLoadFileOffset = (headers: ElfProgramHeader[], address: bigint): bigint | null => {
  const anchor = headers.find(load => fileBackedLoad(load) &&
    address >= load.vaddr && address <= load.vaddr + load.filesz);
  return anchor ? anchor.offset + address - anchor.vaddr : null;
};

const loadSpanEnd = (
  headers: ElfProgramHeader[], address: bigint, translation: bigint, limit: bigint | null
): bigint => {
  let bound = limit;
  const ranges: Range[] = [];
  for (const load of headers) {
    if (!fileBackedLoad(load) || !load.filesz || load.vaddr + load.filesz <= address) continue;
    if (load.vaddr - load.offset === translation) {
      ranges.push({ start: load.vaddr, end: load.vaddr + load.filesz });
    } else if (bound === null || load.vaddr < bound) {
      bound = load.vaddr;
    }
  }
  return coveredEnd(orderRanges(ranges), address, bound);
};

// gABI 7.1/7.2 maps each PT_LOAD's initialized bytes linearly. A single
// file range can span multiple loads while this translation stays unique.
// https://gabi.xinuos.com/elf/07-pheader.html
export const elfLoadFileSpan = (
  headers: ElfProgramHeader[], address: bigint, size?: bigint
): { offset: bigint; size: bigint } | null => {
  if (address < 0n) return null;
  if (size === 0n) {
    const offset = emptyLoadFileOffset(headers, address);
    return offset === null ? null : { offset, size };
  }
  const anchor = headers.find(load => fileBackedLoad(load) &&
    load.vaddr <= address && load.vaddr + load.filesz > address);
  if (!anchor) return null;
  const translation = anchor.vaddr - anchor.offset;
  const end = loadSpanEnd(headers, address, translation, size === undefined ? null : address + size);
  return end > address ? { offset: address - translation, size: end - address } : null;
};

export const elfLoadMappingCovers = (
  headers: ElfProgramHeader[], offset: bigint, address: bigint, size: bigint
): boolean => {
  const mapping = elfLoadFileSpan(headers, address, size);
  return mapping?.offset === offset && mapping.size === size;
};

type FileFragment = { offset: bigint; size: bigint };

const collectLoadFragments = (ordered: (Range & { offset: bigint })[], address: bigint) => {
  const fragments: FileFragment[] = [];
  let covered = address;
  for (const load of ordered) {
    if (load.start > covered) return null;
    const offset = load.offset + covered - load.start;
    const previous = fragments.at(-1);
    const adjacent = previous && previous.offset + previous.size === offset;
    if (previous && load.start < covered && !adjacent) return null;
    if (load.end <= covered) continue;
    if (adjacent) previous.size += load.end - covered;
    else fragments.push({ offset, size: load.end - covered });
    covered = load.end;
  }
  return { fragments, covered };
};

// Runtime pointers describe virtual bytes (gABI 8.3). Adjacent loads can
// supply those bytes from different file offsets, in virtual address order.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
export const elfLoadFileFragments = (headers: ElfProgramHeader[], address: bigint, size: bigint):
FileFragment[] | null => {
  if (address < 0n || size <= 0n) return null;
  const end = address + size;
  const ordered = headers.filter(load => fileBackedLoad(load) && load.filesz > 0n &&
    load.vaddr < end && load.vaddr + load.filesz > address)
    .map(load => {
      const loadEnd = load.vaddr + load.filesz;
      return { start: load.vaddr, end: loadEnd < end ? loadEnd : end, offset: load.offset };
    })
    .sort((left, right) => Number(left.start - right.start));
  const mapping = collectLoadFragments(ordered, address);
  return mapping?.covered === end ? mapping.fragments : null;
};
