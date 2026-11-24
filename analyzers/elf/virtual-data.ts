import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfProgramHeader } from "./types.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import { elfLoadFileFragments } from "./range-coverage.js";

type FileRange = { offset: number; size: number };
export type ElfDataRange = FileRange & { fragments?: FileRange[] };

export const elfVirtualDataRange = (
  headers: ElfProgramHeader[], address: bigint, size: bigint, fileSize: number
): ElfDataRange | null => {
  const contiguous = elfVirtualRange(headers, address, size, fileSize);
  if (contiguous) return contiguous;
  if (size > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const fragments = elfLoadFileFragments(headers, address, size);
  if (!fragments) return null;
  const bounded: FileRange[] = [];
  for (const fragment of fragments) {
    const range = elfFileRange(fragment.offset, fragment.size, fileSize);
    if (!range) return null;
    bounded.push(range);
  }
  return { offset: bounded[0]!.offset, size: Number(size), fragments: bounded };
};

type VirtualFragment = FileRange & { start: number; end: number };

const fragmentAt = (fragments: VirtualFragment[], position: number): number => {
  let low = 0;
  let high = fragments.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (fragments[middle]!.end <= position) low = middle + 1;
    else high = middle;
  }
  return low;
};

const readFragments = async (
  reader: FileRangeReader, fragments: VirtualFragment[], index: number, position: number, size: number
): Promise<Uint8Array> => {
  const first = fragments[index]!;
  const firstLength = Math.min(size, first.end - position);
  const firstBytes = await reader.readBytes(first.offset + position - first.start, firstLength);
  if (firstBytes.length === size || firstBytes.length < firstLength) return firstBytes;
  const result = new Uint8Array(size);
  result.set(firstBytes);
  let written = firstBytes.length;
  for (let current = index + 1; written < size; current += 1) {
    const fragment = fragments[current]!;
    const cursor = position + written;
    const length = Math.min(size - written, fragment.end - cursor);
    const bytes = await reader.readBytes(fragment.offset + cursor - fragment.start, length);
    result.set(bytes, written);
    written += bytes.byteLength;
    if (bytes.byteLength < length) break;
  }
  return result.subarray(0, written);
};

export const openElfDataRange = (
  reader: FileRangeReader, range: ElfDataRange
): FileRange & { reader: FileRangeReader } => {
  if (!range.fragments) return { offset: range.offset, size: range.size, reader };
  let cursor = 0;
  const fragments = range.fragments.map(fragment => {
    const start = cursor;
    cursor += fragment.size;
    return { ...fragment, start, end: cursor };
  });
  const size = range.size;
  const readBytes = (position: number, length: number): Promise<Uint8Array> => {
    if (!Number.isSafeInteger(position) || !Number.isSafeInteger(length) ||
        position < 0 || position >= size || length <= 0) return Promise.resolve(new Uint8Array());
    return readFragments(reader, fragments, fragmentAt(fragments, position),
      position, Math.min(length, size - position));
  };
  return { offset: 0, size, reader: { size, readBytes, read: async (position, length) => {
    const bytes = await readBytes(position, length);
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  } } };
};
