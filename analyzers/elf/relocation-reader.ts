import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfProgramHeader } from "./types.js";
import { ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { DEFAULT_FILE_READ_WINDOW_BYTES } from "../file-range-reader.js";

// ELF gABI, Relocation entries and Program loading:
// https://gabi.xinuos.com/elf/06-reloc.html
// https://gabi.xinuos.com/elf/07-pheader.html
export const elfFileRange = (
  offset: bigint, size: bigint, fileSize: number
): { offset: number; size: number } | null => {
  if (offset < 0n || size < 0n || offset + size > BigInt(fileSize)) return null;
  return { offset: Number(offset), size: Number(size) };
};

export const elfVirtualRange = (
  headers: ElfProgramHeader[], address: bigint, size: bigint, fileSize: number
): { offset: number; size: number } | null => {
  if (address < 0n || size < 0n) return null;
  const segment = headers.find(header => header.type === ELF_SEGMENT_TYPE.LOAD && header.filesz <= header.memsz &&
    address >= header.vaddr && address + size <= header.vaddr + header.filesz);
  return segment ? elfFileRange(segment.offset + address - segment.vaddr, size, fileSize) : null;
};

export const readElfRelocationString = async (
  reader: FileRangeReader, offset: bigint, size: bigint, issues: string[]
): Promise<string> => {
  const range = elfFileRange(offset, size, reader.size);
  if (!range) {
    issues.push("Relocation symbol string is outside the file.");
    return "";
  }
  const decoder = new TextDecoder();
  const parts: string[] = [];
  // Reuse the measured I/O window; it bounds each read, not the total name length.
  for (let consumed = 0; consumed < range.size;) {
    const view = await reader.read(range.offset + consumed,
      Math.min(range.size - consumed, DEFAULT_FILE_READ_WINDOW_BYTES));
    if (!view.byteLength) break;
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    const end = bytes.indexOf(0);
    if (end >= 0) return parts.join("") + decoder.decode(bytes.subarray(0, end));
    parts.push(decoder.decode(bytes, { stream: true }));
    consumed += bytes.length;
  }
  issues.push("Relocation symbol name is unterminated.");
  return parts.join("") + decoder.decode();
};
