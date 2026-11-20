import { DwarfCursor } from "../dwarf/cursor.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfProgramHeader } from "./types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfEhFrameHeaderValue } from "./unwind-pointer.js";

// GNU program header points to .eh_frame_hdr, whose first operand points to .eh_frame.
// https://raw.githubusercontent.com/llvm/llvm-project/main/libunwind/src/EHHeaderParser.hpp
export const findElfEhFrameHeader = (headers: ElfProgramHeader[]): ElfProgramHeader | undefined =>
  headers.find(header => header.type === 0x6474e550 && header.filesz > 0n);

type FrameHeaderLocation = { offset: bigint; size: bigint; addr: bigint };
type FrameHeaderFields = { frameEncoding: number; countEncoding: number; tableEncoding: number };

const readHeaderFields = async (cursor: DwarfCursor, issues: string[]): Promise<FrameHeaderFields | null> => {
  const version = await cursor.uint8();
  if (version == null) return null;
  if (version !== 1) {
    issues.push(`.eh_frame_hdr has unexpected version ${version}.`);
    return null;
  }
  const frameEncoding = await cursor.uint8();
  const countEncoding = await cursor.uint8();
  const tableEncoding = await cursor.uint8();
  return frameEncoding == null || countEncoding == null || tableEncoding == null ? null :
    { frameEncoding, countEncoding, tableEncoding };
};

export const openElfEhFrameHeader = async (
  reader: FileRangeReader, header: FrameHeaderLocation, littleEndian: boolean, issues: string[]
) => {
  const range = elfFileRange(header.offset, header.size, reader.size);
  if (!range) {
    issues.push(".eh_frame_hdr is truncated or outside the file.");
    return null;
  }
  const cursor = new DwarfCursor(reader, { ...range, name: ".eh_frame_hdr", compressed: false },
    0, range.size, littleEndian, issues);
  const fields = await readHeaderFields(cursor, issues);
  return fields ? { cursor, ...fields } : null;
};

export const readElfEhFrameAddress = async (
  cursor: DwarfCursor, encoding: number, width: number, addr: bigint, issues: string[]
): Promise<bigint | null> => {
  const frame = await readElfEhFrameHeaderValue(cursor, encoding, width, addr);
  if (frame == null && encoding !== 0xff) {
    issues.push(".eh_frame_hdr uses an unsupported eh_frame_ptr encoding or the operand is truncated.");
  }
  return frame;
};
