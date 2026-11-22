import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult, ElfProgramHeader } from "./types.js";
import { openElfEhFrameHeader, readElfEhFrameAddress } from "./eh-frame-header.js";
import { elfLoadFileTail } from "./load-file-tail.js";
import { readElfEhFrameHeaderValue } from "./unwind-pointer.js";

export const locateSegmentUnwind = async (
  reader: FileRangeReader, elf: ElfParseResult, header: ElfProgramHeader, issues: string[]
) => {
  const opened = await openElfEhFrameHeader(reader,
    { offset: header.offset, size: header.filesz, addr: header.vaddr }, elf.littleEndian, issues);
  if (!opened) return null;
  const addr = await readElfEhFrameAddress(opened.cursor, opened.frameEncoding,
    elf.is64 ? 8 : 4, header.vaddr, issues);
  if (addr == null) {
    if (!opened.cursor.failed) issues.push("PT_GNU_EH_FRAME does not supply an .eh_frame address.");
    return null;
  }
  // libunwind finds the end of a sectionless .eh_frame using its zero-length record.
  // https://raw.githubusercontent.com/llvm/llvm-project/main/libunwind/src/AddressSpace.hpp
  const range = elfLoadFileTail(elf.programHeaders, addr, reader.size);
  if (!range) {
    issues.push(".eh_frame address does not have an unambiguous file-backed PT_LOAD mapping.");
    return null;
  }
  const count = opened.tableEncoding === 0xff ? null : await readElfEhFrameHeaderValue(
    opened.cursor, opened.countEncoding, elf.is64 ? 8 : 4, header.vaddr);
  // Each index entry contains at least two encoded operands.
  const fdeCount = count != null && count >= 0n &&
    count <= BigInt(Math.floor((opened.cursor.end - opened.cursor.position) / 2)) ? Number(count) : undefined;
  return { ...range, addr, name: ".eh_frame", fdeCount };
};
