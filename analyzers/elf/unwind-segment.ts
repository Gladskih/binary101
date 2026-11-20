import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult, ElfProgramHeader } from "./types.js";
import { openElfEhFrameHeader, readElfEhFrameAddress } from "./eh-frame-header.js";
import { elfFileRange } from "./relocation-reader.js";
import { ELF_SEGMENT_TYPE } from "./abi-constants.js";

// libunwind finds the end of a sectionless .eh_frame using its zero-length record.
// Bound that walk to the file-backed part of the containing PT_LOAD.
// https://raw.githubusercontent.com/llvm/llvm-project/main/libunwind/src/AddressSpace.hpp
const frameLoadRange = (elf: ElfParseResult, address: bigint, fileSize: number) => {
  const ranges = elf.programHeaders.flatMap(header => {
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
  const range = frameLoadRange(elf, addr, reader.size);
  if (!range) {
    issues.push(".eh_frame address does not have an unambiguous file-backed PT_LOAD mapping.");
    return null;
  }
  return { ...range, addr, name: ".eh_frame" };
};
