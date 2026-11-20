import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";
import { findElfEhFrameHeader, openElfEhFrameHeader, readElfEhFrameAddress } from "./eh-frame-header.js";
import { readElfEhFrameHeaderValue } from "./unwind-pointer.js";

type DisassemblyHeaderInput = {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
};

type OpenedHeader = NonNullable<Awaited<ReturnType<typeof openElfEhFrameHeader>>>;

const readStartPcs = async (
  header: OpenedHeader, addr: bigint, width: number, issues: string[]
): Promise<bigint[]> => {
  const { cursor, frameEncoding, countEncoding, tableEncoding } = header;
  await readElfEhFrameAddress(cursor, frameEncoding, width, addr, issues);
  if (cursor.failed) return [];
  const count = await readElfEhFrameHeaderValue(cursor, countEncoding, width, addr);
  if (count == null) {
    issues.push(".eh_frame_hdr uses an unsupported fde_count encoding or the operand is truncated.");
    return [];
  }
  if (count < 0n || count > BigInt(Math.floor((cursor.end - cursor.position) / 2))) {
    issues.push(".eh_frame_hdr search table count exceeds its available entries.");
    return [];
  }
  const vaddrs: bigint[] = [];
  for (let index = 0; index < Number(count); index += 1) {
    const pc = await readElfEhFrameHeaderValue(cursor, tableEncoding, width, addr);
    if (pc == null || await readElfEhFrameHeaderValue(cursor, tableEncoding, width, addr) == null) break;
    if (pc > 0n) vaddrs.push(pc);
  }
  return vaddrs;
};

export async function collectElfDisassemblySeedsFromEhFrameHdr(
  opts: DisassemblyHeaderInput
): Promise<ElfDisassemblySeedGroup[]> {
  const segment = findElfEhFrameHeader(opts.programHeaders);
  const source = segment ? { offset: segment.offset, size: segment.filesz, addr: segment.vaddr } :
    opts.sections.find(section => section.name === ".eh_frame_hdr" && section.size > 0n);
  if (!source) return [];
  const header = await openElfEhFrameHeader(createFileRangeReader(opts.file, 0, opts.file.size),
    source, opts.littleEndian, opts.issues);
  if (!header || header.tableEncoding === 0xff) return [];
  const vaddrs = await readStartPcs(header, source.addr, opts.is64 ? 8 : 4, opts.issues);
  return vaddrs.length ? [{ source: ".eh_frame_hdr start PCs", vaddrs }] : [];
}
