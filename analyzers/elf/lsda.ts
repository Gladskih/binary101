import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfLsda, ElfLsdaCursorAt } from "./lsda-types.js";
import type { ElfUnwindFde } from "./unwind-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfUnwindPointer } from "./unwind-pointer.js";
import { readElfLsdaActions } from "./lsda-actions.js";
import { readElfLsdaCallSites, readElfLsdaTypes } from "./lsda-tables.js";

const readHeader = async (
  cursor: DwarfCursor, addressSize: number, result: ElfLsda
): Promise<number | null> => {
  const encoding = await cursor.uint8();
  if (encoding == null) return null;
  if (encoding !== 255) {
    result.landingPadBase = await readElfUnwindPointer(cursor, encoding, addressSize, result.address);
  }
  const typeEncoding = await cursor.uint8();
  if (typeEncoding == null) return null;
  result.typeEncoding = typeEncoding;
  if (typeEncoding === 255) return null;
  const offset = await cursor.uleb();
  if (offset == null) return null;
  if (offset > BigInt(cursor.end - cursor.position)) { cursor.fail("LSDA type table is truncated"); return null; }
  return cursor.position + Number(offset);
};

const readTables = async (cursorAt: ElfLsdaCursorAt, addressSize: number, result: ElfLsda): Promise<void> => {
  const cursor = cursorAt(0);
  const typeBase = await readHeader(cursor, addressSize, result);
  const encoding = await cursor.uint8();
  const size = await cursor.uleb();
  if (cursor.failed || encoding == null || size == null) return;
  result.callSiteEncoding = encoding;
  if (size > BigInt(cursor.end - cursor.position)) { cursor.fail("LSDA call-site table is truncated"); return; }
  const actionStart = cursor.position + Number(size);
  await readElfLsdaCallSites(cursorAt(cursor.position, actionStart), addressSize, result);
  await readElfLsdaActions(cursorAt, actionStart, typeBase ?? cursor.end, result);
  await readElfLsdaTypes(cursorAt, typeBase, addressSize, result);
};

const readDescriptor = async (reader: FileRangeReader, elf: ElfParseResult,
  section: ElfSectionHeader | undefined, fde: ElfUnwindFde, nextAddress?: bigint): Promise<ElfLsda> => {
  const result: ElfLsda = { address: fde.lsda!.address, landingPadBase: fde.start,
    typeEncoding: 255, callSiteEncoding: 255, callSites: [], actions: [], types: [], specifications: [], issues: [] };
  if (!section || fde.lsda!.indirect || (section.flags & 0x800n)) {
    result.issues.push("LSDA requires a direct pointer into an uncompressed .gcc_except_table section.");
    return result;
  }
  const skip = result.address - section.addr;
  const end = nextAddress != null && nextAddress < section.addr + section.size
    ? nextAddress : section.addr + section.size;
  const range = elfFileRange(section.offset + skip, end - result.address, reader.size);
  if (!range) { result.issues.push("LSDA section is truncated or outside the file."); return result; }
  const cursorAt: ElfLsdaCursorAt = (position, end = range.size) => new DwarfCursor(reader,
    { ...range, name: "LSDA", compressed: false }, position, Math.min(end, range.size), elf.littleEndian, result.issues);
  await readTables(cursorAt, elf.is64 ? 8 : 4, result);
  return result;
};

// GCC/LLVM Itanium LSDA layout, as consumed by libcxxabi cxa_personality.cpp.
export const parseElfLsda = async (file: File, elf: ElfParseResult): Promise<ElfLsda[]> => {
  const results: ElfLsda[] = [];
  const reader = createFileRangeReader(file, 0, file.size);
  const frames = lsdaFrames(elf);
  for (const [index, fde] of frames.entries()) {
    const address = fde.lsda!.address;
    const section = elf.sections.find(item => item.name === ".gcc_except_table" &&
      address >= item.addr && address < item.addr + item.size);
    results.push(await readDescriptor(reader, elf, section, fde, frames[index + 1]?.lsda?.address));
  }
  return results;
};

const lsdaFrames = (elf: ElfParseResult): ElfUnwindFde[] => {
  const unique = new Map<bigint, ElfUnwindFde>();
  for (const fde of (elf.unwind ?? []).flatMap(section => section.fdes)) {
    if (fde.lsda && fde.lsda.address !== 0n && !unique.has(fde.lsda.address)) unique.set(fde.lsda.address, fde);
  }
  return [...unique.values()].sort((left, right) => left.lsda!.address < right.lsda!.address ? -1 : 1);
};
