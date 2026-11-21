import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfLsda, ElfLsdaCursorAt } from "./lsda-types.js";
import type { ElfUnwindFde } from "./unwind-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfUnwindPointer } from "./unwind-pointer.js";
import { readElfLsdaActions } from "./lsda-actions.js";
import { readElfLsdaCallSites, readElfLsdaTypes } from "./lsda-tables.js";
import { elfLoadFileTail } from "./load-file-tail.js";

type LsdaFrame = { fde: ElfUnwindFde; source: "runtime" | "debug" };

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
  section: ElfSectionHeader | undefined, { fde, source }: LsdaFrame, nextAddress?: bigint): Promise<ElfLsda> => {
  const result: ElfLsda = { address: fde.lsda!.address, landingPadBase: fde.start,
    typeEncoding: 255, callSiteEncoding: 255, callSites: [], actions: [], types: [], specifications: [], issues: [] };
  if (fde.lsda!.indirect || (section && (section.flags & 0x800n)) ||
      (!section && elf.sections.length && source === "debug")) {
    result.issues.push("LSDA requires a direct pointer into an uncompressed .gcc_except_table section " +
      "or a file-backed PT_LOAD mapped from runtime unwind data.");
    return result;
  }
  const storage = section
    ? elfFileRange(section.offset + result.address - section.addr,
      section.addr + section.size - result.address, reader.size)
    : elfLoadFileTail(elf.programHeaders, result.address, reader.size);
  if (!storage) {
    result.issues.push(section ? "LSDA section is truncated or outside the file." :
      "LSDA address does not have an unambiguous file-backed PT_LOAD mapping.");
    return result;
  }
  if (!section) result.segmentBacked = true;
  const size = nextAddress != null && nextAddress - result.address < BigInt(storage.size)
    ? Number(nextAddress - result.address) : storage.size;
  const range = { offset: storage.offset, size };
  const cursorAt: ElfLsdaCursorAt = (position, end = range.size) => new DwarfCursor(reader,
    { ...range, name: "LSDA", compressed: false }, position, Math.min(end, range.size), elf.littleEndian, result.issues);
  await readTables(cursorAt, elf.is64 ? 8 : 4, result);
  return result;
};

// GCC/LLVM Itanium LSDA layout, as consumed by libcxxabi cxa_personality.cpp.
export const parseElfLsda = async (file: File, elf: ElfParseResult,
  nativeAotLsdas: ReadonlySet<bigint> = new Set()): Promise<ElfLsda[]> => {
  const results: ElfLsda[] = [];
  const reader = createFileRangeReader(file, 0, file.size);
  const frames = lsdaFrames(elf);
  for (const [index, frame] of frames.entries()) {
    const address = frame.fde.lsda!.address;
    if (nativeAotLsdas.has(address)) continue;
    const section = elf.sections.find(item => item.name === ".gcc_except_table" &&
      address >= item.addr && address < item.addr + item.size);
    results.push(await readDescriptor(reader, elf, section, frame, frames[index + 1]?.fde.lsda?.address));
  }
  return results;
};

const lsdaFrames = (elf: ElfParseResult): LsdaFrame[] => {
  const unique = new Map<bigint, LsdaFrame>();
  for (const record of elf.unwind ?? []) {
    const runtime = record.sectionIndex === null ||
      elf.sections[record.sectionIndex]?.name === ".eh_frame";
    for (const fde of record.fdes) {
      if (!fde.lsda?.address || unique.has(fde.lsda.address)) continue;
      unique.set(fde.lsda.address, { fde, source: runtime ? "runtime" : "debug" });
    }
  }
  return [...unique.values()].sort((left, right) => left.fde.lsda!.address < right.fde.lsda!.address ? -1 : 1);
};
