import { createFileRangeReader } from "../file-range-reader.js";
import { DwarfCursor } from "../dwarf/cursor.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfUnwindSection } from "./unwind-types.js";
import { elfFileRange } from "./relocation-reader.js";
import { readElfUnwindCie } from "./unwind-cie.js";
import { readElfUnwindFde } from "./unwind-fde.js";
import { elfDwarfFrames } from "./dwarf-frames.js";
import { findElfEhFrameHeader } from "./eh-frame-header.js";
import { locateSegmentUnwind } from "./unwind-segment.js";

type FrameSource = { offset: number; size: number; addr: bigint; name: string };

interface FrameRecord {
  offset: number;
  body: number;
  end: number;
  cieOffset: number | null;
}

const cieReference = (name: string, id: bigint, idSize: number, idOffset: number): number | null => {
  if (name === ".debug_frame") {
    return id === (1n << BigInt(idSize * 8)) - 1n ? null : Number(id);
  }
  return id === 0n ? null : idOffset - Number(id);
};

const frameLength = async (cursor: DwarfCursor): Promise<{ size: bigint; width: number } | null> => {
  const length = await cursor.uint32();
  if (length == null || length === 0) return null;
  if (length >= 0xfffffff0 && length !== 0xffffffff) {
    cursor.fail("Reserved unwind record length");
    return null;
  }
  const size = length === 0xffffffff ? await cursor.uint64() : BigInt(length);
  return size == null ? null : { size, width: length === 0xffffffff ? 8 : 4 };
};

// DWARF 5 7.2.2 initial lengths; .eh_frame keeps 4-byte CIE ids even with extended length.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
const readFrameRecord = async (
  cursor: DwarfCursor, sectionName: string
): Promise<FrameRecord | null> => {
  const offset = cursor.position;
  const length = await frameLength(cursor);
  if (!length) return null;
  const idOffset = cursor.position;
  const idSize = sectionName === ".debug_frame" ? length.width : 4;
  if (length.size < BigInt(idSize) || length.size > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Unwind record is truncated or has an invalid length");
    return null;
  }
  const id = await cursor.unsigned(idSize);
  if (id == null) return null;
  return { offset, body: cursor.position, end: idOffset + Number(length.size),
    cieOffset: cieReference(sectionName, id, idSize, idOffset) };
};

const unavailableSection = (
  section: ElfSectionHeader, elf: ElfParseResult, issues: string[]
): boolean => {
  if (!elfFileRange(section.offset, section.size, elf.fileSize)) {
    issues.push("Unwind section is truncated or outside the file.");
    return true;
  }
  if (section.flags & 0x800n) {
    issues.push("Compressed unwind section is not decoded.");
    return true;
  }
  if (elf.sections.some(item => (item.type === 4 || item.type === 9) && item.info === section.index)) {
    issues.push("Unwind section requires relocations; unresolved addresses are not decoded.");
    return true;
  }
  return false;
};

const readUnwindSection = async (
  reader: FileRangeReader, elf: ElfParseResult, section: ElfSectionHeader
): Promise<ElfUnwindSection> => {
  const result: ElfUnwindSection = { sectionIndex: section.index, cies: [], fdes: [], issues: [] };
  if (section.name === ".debug_frame" && elf.dwarf) {
    return elf.dwarf.frames ? elfDwarfFrames(elf.dwarf.frames, section.index) : result;
  }
  if (unavailableSection(section, elf, result.issues)) return result;
  return readUnwindFrames(reader, elf, { offset: Number(section.offset), size: Number(section.size),
    addr: section.addr, name: section.name! }, result);
};

const readUnwindFrames = async (
  reader: FileRangeReader, elf: ElfParseResult, source: FrameSource, result: ElfUnwindSection
): Promise<ElfUnwindSection> => {
  const cursorAt = (position: number, end: number) => new DwarfCursor(reader,
    { name: source.name, offset: source.offset, size: source.size, compressed: false },
    position, end, elf.littleEndian, result.issues);
  const cursor = cursorAt(0, source.size);
  const pending: FrameRecord[] = [];
  let terminated = false;
  while (cursor.position < cursor.end) {
    const record = await readFrameRecord(cursor, source.name);
    if (!record) {
      terminated = !cursor.failed;
      break;
    }
    if (record.cieOffset == null) {
      const cie = await readElfUnwindCie(cursorAt(record.body, record.end), record.offset,
        elf.is64 ? 8 : 4, source.addr, elf.header.machine);
      if (cie) result.cies.push(cie);
    } else pending.push(record);
    cursor.position = record.end;
  }
  if (result.sectionIndex === null && !terminated && !cursor.failed) {
    result.issues.push("No .eh_frame terminator before the end of the file-backed PT_LOAD.");
  }
  await readPendingFdes(pending, result, cursorAt, source.addr, elf.header.machine);
  return result;
};

const readPendingFdes = async (
  pending: FrameRecord[], result: ElfUnwindSection,
  cursorAt: (position: number, end: number) => DwarfCursor,
  address: bigint, machine: number
): Promise<void> => {
  const cies = new Map(result.cies.map(cie => [cie.offset, cie]));
  for (const record of pending) {
    const cie = cies.get(record.cieOffset!);
    if (!cie) {
      result.issues.push(`FDE at 0x${record.offset.toString(16)} references an invalid CIE.`);
      continue;
    }
    const fde = await readElfUnwindFde(cursorAt(record.body, record.end), record.offset,
      cie, address, machine);
    if (fde) result.fdes.push(fde);
  }
};

export const parseElfUnwind = async (file: File, elf: ElfParseResult): Promise<ElfUnwindSection[]> => {
  const reader = createFileRangeReader(file, 0, file.size);
  const result: ElfUnwindSection[] = [];
  const sections = elf.sections.filter(item => item.name === ".eh_frame" || item.name === ".debug_frame");
  let haveRuntimeFrames = false;
  for (const section of sections) {
    const frames = await readUnwindSection(reader, elf, section);
    result.push(frames);
    if (section.name === ".eh_frame" && frames.fdes.length) haveRuntimeFrames = true;
  }
  if (!haveRuntimeFrames) {
    const fallback = await readSegmentFrames(reader, elf, sections);
    if (fallback) result.push(fallback);
  }
  return result;
};

const readSegmentFrames = async (
  reader: FileRangeReader, elf: ElfParseResult, attempted: ElfSectionHeader[]
): Promise<ElfUnwindSection | null> => {
  const header = findElfEhFrameHeader(elf.programHeaders);
  if (!header) return null;
  const unwind: ElfUnwindSection = { sectionIndex: null, programHeaderIndex: header.index,
    cies: [], fdes: [], issues: [] };
  const source = await locateSegmentUnwind(reader, elf, header, unwind.issues);
  if (!source) return unwind;
  const start = BigInt(source.offset);
  // An in-file, overlapping .eh_frame has already been handled by the section path.
  // An out-of-file section size does not invalidate an independently bounded PT_LOAD.
  if (attempted.some(section => section.name === ".eh_frame" &&
    start >= section.offset && start < section.offset + section.size &&
    elfFileRange(section.offset, section.size, reader.size))) return null;
  return readUnwindFrames(reader, elf, source, unwind);
};
