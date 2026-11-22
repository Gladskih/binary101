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

type FrameSource = { offset: number; size: number; addr: bigint; name: string; fdeCount?: number | undefined };
type FrameStop = "terminator" | "short-record" | "invalid";
type Continuation = { offset: number; stop: "section-end" | "short-record" };
type SectionScan = { section: ElfSectionHeader; frames: ElfUnwindSection; continuation?: Continuation };

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

const frameLength = async (cursor: DwarfCursor): Promise<{ size: bigint; width: number } | FrameStop> => {
  const available = cursor.end - cursor.position;
  const length = await cursor.uint32();
  if (length == null) return available < 4 ? "short-record" : "invalid";
  if (length === 0) return "terminator";
  if (length >= 0xfffffff0 && length !== 0xffffffff) {
    cursor.fail("Reserved unwind record length");
    return "invalid";
  }
  const size = length === 0xffffffff ? await cursor.uint64() : BigInt(length);
  return size == null ? available < 12 ? "short-record" : "invalid" :
    { size, width: length === 0xffffffff ? 8 : 4 };
};

// DWARF 5 7.2.2 initial lengths; .eh_frame keeps 4-byte CIE ids even with extended length.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/ehframechpt.html
const readFrameRecord = async (
  cursor: DwarfCursor, sectionName: string
): Promise<FrameRecord | FrameStop> => {
  const offset = cursor.position;
  const length = await frameLength(cursor);
  if (typeof length === "string") return length;
  const idOffset = cursor.position;
  const idSize = sectionName === ".debug_frame" ? length.width : 4;
  if (length.size < BigInt(idSize) || length.size > BigInt(cursor.end - cursor.position)) {
    cursor.fail("Unwind record is truncated or has an invalid length");
    return length.size < BigInt(idSize) ? "invalid" : "short-record";
  }
  const id = await cursor.unsigned(idSize);
  if (id == null) return "invalid";
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
): Promise<SectionScan> => {
  const frames: ElfUnwindSection = { sectionIndex: section.index, cies: [], fdes: [], issues: [] };
  if (section.name === ".debug_frame" && elf.dwarf) {
    return { section, frames: elf.dwarf.frames ? elfDwarfFrames(elf.dwarf.frames, section.index) : frames };
  }
  if (unavailableSection(section, elf, frames.issues)) return { section, frames };
  const continuation = await readUnwindFrames(reader, elf, { offset: Number(section.offset),
    size: Number(section.size), addr: section.addr, name: section.name! }, frames);
  return { section, frames, ...(continuation && { continuation }) };
};

const readUnwindFrames = async (
  reader: FileRangeReader, elf: ElfParseResult, source: FrameSource, result: ElfUnwindSection, start = 0
): Promise<Continuation | undefined> => {
  const cursorAt = (position: number, end: number) => new DwarfCursor(reader,
    { name: source.name, offset: source.offset, size: source.size, compressed: false },
    position, end, elf.littleEndian, result.issues);
  const cursor = cursorAt(start, source.size);
  const pending: FrameRecord[] = [];
  let stop: FrameStop | "section-end" = "section-end";
  let offset = start;
  while (cursor.position < cursor.end) {
    const record = await readFrameRecord(cursor, source.name);
    if (typeof record === "string") {
      stop = record;
      break;
    }
    if (record.cieOffset == null) {
      const cie = await readElfUnwindCie(cursorAt(record.body, record.end), record.offset,
        elf.is64 ? 8 : 4, source.addr, elf.header.machine);
      if (cie) result.cies.push(cie);
    } else pending.push(record);
    cursor.position = record.end;
    offset = record.end;
  }
  if (result.sectionIndex === null && stop === "section-end") {
    result.issues.push("No .eh_frame terminator before the end of the file-backed PT_LOAD.");
  }
  await readPendingFdes(pending, result, cursorAt, source.addr, elf.header.machine);
  return stop === "section-end" || stop === "short-record" ? { offset, stop } : undefined;
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
  const sections: SectionScan[] = [];
  for (const section of elf.sections) {
    if (section.name === ".eh_frame" || section.name === ".debug_frame") {
      sections.push(await readUnwindSection(reader, elf, section));
    }
  }
  const runtime = sections.filter(scan => scan.section.name === ".eh_frame");
  const result = sections.map(scan => scan.frames);
  if (runtime.some(scan => scan.frames.fdes.length) &&
      !runtime.some(scan => scan.continuation)) return result;
  const fallback = await readSegmentFrames(reader, elf, runtime);
  if (fallback?.replaced) result[result.indexOf(fallback.replaced)] = fallback.frames;
  else if (fallback) result.push(fallback.frames);
  return result;
};

const readSegmentFrames = async (
  reader: FileRangeReader, elf: ElfParseResult, attempted: SectionScan[]
): Promise<{ frames: ElfUnwindSection; replaced?: ElfUnwindSection } | null> => {
  const header = findElfEhFrameHeader(elf.programHeaders);
  if (!header) return null;
  const unwind: ElfUnwindSection = { sectionIndex: null, programHeaderIndex: header.index,
    cies: [], fdes: [], issues: [] };
  const source = await locateSegmentUnwind(reader, elf, header, unwind.issues);
  const haveFrames = attempted.some(scan => scan.frames.fdes.length);
  if (!source) return haveFrames ? null : { frames: unwind };
  const start = BigInt(source.offset);
  const alias = attempted.find(({ section }) => start === section.offset && source.addr === section.addr &&
    elfFileRange(section.offset, section.size, reader.size));
  if (alias) return extendSectionScan(reader, elf, source, unwind, alias);
  if (haveFrames) return null;
  await readUnwindFrames(reader, elf, source, unwind);
  return { frames: unwind };
};

const extendSectionScan = async (
  reader: FileRangeReader, elf: ElfParseResult, source: FrameSource,
  unwind: ElfUnwindSection, { section, frames, continuation }: SectionScan
): Promise<{ frames: ElfUnwindSection; replaced: ElfUnwindSection } | null> => {
  if (!continuation || BigInt(source.size) <= section.size) return null;
  if (continuation.stop === "section-end" && frames.fdes.length &&
    (source.fdeCount ?? 0) <= frames.fdes.length) return null;
  // CIE references and PC-relative operands have the same origin in both views.
  // Keep complete records and resume at the first record outside the section.
  unwind.cies = frames.cies.slice();
  unwind.fdes = frames.fdes.slice();
  unwind.issues = frames.issues.slice();
  await readUnwindFrames(reader, elf, source, unwind, continuation.offset);
  if (unwind.fdes.length <= frames.fdes.length) return null;
  unwind.issues.unshift(`.eh_frame via PT_GNU_EH_FRAME extends beyond section #${section.index}.`);
  return { frames: unwind, replaced: frames };
};
