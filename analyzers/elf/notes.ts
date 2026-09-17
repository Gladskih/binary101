"use strict";

import { alignUpTo, readAsciiString } from "../../binary-utils.js";
import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { decodeElfNotePayload } from "./note-payload.js";

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

// Note descriptor and next-record alignment follow sh_addralign / p_align.
// ELF64 producers also use 4-byte alignment; class alone is insufficient.
// https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/Object/ELFTypes.h
const noteBounds = (view: DataView, offset: number, littleEndian: boolean,
  source: string, issues: string[], alignment: number) => {
  const namesz = view.getUint32(offset, littleEndian);
  const descsz = view.getUint32(offset + 4, littleEndian);
  const nameStart = offset + 12;
  const nameEnd = nameStart + namesz;
  if (nameEnd > view.byteLength) { issues.push(`${source}: note name is truncated.`); return null; }
  const descStart = alignUpTo(nameEnd, alignment);
  const descEnd = descStart + descsz;
  if (descEnd > view.byteLength) { issues.push(`${source}: note desc is truncated.`); return null; }
  return { nameStart, nameEnd, descStart, descEnd };
};

const parseNotesFromBytes = (bytes: Uint8Array, littleEndian: boolean,
  range: ReturnType<typeof noteRanges>[number], issues: string[], wordSize: 4 | 8,
  coreMachine: number | undefined, seenNotes: Set<string>): ElfNoteEntry[] => {
  const { source } = range;
  const alignment = noteAlignment(range.align, source, issues);
  if (alignment == null) return [];
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries: ElfNoteEntry[] = [];
  let offset = 0;
  while (offset + 12 <= view.byteLength) {
    const key = (range.offset + BigInt(offset)).toString();
    const bounds = noteBounds(view, offset, littleEndian, source, issues, alignment);
    if (!bounds) break;
    const type = view.getUint32(offset + 8, littleEndian);
    offset = alignUpTo(bounds.descEnd, alignment);
    if (seenNotes.has(key)) continue;
    seenNotes.add(key);
    const name = readAsciiString(view, bounds.nameStart, bounds.nameEnd - bounds.nameStart);
    const desc = bytes.subarray(bounds.descStart, bounds.descEnd);
    const entry: ElfNoteEntry = { source, name, type, descSize: desc.length,
      typeName: null, description: null, value: null };
    decodeElfNotePayload(entry, desc, wordSize, littleEndian ? "little" : "big", coreMachine, issues);
    entries.push(entry);
  }
  return entries;
};

const noteAlignment = (align: bigint, source: string, issues: string[]): number | null => {
  // Treat unspecified/byte alignment as the traditional four-byte note layout.
  if ([0n, 1n, 2n, 4n].includes(align)) return 4;
  if (align === 8n) return 8;
  issues.push(`${source}: unsupported note alignment ${align}.`);
  return null;
};

const noteRanges = (sections: ElfSectionHeader[], headers: ElfProgramHeader[]) => {
  const ranges = sections.filter(section => section.type === 7 && section.size > 0n)
    .map(section => ({ offset: section.offset, size: section.size, align: section.addralign,
      source: section.name ? `Section "${section.name}"` : `SHT_NOTE section #${section.index}` }));
  // SHT_NOTE=7; PT_NOTE=4; PT_GNU_PROPERTY=0x6474e553 (glibc elf.h).
  ranges.push(...headers.filter(header => [4, 0x6474e553].includes(header.type) && header.filesz > 0n)
    .map(header => ({ offset: header.offset, size: header.filesz, align: header.align,
      source: `PT_NOTE segment #${header.index}` })));
  return ranges;
};

const readNoteRange = async (reader: FileRangeReader,
  range: ReturnType<typeof noteRanges>[number], issues: string[]): Promise<Uint8Array | null> => {
  const start = toSafeIndex(range.offset, `${range.source} offset`, issues);
  const size = toSafeIndex(range.size, `${range.source} size`, issues);
  if (start == null || size == null || size <= 0) return null;
  // Bound descriptor storage even when hostile metadata claims a huge segment.
  const end = Math.min(reader.size, start + size, start + 16 * 1024 * 1024);
  if (start >= reader.size || end <= start) {
    issues.push(`${range.source} falls outside the file.`);
    return null;
  }
  if (end !== start + size) issues.push(`${range.source} is truncated or exceeds the 16 MiB note limit.`);
  return reader.readBytes(start, end - start);
};

export async function parseElfNotes(opts: {
  file: File; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
  littleEndian: boolean; is64?: boolean; coreMachine?: number;
}): Promise<ElfNotesInfo | null> {
  const ranges = noteRanges(opts.sections, opts.programHeaders);
  if (!ranges.length) return null;
  const issues: string[] = [];
  const dedupe = new Set<string>();
  const seenNotes = new Set<string>();
  const entries: ElfNoteEntry[] = [];
  const reader = createFileRangeReader(opts.file, 0, opts.file.size);
  for (const range of ranges) {
    const key = `${range.offset}-${range.size}`;
    if (dedupe.has(key)) continue;
    dedupe.add(key);
    const bytes = await readNoteRange(reader, range, issues);
    if (!bytes) continue;
    const parsed = parseNotesFromBytes(bytes, opts.littleEndian, range, issues,
      opts.is64 ? 8 : 4, opts.coreMachine, seenNotes);
    for (const entry of parsed) entries.push(entry);
  }
  return { entries, issues };
}
