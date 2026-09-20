"use strict";

import { readAsciiString } from "../../binary-utils.js";
import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { decodeElfNotePayload } from "./note-payload.js";
import type { ElfByteOrder } from "./binary-layout-types.js";
import { decodeBuildAttributeNote } from "./build-attribute-note.js";

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
  source: string, issues: string[], alignment: number, size: number) => {
  const namesz = view.getUint32(0, littleEndian);
  const descsz = view.getUint32(4, littleEndian);
  const nameStart = offset + 12;
  const nameEnd = nameStart + namesz;
  if (nameEnd > size) { issues.push(`${source}: note name is truncated.`); return null; }
  const descStart = Math.ceil(nameEnd / alignment) * alignment;
  const descEnd = descStart + descsz;
  if (descEnd > size) { issues.push(`${source}: note desc is truncated.`); return null; }
  return { nameStart, nameEnd, descStart, descEnd };
};

const parseNotesFromRange = async (reader: FileRangeReader, littleEndian: boolean,
  range: ReturnType<typeof noteRanges>[number], issues: string[], wordSize: 4 | 8,
  coreMachine: number | undefined, seenNotes: Set<string>,
  attributeRanges: Map<number, string>): Promise<ElfNoteEntry[]> => {
  const { source } = range;
  const alignment = noteAlignment(range.align, source, issues);
  if (alignment == null) return [];
  const entries: ElfNoteEntry[] = [];
  let offset = 0;
  while (offset + 12 <= reader.size) {
    const view = await reader.read(offset, 12);
    if (view.byteLength < 12) { issues.push(`${source}: note header is truncated.`); break; }
    const key = (range.offset + BigInt(offset)).toString();
    const bounds = noteBounds(view, offset, littleEndian, source, issues, alignment, reader.size);
    if (!bounds) break;
    const type = view.getUint32(8, littleEndian);
    offset = Math.ceil(bounds.descEnd / alignment) * alignment;
    if (seenNotes.has(key)) continue;
    seenNotes.add(key);
    const nameBytes = await reader.readBytes(bounds.nameStart, bounds.nameEnd - bounds.nameStart);
    const desc = await reader.readBytes(bounds.descStart, bounds.descEnd - bounds.descStart);
    if (nameBytes.length !== bounds.nameEnd - bounds.nameStart ||
      desc.length !== bounds.descEnd - bounds.descStart) {
      issues.push(`${source}: note payload is truncated.`);
      break;
    }
    const name = readAsciiString(new DataView(nameBytes.buffer, nameBytes.byteOffset,
      nameBytes.byteLength), 0, nameBytes.length);
    const entry: ElfNoteEntry = { source, name, type, descSize: desc.length,
      typeName: null, description: null, value: null };
    decodeNote(entry, nameBytes, desc, wordSize, littleEndian ? "little" : "big",
      coreMachine, attributeRanges, issues);
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
  return ranges.concat(headers.filter(header => [4, 0x6474e553].includes(header.type) && header.filesz > 0n)
    .map(header => ({ offset: header.offset, size: header.filesz, align: header.align,
      source: `PT_NOTE segment #${header.index}` })));
};

const readNoteRange = (file: File,
  range: ReturnType<typeof noteRanges>[number], issues: string[]): FileRangeReader | null => {
  const start = toSafeIndex(range.offset, `${range.source} offset`, issues);
  const size = toSafeIndex(range.size, `${range.source} size`, issues);
  if (start == null || size == null || size <= 0) return null;
  const available = Math.min(file.size - start, size);
  if (available <= 0) {
    issues.push(`${range.source} falls outside the file.`);
    return null;
  }
  if (available !== size) issues.push(`${range.source} is truncated.`);
  return createFileRangeReader(file, start, available);
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
  for (const range of ranges) {
    const key = `${range.offset}-${range.size}`;
    if (dedupe.has(key)) continue;
    dedupe.add(key);
    const reader = readNoteRange(opts.file, range, issues);
    if (!reader) continue;
    const parsed = await parseNotesFromRange(reader, opts.littleEndian, range, issues,
      opts.is64 ? 8 : 4, opts.coreMachine, seenNotes, new Map());
    for (const entry of parsed) entries.push(entry);
  }
  return { entries, issues };
}

function decodeNote(entry: ElfNoteEntry, nameBytes: Uint8Array, desc: Uint8Array,
  wordSize: 4 | 8, order: ElfByteOrder, coreMachine: number | undefined,
  attributeRanges: Map<number, string>, issues: string[]): void {
  if ((entry.type === 0x100 || entry.type === 0x101) &&
    (entry.name.startsWith("GA") || /^[*$+!]/.test(entry.name))) {
    decodeBuildAttributeNote(entry, nameBytes, desc, order,
      attributeRanges, issues);
  } else decodeElfNotePayload(entry, desc, wordSize, order, coreMachine, issues);
}
