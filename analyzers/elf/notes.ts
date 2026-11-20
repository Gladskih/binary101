"use strict";

import { readAsciiString } from "../../binary-utils.js";
import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfNoteEntry, ElfNotesInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { decodeElfNotePayload } from "./note-payload.js";
import type { ElfByteOrder } from "./binary-layout-types.js";
import { decodeBuildAttributeNote, gnuBuildAttributeTypes } from "./build-attribute-note.js";

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

type NoteRecord = { entry: ElfNoteEntry; aliases?: Set<string> };

const addNoteSource = (note: NoteRecord, source: string): void => {
  if (note.entry.source !== source) (note.aliases ??= new Set()).add(source);
};

const readNotePayload = async (reader: FileRangeReader,
  bounds: NonNullable<ReturnType<typeof noteBounds>>, source: string, issues: string[]) => {
  const nameBytes = await reader.readBytes(bounds.nameStart, bounds.nameEnd - bounds.nameStart);
  const desc = await reader.readBytes(bounds.descStart, bounds.descEnd - bounds.descStart);
  if (nameBytes.length !== bounds.nameEnd - bounds.nameStart ||
    desc.length !== bounds.descEnd - bounds.descStart) {
    issues.push(`${source}: note payload is truncated.`);
    return null;
  }
  const name = readAsciiString(new DataView(nameBytes.buffer, nameBytes.byteOffset,
    nameBytes.byteLength), 0, nameBytes.length);
  return { nameBytes, name, desc };
};

const parseNotesFromRange = async (reader: FileRangeReader, opts: ElfNoteInput,
  range: NoteRange, alignment: number, issues: string[],
  decoded: Map<string, NoteRecord>): Promise<NoteRecord[]> => {
  const { source } = range;
  const { littleEndian } = opts;
  const attributeRanges = new Map<number, string>();
  const records: NoteRecord[] = [];
  let offset = 0;
  while (offset + 12 <= reader.size) {
    const view = await reader.read(offset, 12);
    if (view.byteLength < 12) { issues.push(`${source}: note header is truncated.`); break; }
    const bounds = noteBounds(view, offset, littleEndian, source, issues, alignment, reader.size);
    if (!bounds) break;
    const key = `${range.offset + BigInt(offset)}/${range.offset + BigInt(bounds.descStart)}`;
    offset = Math.ceil(bounds.descEnd / alignment) * alignment;
    const existing = decoded.get(key);
    if (existing) {
      addNoteSource(existing, source);
      records.push(existing);
      continue;
    }
    const type = view.getUint32(8, littleEndian);
    const payload = await readNotePayload(reader, bounds, source, issues);
    if (!payload) break;
    const entry: ElfNoteEntry = { source, name: payload.name, type, descSize: payload.desc.length,
      typeName: null, description: null, value: null };
    decodeNote(entry, payload.nameBytes, payload.desc, opts.is64 ? 8 : 4, littleEndian ? "little" : "big",
      opts.coreMachine, attributeRanges, issues);
    const record = { entry };
    decoded.set(key, record);
    records.push(record);
  }
  return records;
};

const noteAlignment = (align: bigint, source: string, issues: string[]): number | null => {
  // Treat unspecified/byte alignment as the traditional four-byte note layout.
  if ([0n, 1n, 2n, 4n].includes(align)) return 4;
  if (align === 8n) return 8;
  issues.push(`${source}: unsupported note alignment ${align}.`);
  return null;
};

type NoteRange = { offset: bigint; size: bigint; align: bigint; source: string };

const noteRanges = (sections: ElfSectionHeader[], headers: ElfProgramHeader[]): NoteRange[] => {
  const ranges = sections.filter(section => section.type === 7 && section.size > 0n)
    .map(section => ({ offset: section.offset, size: section.size, align: section.addralign,
      source: section.name ? `Section "${section.name}"` : `SHT_NOTE section #${section.index}` }));
  // SHT_NOTE=7; PT_NOTE=4; PT_GNU_PROPERTY=0x6474e553 (glibc elf.h).
  return ranges.concat(headers.filter(header => [4, 0x6474e553].includes(header.type) && header.filesz > 0n)
    .map(header => ({ offset: header.offset, size: header.filesz, align: header.align,
      source: `${header.type === 4 ? "PT_NOTE" : "PT_GNU_PROPERTY"} segment #${header.index}` })));
};

const readNoteRange = (file: File, range: NoteRange, issues: string[]): FileRangeReader | null => {
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

type ElfNoteInput = {
  file: File; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
  littleEndian: boolean; is64?: boolean; coreMachine?: number;
};

export async function parseElfNotes(opts: ElfNoteInput): Promise<ElfNotesInfo | null> {
  const ranges = noteRanges(opts.sections, opts.programHeaders);
  if (!ranges.length) return null;
  const issues: string[] = [];
  const parsedRanges = new Map<string, NoteRecord[]>();
  const decoded = new Map<string, NoteRecord>();
  for (const range of ranges) {
    const alignment = noteAlignment(range.align, range.source, issues);
    if (alignment == null) continue;
    const key = `${range.offset}/${range.size}/${alignment}`;
    const records = parsedRanges.get(key);
    if (records) {
      for (const note of records) addNoteSource(note, range.source);
      continue;
    }
    const reader = readNoteRange(opts.file, range, issues);
    if (!reader) continue;
    parsedRanges.set(key, await parseNotesFromRange(reader, opts, range, alignment, issues, decoded));
  }
  return { entries: Array.from(decoded.values(), ({ entry, aliases }) =>
    aliases ? { ...entry, sourceAliases: [...aliases] } : entry), issues };
}

function decodeNote(entry: ElfNoteEntry, nameBytes: Uint8Array, desc: Uint8Array,
  wordSize: 4 | 8, order: ElfByteOrder, coreMachine: number | undefined,
  attributeRanges: Map<number, string>, issues: string[]): void {
  if (gnuBuildAttributeTypes[entry.type] != null &&
    (entry.name.startsWith("GA") || /^[*$+!]/.test(entry.name))) {
    decodeBuildAttributeNote(entry, nameBytes, desc, order,
      attributeRanges, issues);
  } else decodeElfNotePayload(entry, desc, wordSize, order, coreMachine, issues);
}
