"use strict";

import { createElfStringTableReader } from "./string-table.js";
import type { ElfDynamicInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import { readElfDynamicEntries, type ElfDynamicEntry } from "./dynamic-entries.js";
import { createFileRangeReader } from "../file-range-reader.js";

// gABI p_type/sh_type and dynamic tags; GNU DT_FLAGS_1 from glibc's ELF declarations.
// https://gabi.xinuos.com/elf/07-pheader.html
// https://gabi.xinuos.com/elf/03-sheader.html
// https://gabi.xinuos.com/elf/08-dynamic.html
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const PT_DYNAMIC = 2;
const SHT_DYNAMIC = 6;

const DT_NEEDED = 1;
const DT_INIT = 12;
const DT_FINI = 13;
const DT_STRTAB = 5;
const DT_STRSZ = 10;
const DT_SONAME = 14;
const DT_RPATH = 15;
const DT_INIT_ARRAY = 25;
const DT_FINI_ARRAY = 26;
const DT_INIT_ARRAYSZ = 27;
const DT_FINI_ARRAYSZ = 28;
const DT_RUNPATH = 29;
const DT_FLAGS = 30;
const DT_PREINIT_ARRAY = 32;
const DT_PREINIT_ARRAYSZ = 33;
const DT_FLAGS_1 = 0x6ffffffb;

type DynEntry = { tag: number; value: bigint };

const hasDynamicTable = (file: File, headers: ElfProgramHeader[], sections: ElfSectionHeader[],
  issues: string[]): boolean => {
  const segment = headers.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  const source = segment ? { offset: segment.offset, size: segment.filesz } :
    sections.find(section => section.type === SHT_DYNAMIC && section.size > 0n);
  if (!source) return false;
  if (source.offset < 0n || source.offset >= BigInt(file.size)) return false;
  if (source.offset + source.size > BigInt(file.size)) issues.push("Dynamic section is truncated.");
  return true;
};

const locateDynStringTable = (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  entries: DynEntry[];
  issues: string[];
}): { offset: number; size: number } | null => {
  const strtabEntry = opts.entries.find(entry => entry.tag === DT_STRTAB);
  const strszEntry = opts.entries.find(entry => entry.tag === DT_STRSZ);
  if (strtabEntry) {
    const range = strszEntry ? elfVirtualRange(opts.programHeaders,
      strtabEntry.value, strszEntry.value, opts.file.size) : null;
    if (range) {
      return range;
    } else {
      opts.issues.push("DT_STRTAB does not map into a PT_LOAD segment for the full DT_STRSZ range.");
    }
  }

  return linkedDynamicStrings(opts.sections, opts.programHeaders, opts.file.size, opts.issues);
};

const linkedDynamicStrings = (sections: ElfSectionHeader[], programHeaders: ElfProgramHeader[],
  fileSize: number, issues: string[]): { offset: number; size: number } | null => {
  // gABI 3.5: SHT_DYNAMIC.sh_link identifies its string table, independent of names.
  const segment = programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  const dynamic = sections.find(section => section.type === SHT_DYNAMIC &&
    (!segment || section.offset === segment.offset));
  if (!dynamic) return null;
  const strings = sections.find(section => section.index === dynamic.link);
  if (!strings || strings.type !== 3) {
    issues.push("SHT_DYNAMIC sh_link does not reference SHT_STRTAB.");
    return null;
  }
  const range = elfFileRange(strings.offset, strings.size, fileSize);
  if (!range) {
    issues.push("Dynamic string table is truncated or outside the file.");
    return null;
  }
  return range;
};

const getTagValue = (entries: DynEntry[], tag: number): bigint | null =>
  entries.find(entry => entry.tag === tag)?.value ?? null;
const getTagValues = (entries: DynEntry[], tag: number): bigint[] =>
  entries.filter(entry => entry.tag === tag).map(entry => entry.value);

const dynamicFlags = (entries: DynEntry[], tag: number): number | null => {
  const value = getTagValue(entries, tag);
  return value != null && value <= 0xffffffffn ? Number(value) : null;
};

const readNamedTag = async (entries: DynEntry[], tag: number,
  readString: ReturnType<typeof createElfStringTableReader>): Promise<string | null> => {
  const value = getTagValue(entries, tag);
  return value == null ? null : await readString(Number(value)) || null;
};

const readArrayTag = (entries: DynEntry[], baseTag: number, sizeTag: number):
{ vaddr: bigint; size: bigint } | null => {
  const base = getTagValue(entries, baseTag);
  const byteCount = getTagValue(entries, sizeTag);
  if (base == null || byteCount == null || base === 0n || byteCount === 0n) return null;
  return { vaddr: base, size: byteCount };
};

export async function parseElfDynamicInfo(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
}, parsedEntries?: ElfDynamicEntry[]): Promise<ElfDynamicInfo | null> {
  const issues: string[] = [];
  if (!hasDynamicTable(opts.file, opts.programHeaders, opts.sections, issues)) return null;
  const reader = createFileRangeReader(opts.file, 0, opts.file.size);
  const entries = parsedEntries ?? await readElfDynamicEntries(reader, opts, issues);
  const readString = createElfStringTableReader(reader,
    locateDynStringTable({ ...opts, entries, issues }), issues);
  const needed = (await Promise.all(getTagValues(entries, DT_NEEDED)
    .map(value => readString(Number(value))))).filter((name): name is string => !!name);
  return {
    needed,
    soname: await readNamedTag(entries, DT_SONAME, readString),
    rpath: await readNamedTag(entries, DT_RPATH, readString),
    runpath: await readNamedTag(entries, DT_RUNPATH, readString),
    init: getTagValue(entries, DT_INIT),
    fini: getTagValue(entries, DT_FINI),
    preinitArray: readArrayTag(entries, DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
    initArray: readArrayTag(entries, DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
    finiArray: readArrayTag(entries, DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    flags: dynamicFlags(entries, DT_FLAGS),
    flags1: dynamicFlags(entries, DT_FLAGS_1),
    issues
  };
}
