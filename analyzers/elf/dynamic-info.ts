import { createElfStringTableReader } from "./string-table.js";
import type { ElfDynamicInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { FileRangeReader } from "../file-range-reader.js";
import { elfVirtualRange } from "./relocation-reader.js";
import {
  readElfDynamicTable, type ElfDynamicEntry, type ElfDynamicTable
} from "./dynamic-entries.js";
import { createFileRangeReader } from "../file-range-reader.js";
import { ELF_DYNAMIC_TAG_DESCRIPTIONS } from "./dynamic-tags.js";
import { hasCompressedSectionAt, openElfSectionData, type ElfSectionEncoding } from "./section-data.js";
import { elfRangesCover } from "./range-coverage.js";

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

type DynEntry = ElfDynamicEntry;

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

type DynamicInfoInput = ElfSectionEncoding & {
  file: File; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
};

const locateDynStringTable = async (
  reader: FileRangeReader, opts: DynamicInfoInput, entries: DynEntry[], issues: string[]
) => {
  const strtabEntry = entries.find(entry => entry.tag === DT_STRTAB);
  const strszEntry = entries.find(entry => entry.tag === DT_STRSZ);
  if (strtabEntry) {
    const range = strszEntry ? elfVirtualRange(opts.programHeaders,
      strtabEntry.value, strszEntry.value, opts.file.size) : null;
    if (range && !hasCompressedSectionAt(opts.sections, 3, range.offset)) {
      return { ...range, reader };
    }
    issues.push(range ? "DT_STRTAB points into a compressed string table." :
      "DT_STRTAB does not map into a PT_LOAD segment for the full DT_STRSZ range.");
  }

  return linkedDynamicStrings(reader, opts, issues);
};

const linkedDynamicStrings = async (reader: FileRangeReader, opts: DynamicInfoInput, issues: string[]) => {
  // gABI 3.5: SHT_DYNAMIC.sh_link identifies its string table, independent of names.
  const segment = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  const dynamic = opts.sections.find(section => section.type === SHT_DYNAMIC &&
    (!segment || section.offset === segment.offset));
  if (!dynamic) return null;
  const strings = opts.sections.find(section => section.index === dynamic.link);
  if (!strings || strings.type !== 3) {
    issues.push("SHT_DYNAMIC sh_link does not reference SHT_STRTAB.");
    return null;
  }
  return openElfSectionData(reader, { ...strings, name: strings.name || "Dynamic string table" }, opts, issues);
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

const readArrayTag = (
  table: ElfDynamicTable, tags: readonly [number, number], image: DynamicInfoInput, issues: string[]
):
{ vaddr: bigint; size: bigint } | null => {
  const [baseTag, sizeTag] = tags;
  const base = getTagValue(table.entries, baseTag);
  if (base == null) return null;
  const byteCount = getTagValue(table.entries, sizeTag);
  const label = ELF_DYNAMIC_TAG_DESCRIPTIONS[baseTag]![0];
  if (byteCount == null) {
    if (table.terminated) issues.push(`${label} requires ${ELF_DYNAMIC_TAG_DESCRIPTIONS[sizeTag]![0]}.`);
    return null;
  }
  if (byteCount === 0n) return null;
  if (byteCount % (image.is64 ? 8n : 4n) !== 0n) {
    issues.push(`${label} size does not describe a whole number of pointers.`);
  }
  const ranges = image.programHeaders.filter(header => header.type === 1 && header.memsz > 0n)
    .map(header => ({ start: header.vaddr, end: header.vaddr + header.memsz }));
  const end = base + byteCount;
  if (end > (1n << (image.is64 ? 64n : 32n)) || !elfRangesCover(ranges, base, end)) {
    issues.push(`${label} range is outside PT_LOAD memory.`);
  }
  return { vaddr: base, size: byteCount };
};

export async function parseElfDynamicInfo(
  opts: DynamicInfoInput, parsedEntries?: ElfDynamicEntry[] | ElfDynamicTable
): Promise<ElfDynamicInfo | null> {
  const issues: string[] = [];
  if (!hasDynamicTable(opts.file, opts.programHeaders, opts.sections, issues)) return null;
  const reader = createFileRangeReader(opts.file, 0, opts.file.size);
  // Legacy callers supplying entries alone provide no evidence of the DT_NULL terminator.
  const table = Array.isArray(parsedEntries) ? { entries: parsedEntries, terminated: false } :
    parsedEntries ?? await readElfDynamicTable(reader, opts, issues);
  const { entries } = table;
  const strings = await locateDynStringTable(reader, opts, entries, issues);
  const readString = createElfStringTableReader(strings?.reader ?? reader, strings, issues);
  const needed = (await Promise.all(getTagValues(entries, DT_NEEDED)
    .map(value => readString(Number(value))))).filter((name): name is string => !!name);
  return {
    terminated: table.terminated,
    entries: await Promise.all(entries.map(async entry =>
      typeof entry.tag === "number" &&
      ELF_DYNAMIC_TAG_DESCRIPTIONS[entry.tag]?.[1] === "string"
        ? { ...entry, string: await readString(Number(entry.value)) } : entry)),
    needed,
    soname: await readNamedTag(entries, DT_SONAME, readString),
    rpath: await readNamedTag(entries, DT_RPATH, readString),
    runpath: await readNamedTag(entries, DT_RUNPATH, readString),
    init: getTagValue(entries, DT_INIT),
    fini: getTagValue(entries, DT_FINI),
    preinitArray: readArrayTag(table, [DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ], opts, issues),
    initArray: readArrayTag(table, [DT_INIT_ARRAY, DT_INIT_ARRAYSZ], opts, issues),
    finiArray: readArrayTag(table, [DT_FINI_ARRAY, DT_FINI_ARRAYSZ], opts, issues),
    flags: dynamicFlags(entries, DT_FLAGS),
    flags1: dynamicFlags(entries, DT_FLAGS_1),
    issues
  };
}
