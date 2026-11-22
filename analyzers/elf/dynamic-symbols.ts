"use strict";

import { createFileRangeReader, type FileRangeReader } from "../file-range-reader.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { readDynsymCountFromGnuHash, readDynsymCountFromSysvHash } from "./dynsym-count.js";
import { elfVirtualRange } from "./relocation-reader.js";
import { findElfDynamicSegment, readElfDynamicTable, type ElfDynamicEntry,
  type ElfDynamicTable } from "./dynamic-entries.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { createElfDynamicIndexReader } from "./dynamic-symbol-indices.js";
import type { ElfHashTable } from "./hash-types.js";
import { ELF_DYNAMIC_TAG } from "./abi-constants.js";
import { declaredDynamicSymbolRange } from "./dynsym-range.js";
import { elfSymbolSectionFields } from "./symbol-section-index.js";
import { createElfGnuHashSymbolValidator } from "./hash-symbols.js";
import { createElfSysvHashSymbolValidator } from "./sysv-hash.js";
import { associatedElfHashTables, validateElfSysvHashSymbolCount } from "./hash-tables.js";
import { elfRuntimeStringsForSectionSymbols } from "./dynamic-consistency.js";
import { elfDynamicSymbolTags } from "./dynamic-symbol-tags.js";
import { createElfDynamicSymbolNameReader, readElfDynamicSymbolRecords,
  type ElfDynamicSymbolRange, type ElfDynamicSymbolTables, type ElfSymbolHashValidators } from
  "./dynamic-symbol-records.js";
import { ELF_SECTION_COMPRESSED, hasCompressedSectionAt, openElfSectionData,
  type ElfSectionEncoding } from "./section-data.js";

// gABI p_type/sh_type and d_tag definitions:
// https://gabi.xinuos.com/elf/03-sheader.html
// https://gabi.xinuos.com/elf/07-pheader.html
// https://gabi.xinuos.com/elf/08-dynamic.html
const SHT_DYNSYM = 11;

const DT_HASH = 4;
const DT_GNU_HASH = 0x6ffffef5;

// gABI symbol binding, type, visibility and section-index encodings:
// https://gabi.xinuos.com/elf/05-symtab.html
// GNU additions (STT_GNU_IFUNC, STB_GNU_UNIQUE, DT_GNU_HASH):
// https://raw.githubusercontent.com/bminor/glibc/master/elf/elf.h
const SHN_UNDEF = 0;

const STB_LOCAL = 0;

const STV_DEFAULT = 0;
const STV_INTERNAL = 1;
const STV_HIDDEN = 2;
const STV_PROTECTED = 3;

type DynamicSymbolInput = ElfSectionEncoding & {
  file: File; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
};

const decodeBind = (bind: number): string => {
  const map: Record<number, string> = { 0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE" };
  return map[bind] || `BIND_${bind}`;
};

const decodeType = (type: number): string => {
  const map: Record<number, string> = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "GNU_IFUNC"
  };
  return map[type] || `TYPE_${type}`;
};

const decodeVisibility = (vis: number): string => {
  const map: Record<number, string> = {
    [STV_DEFAULT]: "DEFAULT",
    [STV_INTERNAL]: "INTERNAL",
    [STV_HIDDEN]: "HIDDEN",
    [STV_PROTECTED]: "PROTECTED"
  };
  return map[vis] || `VIS_${vis}`;
};

const parseDynsym = async (
  tables: ElfDynamicSymbolTables,
  layout: ElfBinaryLayout,
  issues: string[],
  symbolCache: Map<number, ElfRelocationSymbol>,
  readSectionIndex: ReturnType<typeof createElfDynamicIndexReader>,
  reader: FileRangeReader,
  hashes: ElfSymbolHashValidators
): Promise<ElfDynamicSymbol[]> => {
  const { symtab } = tables;
  const readName = createElfDynamicSymbolNameReader(tables.strtab, reader, issues, hashes);
  const records = await readElfDynamicSymbolRecords(symtab, layout, issues, symtab.reader ?? reader, hashes);
  const out: ElfDynamicSymbol[] = [];
  for (const item of records) {
    const name = await readName(item);
    if (name == null) continue;
    const { index, record } = item;
    const { value, size, info, other, sectionIndex } = record;
    // ELF*_ST_BIND/TYPE/VISIBILITY: high/low st_info nibbles and low two st_other bits.
    // https://gabi.xinuos.com/elf/05-symtab.html
    const bind = info >> 4;
    const type = info & 0x0f;
    const visibility = other & 0x03;
    const shndx = await readSectionIndex(index, sectionIndex);
    if (shndx == null) continue;
    const section = elfSymbolSectionFields(sectionIndex, shndx);
    if (!symtab.reader) symbolCache.set(symtab.offset + index * layout.symbolEntrySize, { name, value, ...section });
    out.push({ index, name, value, size, bind, bindName: decodeBind(bind),
      type, typeName: decodeType(type), visibility,
      visibilityName: decodeVisibility(visibility), shndx,
      ...(other !== visibility ? { other } : {}),
      ...(section.rawSectionIndex === undefined ? {} : { rawSectionIndex: section.rawSectionIndex }) });
  }
  return out.sort((left, right) => left.index - right.index);
};

const readTableRange = (file: File, offset: bigint, size: bigint,
  label: string, issues: string[]): ElfDynamicSymbolRange | null => {
  if (offset < 0n || offset >= BigInt(file.size) || size <= 0n) {
    issues.push(`${label} is outside the file or empty.`);
    return null;
  }
  const available = BigInt(file.size) - offset;
  if (size > available) issues.push(`${label} is truncated.`);
  return { offset: Number(offset), size: Number(size > available ? available : size), truncated: size > available };
};

const openDynamicSymbolSection = async (
  opts: DynamicSymbolInput, section: ElfSectionHeader, name: string, issues: string[]
): Promise<ElfDynamicSymbolRange | null> => {
  if (!(section.flags & ELF_SECTION_COMPRESSED)) {
    return readTableRange(opts.file, section.offset, section.size, name, issues);
  }
  const data = await openElfSectionData(createFileRangeReader(opts.file, 0, opts.file.size),
    { ...section, name: section.name || name }, opts, issues);
  return data && { ...data, storedOffset: Number(section.offset) };
};

const parseDynsymFromSections = async (opts: DynamicSymbolInput & { issues: string[] }):
Promise<ElfDynamicSymbolTables | null> => {
  const dynsym = opts.sections.find(sec => sec.type === SHT_DYNSYM);
  if (!dynsym) return null;
  if (!dynsym.size) {
    opts.issues.push(".dynsym is missing symbol #0 (STN_UNDEF).");
    return null;
  }
  if (dynsym.entsize !== BigInt(selectElfBinaryLayout(opts).symbolEntrySize)) {
    opts.issues.push(".dynsym has an invalid entry size.");
    return null;
  }
  const symtab = await openDynamicSymbolSection(opts, dynsym, ".dynsym", opts.issues);
  if (!symtab) return null;
  symtab.section = dynsym;

  const linked = opts.sections[dynsym.link];
  // gABI 3: SHT_DYNSYM.sh_link identifies the associated SHT_STRTAB, regardless of names.
  if (!linked || linked.type !== 3) {
    opts.issues.push(".dynsym sh_link does not reference SHT_STRTAB.");
    return { symtab, strtab: null };
  }
  const strtab = await openDynamicSymbolSection(opts, linked, ".dynstr", opts.issues);
  return { symtab, strtab };
};

type DynamicSymbolTags = NonNullable<ReturnType<typeof elfDynamicSymbolTags>>;

const parseDynsymFromDynamicTags = async (opts: DynamicSymbolInput & { issues: string[] },
  tags: DynamicSymbolTags, entries: ElfDynamicEntry[], hashes?: ElfHashTable[]):
Promise<ElfDynamicSymbolTables | null> => {
  const symtab = await locateDynamicSymbolTable(opts, tags, entries, hashes);
  if (!symtab) return null;
  const strtab = elfVirtualRange(opts.programHeaders, tags.strtabVaddr, tags.strsz, opts.file.size);
  if (!strtab) {
    opts.issues.push("DT_STRTAB is outside a file-backed PT_LOAD range.");
    return null;
  }
  if (hasCompressedSectionAt(opts.sections, SHT_DYNSYM, symtab.offset) ||
      hasCompressedSectionAt(opts.sections, 3, strtab.offset)) {
    opts.issues.push("Dynamic symbol tags point into compressed section data.");
    return null;
  }
  return { symtab, strtab };
};

const locateDynamicSymbolTable = async (opts: Parameters<typeof parseDynsymFromDynamicTags>[0],
  { symtabVaddr, strtabVaddr, entrySize, declaredSize }: DynamicSymbolTags,
  entries: ElfDynamicEntry[], hashes: ElfHashTable[] | undefined): Promise<ElfDynamicSymbolRange | null> => {
  if (declaredSize != null) return declaredDynamicSymbolRange(
    opts.programHeaders, symtabVaddr, declaredSize, entrySize, opts.file.size, opts.issues);
  const count = await dynamicHashCount(opts, entries, hashes) ??
    inferDynsymCount(symtabVaddr, strtabVaddr, entrySize, opts.issues);
  if (!count) {
    opts.issues.push("Dynamic symbol table size could not be determined.");
    return null;
  }
  const range = elfVirtualRange(opts.programHeaders, symtabVaddr,
    BigInt(count) * BigInt(entrySize), opts.file.size);
  if (!range) opts.issues.push("DT_SYMTAB is outside a file-backed PT_LOAD range.");
  return range;
};

const dynamicHashCount = async (opts: Parameters<typeof parseDynsymFromDynamicTags>[0],
  entries: ElfDynamicEntry[], hashes: ElfHashTable[] | undefined): Promise<number | null> => {
  if (hashes != null) return hashSymbolCount(hashes);
  const hashVaddr = entries.find(entry => entry.tag === DT_HASH)?.value ?? 0n;
  const gnuHashVaddr = entries.find(entry => entry.tag === DT_GNU_HASH)?.value ?? 0n;
  const count = hashVaddr === 0n ? null : await readDynsymCountFromSysvHash({ ...opts, hashVaddr });
  if (count != null || gnuHashVaddr === 0n) return count;
  return readDynsymCountFromGnuHash({ ...opts, hashVaddr: gnuHashVaddr });
};

const inferDynsymCount = (symtab: bigint, strtab: bigint, entrySize: number,
  issues: string[]): number | null => {
  if (strtab <= symtab) return null;
  const size = strtab - symtab;
  const count = Number(size / BigInt(entrySize));
  if (!Number.isSafeInteger(count) || count <= 0) return null;
  if (size % BigInt(entrySize) !== 0n) issues.push("Inferred .dynsym size is not aligned to entry size.");
  issues.push("Dynsym count inferred from DT_STRTAB - DT_SYMTAB; may be imprecise.");
  return count;
};

export async function parseElfDynamicSymbols(opts: DynamicSymbolInput,
  parsedEntries?: ElfDynamicEntry[] | ElfDynamicTable, symbolCache = new Map<number, ElfRelocationSymbol>(),
layout = selectElfBinaryLayout(opts), hashes?: ElfHashTable[]):
Promise<ElfDynamicSymbolInfo | null> {
  const issues: string[] = [];

  const sectionTables = await parseDynsymFromSections({ ...opts, issues });
  const table = Array.isArray(parsedEntries) ? { entries: parsedEntries, terminated: false } :
    parsedEntries ?? await readElfDynamicTable(
      createFileRangeReader(opts.file, 0, opts.file.size), opts, issues, layout);
  const { entries } = table;
  const tags = findElfDynamicSegment(opts.programHeaders) ?
    elfDynamicSymbolTags(table, layout.symbolEntrySize, issues) : null;
  const tables = sectionTables ?? (tags &&
    await parseDynsymFromDynamicTags({ ...opts, issues }, tags, entries, hashes));
  if (!tables) return issues.length ? { total: 0, importSymbols: [], exportSymbols: [], issues } : null;
  if (sectionTables && !sectionTables.symtab.reader) {
    // Both tables may be independently valid. Runtime symbol names use DT_STRTAB/DT_STRSZ.
    tables.strtab = elfRuntimeStringsForSectionSymbols(opts, entries, sectionTables.symtab.offset) ?? tables.strtab;
  }
  const associatedHashes = associatedElfHashTables(opts, tables.symtab, entries, hashes);
  const stride = layout.symbolEntrySize;
  const { size, truncated, section } = tables.symtab;
  const declared = !section && entries.some(entry => entry.tag === ELF_DYNAMIC_TAG.SYMTABSZ);
  const total = Math.floor(size / stride);
  validateElfSysvHashSymbolCount(associatedHashes,
    (section || declared) && !truncated && size % stride === 0 ? total : undefined);
  const symbols = await parseDynsym(tables, layout,
    issues, symbolCache,
    createElfDynamicIndexReader(opts.file, opts, tables.symtab.storedOffset ?? tables.symtab.offset, entries, issues),
    createFileRangeReader(opts.file, 0, opts.file.size),
    { gnu: createElfGnuHashSymbolValidator(associatedHashes, layout.wordSize === 8 ? 64 : 32),
      sysv: createElfSysvHashSymbolValidator(associatedHashes) });
  const importSymbols = symbols.filter(sym => sym.shndx === SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);
  const exportSymbols = symbols.filter(sym => sym.shndx !== SHN_UNDEF &&
    sym.bind !== STB_LOCAL && sym.name.length > 0 &&
    sym.visibility !== STV_HIDDEN && sym.visibility !== STV_INTERNAL);

  return {
    total,
    importSymbols,
    exportSymbols,
    issues
  };
}

const hashSymbolCount = (tables: ElfHashTable[] | undefined): number | null => {
  const valid = tables?.filter(table => !table.issues.length);
  const sysv = valid?.find(table => table.kind === "sysv" && table.chains.length > 0);
  if (sysv) return sysv.chains.length;
  // GNU ld's empty hash still advertises a symbol offset of one.
  // https://gnu.googlesource.com/binutils-gdb/+/4d9e2e53b9f93b0ae33ba948ae3d2825b3424441/bfd/elflink.c#7563
  const gnu = valid?.find(table => table.kind === "gnu" && table.chains.length > 0);
  return gnu?.kind === "gnu" ? gnu.symbolOffset + gnu.chains.length : null;
};
