"use strict";

import { createElfStringTableReader } from "./string-table.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { readDynsymCountFromGnuHash, readDynsymCountFromSysvHash } from "./dynsym-count.js";
import { elfVirtualRange } from "./relocation-reader.js";
import { readElfDynamicEntries, type ElfDynamicEntry } from "./dynamic-entries.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { createElfDynamicIndexReader } from "./dynamic-symbol-indices.js";
import type { ElfHashTable } from "./hash-types.js";
import { ELF_DYNAMIC_TAG } from "./abi-constants.js";
import { declaredDynamicSymbolRange } from "./dynsym-range.js";
import { elfSymbolSectionFields } from "./symbol-section-index.js";

// gABI p_type/sh_type and d_tag definitions:
// https://gabi.xinuos.com/elf/03-sheader.html
// https://gabi.xinuos.com/elf/07-pheader.html
// https://gabi.xinuos.com/elf/08-dynamic.html
const PT_DYNAMIC = 2;
const SHT_DYNSYM = 11;

const DT_HASH = 4;
const DT_GNU_HASH = 0x6ffffef5;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;

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

type TableRange = { offset: number; size: number };
type DynamicSymbolTables = { symtab: TableRange; strtab: TableRange | null };

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

const isDisplayableType = (type: number): boolean =>
  // NOTYPE, OBJECT, FUNC, COMMON, TLS (gABI 5.3), GNU_IFUNC (glibc elf.h).
  [0, 1, 2, 5, 6, 10].includes(type);

const readDynsymRecords = async (
  symtab: TableRange, layout: ElfBinaryLayout, issues: string[], reader: FileRangeReader
) => {
  const records = [];
  const count = Math.floor(symtab.size / layout.symbolEntrySize);
  if (symtab.size % layout.symbolEntrySize !== 0) {
    issues.push(`.dynsym size is not aligned to entry size (${layout.symbolEntrySize} bytes).`);
  }
  for (let index = 0; index < count; index += 1) {
    const record = layout.readSymbol(await reader.read(
      symtab.offset + index * layout.symbolEntrySize, layout.symbolEntrySize));
    if (!record) { issues.push(`Dynamic symbol #${index} is truncated.`); break; }
    if (isDisplayableType(record.info & 0x0f)) records.push({ index, record });
  }
  // The lto-dump profile repeatedly reloads .dynstr blocks when resolving names in symbol order.
  // Sort this private list to read names sequentially without growing the byte cache.
  return records.sort((left, right) => left.record.nameOffset - right.record.nameOffset);
};

const parseDynsym = async (
  symtab: TableRange,
  strtab: TableRange | null,
  layout: ElfBinaryLayout,
  issues: string[],
  symbolCache: Map<number, ElfRelocationSymbol>,
  readSectionIndex: ReturnType<typeof createElfDynamicIndexReader>,
  reader: FileRangeReader
): Promise<ElfDynamicSymbol[]> => {
  const readName = createElfStringTableReader(reader, strtab, issues);
  const out: ElfDynamicSymbol[] = [];
  for (const { index, record } of await readDynsymRecords(symtab, layout, issues, reader)) {
    const { nameOffset: nameOff, value, size, info, other, sectionIndex } = record;
    // ELF*_ST_BIND/TYPE/VISIBILITY: high/low st_info nibbles and low two st_other bits.
    // https://gabi.xinuos.com/elf/05-symtab.html
    const bind = info >> 4;
    const type = info & 0x0f;
    const visibility = other & 0x03;
    const name = await readName(nameOff);
    if (name == null) continue;
    const shndx = await readSectionIndex(index, sectionIndex);
    if (shndx == null) continue;
    const section = elfSymbolSectionFields(sectionIndex, shndx);
    symbolCache.set(symtab.offset + index * layout.symbolEntrySize, { name, value, ...section });
    out.push({ index, name, value, size, bind, bindName: decodeBind(bind),
      type, typeName: decodeType(type), visibility,
      visibilityName: decodeVisibility(visibility), shndx,
      ...(other !== visibility ? { other } : {}),
      ...(section.rawSectionIndex === undefined ? {} : { rawSectionIndex: section.rawSectionIndex }) });
  }
  return out.sort((left, right) => left.index - right.index);
};

const readTableRange = (file: File, offset: bigint, size: bigint,
  label: string, issues: string[]): TableRange | null => {
  if (offset < 0n || offset >= BigInt(file.size) || size <= 0n) {
    issues.push(`${label} is outside the file or empty.`);
    return null;
  }
  const available = BigInt(file.size) - offset;
  if (size > available) issues.push(`${label} is truncated.`);
  return { offset: Number(offset), size: Number(size > available ? available : size) };
};

const parseDynsymFromSections = async (opts: {
  file: File;
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<DynamicSymbolTables | null> => {
  const dynsym = opts.sections.find(sec => sec.type === SHT_DYNSYM && sec.size > 0n);
  if (!dynsym) return null;
  if (dynsym.entsize !== BigInt(selectElfBinaryLayout(opts).symbolEntrySize)) {
    opts.issues.push(".dynsym has an invalid entry size.");
    return null;
  }
  const symtab = readTableRange(opts.file, dynsym.offset, dynsym.size, ".dynsym", opts.issues);
  if (!symtab) return null;

  const linked = opts.sections[dynsym.link];
  // gABI 3: SHT_DYNSYM.sh_link identifies the associated SHT_STRTAB, regardless of names.
  if (!linked || linked.type !== 3) {
    opts.issues.push(".dynsym sh_link does not reference SHT_STRTAB.");
    return { symtab, strtab: null };
  }
  const strtab = readTableRange(opts.file, linked.offset, linked.size, ".dynstr", opts.issues);
  return { symtab, strtab };
};

const parseDynsymFromDynamicTags = async (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}, entries: ElfDynamicEntry[], hashes?: ElfHashTable[]):
Promise<DynamicSymbolTables | null> => {
  const dynamicPh = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  if (!dynamicPh) return null;
  const tags = dynsymTags(entries, selectElfBinaryLayout(opts).symbolEntrySize, opts.issues);
  if (!tags) return null;
  const symtab = await locateDynamicSymbolTable(opts, tags, entries, hashes);
  if (!symtab) return null;
  const strtab = elfVirtualRange(opts.programHeaders, tags.strtabVaddr, tags.strsz, opts.file.size);
  if (!strtab) opts.issues.push("DT_STRTAB is outside a file-backed PT_LOAD range.");
  return strtab ? { symtab, strtab } : null;
};

const locateDynamicSymbolTable = async (opts: Parameters<typeof parseDynsymFromDynamicTags>[0],
  { symtabVaddr, strtabVaddr, entrySize }: NonNullable<ReturnType<typeof dynsymTags>>,
  entries: ElfDynamicEntry[], hashes: ElfHashTable[] | undefined): Promise<TableRange | null> => {
  const declaredSize = entries.find(entry => entry.tag === ELF_DYNAMIC_TAG.SYMTABSZ)?.value;
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

const dynsymTags = (entries: ElfDynamicEntry[], expectedSize: number, issues: string[]) => {
  const value = (tag: number): bigint => entries.find(entry => entry.tag === tag)?.value ?? 0n;
  const symtabVaddr = value(DT_SYMTAB);
  const strtabVaddr = value(DT_STRTAB);
  const strsz = value(DT_STRSZ);
  const entrySize = Number(value(DT_SYMENT));
  if (entrySize !== expectedSize) {
    issues.push("DT_SYMENT has an invalid symbol entry size.");
    return null;
  }
  if ([symtabVaddr, strtabVaddr, strsz].includes(0n)) return null;
  return { symtabVaddr, strtabVaddr, strsz, entrySize };
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

export async function parseElfDynamicSymbols(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
}, parsedEntries?: ElfDynamicEntry[], symbolCache = new Map<number, ElfRelocationSymbol>(),
layout = selectElfBinaryLayout(opts), hashes?: ElfHashTable[]):
Promise<ElfDynamicSymbolInfo | null> {
  const issues: string[] = [];

  const sectionTables = await parseDynsymFromSections({ ...opts, issues });
  const entries = parsedEntries ?? await readElfDynamicEntries(
    createFileRangeReader(opts.file, 0, opts.file.size), opts, issues, layout);
  const tagTables = sectionTables ? null :
    await parseDynsymFromDynamicTags({ ...opts, issues }, entries, hashes);
  const tables = sectionTables ?? tagTables;
  if (!tables) return issues.length ? { total: 0, importSymbols: [], exportSymbols: [], issues } : null;

  const symbols = await parseDynsym(tables.symtab, tables.strtab, layout,
    issues, symbolCache,
    createElfDynamicIndexReader(opts.file, opts, tables.symtab.offset, entries, issues),
    createFileRangeReader(opts.file, 0, opts.file.size));
  const importSymbols = symbols.filter(sym => sym.shndx === SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);
  const exportSymbols = symbols.filter(sym => sym.shndx !== SHN_UNDEF &&
    sym.bind !== STB_LOCAL && sym.name.length > 0 &&
    sym.visibility !== STV_HIDDEN && sym.visibility !== STV_INTERNAL);

  return {
    total: Math.floor(tables.symtab.size / layout.symbolEntrySize),
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
