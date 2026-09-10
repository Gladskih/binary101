"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { readDynsymCountFromGnuHash, readDynsymCountFromSysvHash } from "./dynsym-count.js";
import { vaddrToFileOffset } from "./vaddr-to-file-offset.js";
import { readElfDynamicEntries, type ElfDynamicEntry } from "./dynamic-entries.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import { ELF_SYMBOL_INDEX } from "./abi-constants.js";
import type { ElfHashTable } from "./hash-types.js";

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

const STT_NOTYPE = 0;
const STT_OBJECT = 1;
const STT_FUNC = 2;
const STT_TLS = 6;
const STT_GNU_IFUNC = 10;

const STB_LOCAL = 0;

const STV_DEFAULT = 0;
const STV_INTERNAL = 1;
const STV_HIDDEN = 2;
const STV_PROTECTED = 3;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const readString = (table: DataView | null, offset: number): string => {
  if (!table || offset < 0 || offset >= table.byteLength) return "";
  return readAsciiString(table, offset, table.byteLength - offset);
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

const isDisplayableType = (type: number): boolean =>
  type === STT_NOTYPE || type === STT_OBJECT || type === STT_FUNC || type === STT_TLS || type === STT_GNU_IFUNC;

const parseDynsym = (
  symtab: DataView,
  strtab: DataView | null,
  layout: ElfBinaryLayout,
  issues: string[],
  tableOffset: number,
  symbolCache: Map<number, ElfRelocationSymbol>
): ElfDynamicSymbol[] => {
  const entrySize = layout.symbolEntrySize;
  const count = Math.floor(symtab.byteLength / entrySize);
  if (symtab.byteLength % entrySize !== 0) {
    issues.push(`.dynsym size is not aligned to entry size (${entrySize} bytes).`);
  }
  const out: ElfDynamicSymbol[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = index * entrySize;
    if (base + entrySize > symtab.byteLength) break;
    const { nameOffset: nameOff, value, size, info, other, sectionIndex: shndx } =
      layout.readSymbol(new DataView(symtab.buffer, symtab.byteOffset + base, entrySize))!;
    // ELF*_ST_BIND/TYPE/VISIBILITY: high/low st_info nibbles and low two st_other bits.
    // https://gabi.xinuos.com/elf/05-symtab.html
    const bind = info >> 4;
    const type = info & 0x0f;
    if (!isDisplayableType(type)) continue;
    const visibility = other & 0x03;
    const name = readString(strtab, nameOff);
    // Reuse only names terminated within the table.
    if (strtab && nameOff + name.length < strtab.byteLength &&
      shndx !== ELF_SYMBOL_INDEX.XINDEX) {
      symbolCache.set(tableOffset + base, { name, value, sectionIndex: shndx });
    }
    out.push({
      index,
      name,
      value,
      size,
      bind,
      bindName: decodeBind(bind),
      type,
      typeName: decodeType(type),
      visibility,
      visibilityName: decodeVisibility(visibility),
      shndx
    });
  }
  return out;
};

const readDataViewSlice = async (
  file: File,
  offset: bigint,
  size: bigint,
  label: string,
  issues: string[]
): Promise<DataView | null> => {
  const start = toSafeIndex(offset, `${label} offset`, issues);
  const byteSize = toSafeIndex(size, `${label} size`, issues);
  if (start == null || byteSize == null || byteSize <= 0) return null;
  const end = Math.min(file.size, start + byteSize);
  if (start >= file.size || end <= start) return null;
  if (end !== start + byteSize) issues.push(`${label} is truncated.`);
  const bytes = new Uint8Array(await file.slice(start, end).arrayBuffer());
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
};

const parseDynsymFromSections = async (opts: {
  file: File;
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<{ symtab: DataView; strtab: DataView | null; offset: number } | null> => {
  const dynsym = opts.sections.find(sec => sec.type === SHT_DYNSYM && sec.size > 0n);
  if (!dynsym) return null;
  const symtab = await readDataViewSlice(opts.file, dynsym.offset, dynsym.size, ".dynsym", opts.issues);
  if (!symtab) return null;

  const linked = opts.sections[dynsym.link];
  const dynstr =
    (linked && linked.size > 0n ? linked : null) ?? opts.sections.find(sec => sec.name === ".dynstr" && sec.size > 0n) ?? null;
  const strtab = dynstr ? await readDataViewSlice(opts.file, dynstr.offset, dynstr.size, ".dynstr", opts.issues) : null;
  return { symtab, strtab, offset: Number(dynsym.offset) };
};

const parseDynsymFromDynamicTags = async (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}, parsedEntries?: ElfDynamicEntry[], hashes?: ElfHashTable[]):
Promise<{ symtab: DataView; strtab: DataView | null; offset: number } | null> => {
  const dynamicPh = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  if (!dynamicPh) return null;
  const entries = parsedEntries ?? await readElfDynamicEntries(
    createFileRangeReader(opts.file, 0, opts.file.size), opts, opts.issues);

  const symtabVaddr = entries.find(entry => entry.tag === DT_SYMTAB)?.value ?? 0n;
  const syment = entries.find(entry => entry.tag === DT_SYMENT)?.value ?? 0n;
  const strtabVaddr = entries.find(entry => entry.tag === DT_STRTAB)?.value ?? 0n;
  const strsz = entries.find(entry => entry.tag === DT_STRSZ)?.value ?? 0n;

  if (symtabVaddr === 0n || syment === 0n || strtabVaddr === 0n || strsz === 0n) return null;

  const hashVaddr = entries.find(entry => entry.tag === DT_HASH)?.value ?? 0n;
  const gnuHashVaddr = entries.find(entry => entry.tag === DT_GNU_HASH)?.value ?? 0n;
  let symbolCount: number | null = hashSymbolCount(hashes);
  if (hashes == null && hashVaddr !== 0n) {
    symbolCount = await readDynsymCountFromSysvHash({
      file: opts.file,
      programHeaders: opts.programHeaders,
      hashVaddr,
      littleEndian: opts.littleEndian,
      issues: opts.issues
    });
  }
  if (hashes == null && symbolCount == null && gnuHashVaddr !== 0n) {
    symbolCount = await readDynsymCountFromGnuHash({
      file: opts.file,
      programHeaders: opts.programHeaders,
      hashVaddr: gnuHashVaddr,
      is64: opts.is64,
      littleEndian: opts.littleEndian,
      issues: opts.issues
    });
  }

  const entrySize = Number(syment);
  if (!Number.isSafeInteger(entrySize) || entrySize <= 0) return null;

  if (symbolCount == null) {
    if (strtabVaddr > symtabVaddr) {
      const inferredBytes = strtabVaddr - symtabVaddr;
      const inferredCount = Number(inferredBytes / BigInt(entrySize));
      if (Number.isSafeInteger(inferredCount) && inferredCount > 0) {
        symbolCount = inferredCount;
        if (inferredBytes % BigInt(entrySize) !== 0n) {
          opts.issues.push("Inferred .dynsym size is not aligned to entry size.");
        }
        opts.issues.push("Dynsym count inferred from DT_STRTAB - DT_SYMTAB; may be imprecise.");
      }
    }
  }

  if (symbolCount == null || symbolCount <= 0) return null;

  const symtabOff = vaddrToFileOffset(opts.programHeaders, symtabVaddr);
  const strtabOff = vaddrToFileOffset(opts.programHeaders, strtabVaddr);
  if (symtabOff == null || strtabOff == null) return null;

  const symtabByteSize = BigInt(symbolCount) * BigInt(entrySize);
  const symtab = await readDataViewSlice(opts.file, symtabOff, symtabByteSize, "DT_SYMTAB", opts.issues);
  const strtab = await readDataViewSlice(opts.file, strtabOff, strsz, "DT_STRTAB", opts.issues);
  if (!symtab) return null;
  return { symtab, strtab, offset: Number(symtabOff) };
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
  const tagTables = sectionTables ? null : await parseDynsymFromDynamicTags({ ...opts, issues }, parsedEntries, hashes);
  const tables = sectionTables ?? tagTables;
  if (!tables) return null;

  const symbols = parseDynsym(tables.symtab, tables.strtab, layout,
    issues, tables.offset, symbolCache);
  const importSymbols = symbols.filter(sym => sym.shndx === SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);
  const exportSymbols = symbols.filter(sym => sym.shndx !== SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);

  return {
    total: Math.floor(tables.symtab.byteLength / layout.symbolEntrySize),
    importSymbols,
    exportSymbols,
    issues
  };
}

const hashSymbolCount = (tables: ElfHashTable[] | undefined): number | null => {
  const valid = tables?.filter(table => !table.issues.length);
  const sysv = valid?.find(table => table.kind === "sysv");
  if (sysv) return sysv.chains.length;
  const gnu = valid?.find(table => table.kind === "gnu");
  return gnu?.kind === "gnu" ? gnu.symbolOffset + gnu.chains.length : null;
};
