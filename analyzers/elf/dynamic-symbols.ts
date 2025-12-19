"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { ElfDynamicSymbol, ElfDynamicSymbolInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { vaddrToFileOffset } from "./vaddr-to-file-offset.js";

const PT_DYNAMIC = 2;
const SHT_DYNSYM = 11;

const DT_NULL = 0;
const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_STRSZ = 10;
const DT_SYMENT = 11;

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

type DynEntry = { tag: number; value: bigint };

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const parseDynamicEntries = (bytes: Uint8Array, is64: boolean, littleEndian: boolean): DynEntry[] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entrySize = is64 ? 16 : 8;
  const count = Math.floor(dv.byteLength / entrySize);
  const out: DynEntry[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = index * entrySize;
    const tagBig = is64 ? dv.getBigInt64(base, littleEndian) : BigInt(dv.getInt32(base, littleEndian));
    const tag = Number(tagBig);
    if (!Number.isSafeInteger(tag)) break;
    const value = is64 ? dv.getBigUint64(base + 8, littleEndian) : BigInt(dv.getUint32(base + 4, littleEndian));
    if (tag === DT_NULL) break;
    out.push({ tag, value });
  }
  return out;
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
  is64: boolean,
  littleEndian: boolean,
  issues: string[]
): ElfDynamicSymbol[] => {
  const defaultEntrySize = is64 ? 24 : 16;
  const entrySize = defaultEntrySize;
  const count = Math.floor(symtab.byteLength / entrySize);
  if (symtab.byteLength % entrySize !== 0) {
    issues.push(`.dynsym size is not aligned to entry size (${entrySize} bytes).`);
  }
  const out: ElfDynamicSymbol[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = index * entrySize;
    if (base + entrySize > symtab.byteLength) break;
    const nameOff = symtab.getUint32(base, littleEndian);
    let value: bigint;
    let size: bigint;
    let info: number;
    let other: number;
    let shndx: number;
    if (is64) {
      info = symtab.getUint8(base + 4);
      other = symtab.getUint8(base + 5);
      shndx = symtab.getUint16(base + 6, littleEndian);
      value = symtab.getBigUint64(base + 8, littleEndian);
      size = symtab.getBigUint64(base + 16, littleEndian);
    } else {
      value = BigInt(symtab.getUint32(base + 4, littleEndian));
      size = BigInt(symtab.getUint32(base + 8, littleEndian));
      info = symtab.getUint8(base + 12);
      other = symtab.getUint8(base + 13);
      shndx = symtab.getUint16(base + 14, littleEndian);
    }
    const bind = info >> 4;
    const type = info & 0x0f;
    if (!isDisplayableType(type)) continue;
    const visibility = other & 0x03;
    const name = readString(strtab, nameOff);
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
}): Promise<{ symtab: DataView; strtab: DataView | null } | null> => {
  const dynsym = opts.sections.find(sec => sec.type === SHT_DYNSYM && sec.size > 0n);
  if (!dynsym) return null;
  const symtab = await readDataViewSlice(opts.file, dynsym.offset, dynsym.size, ".dynsym", opts.issues);
  if (!symtab) return null;

  const linked = opts.sections[dynsym.link];
  const dynstr =
    (linked && linked.size > 0n ? linked : null) ?? opts.sections.find(sec => sec.name === ".dynstr" && sec.size > 0n) ?? null;
  const strtab = dynstr ? await readDataViewSlice(opts.file, dynstr.offset, dynstr.size, ".dynstr", opts.issues) : null;
  return { symtab, strtab };
};

const parseDynsymFromDynamicTags = async (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<{ symtab: DataView; strtab: DataView | null } | null> => {
  const dynamicPh = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  if (!dynamicPh) return null;
  const dynamicBytes = await readDataViewSlice(opts.file, dynamicPh.offset, dynamicPh.filesz, "PT_DYNAMIC", opts.issues);
  if (!dynamicBytes) return null;
  const entries = parseDynamicEntries(
    new Uint8Array(dynamicBytes.buffer, dynamicBytes.byteOffset, dynamicBytes.byteLength),
    opts.is64,
    opts.littleEndian
  );

  const symtabVaddr = entries.find(entry => entry.tag === DT_SYMTAB)?.value ?? 0n;
  const syment = entries.find(entry => entry.tag === DT_SYMENT)?.value ?? 0n;
  const strtabVaddr = entries.find(entry => entry.tag === DT_STRTAB)?.value ?? 0n;
  const strsz = entries.find(entry => entry.tag === DT_STRSZ)?.value ?? 0n;

  if (symtabVaddr === 0n || syment === 0n || strtabVaddr === 0n || strsz === 0n) return null;

  const hashVaddr = entries.find(entry => entry.tag === DT_HASH)?.value ?? 0n;
  let symbolCount: number | null = null;
  if (hashVaddr !== 0n) {
    const hashOff = vaddrToFileOffset(opts.programHeaders, hashVaddr);
    if (hashOff != null) {
      const start = toSafeIndex(hashOff, "DT_HASH file offset", opts.issues);
      if (start != null) {
        const bytes = new Uint8Array(await opts.file.slice(start, Math.min(opts.file.size, start + 8)).arrayBuffer());
        if (bytes.byteLength === 8) {
          const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
          symbolCount = dv.getUint32(4, opts.littleEndian);
        }
      }
    }
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
  return { symtab, strtab };
};

export async function parseElfDynamicSymbols(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
}): Promise<ElfDynamicSymbolInfo | null> {
  const issues: string[] = [];

  const sectionTables = await parseDynsymFromSections({ ...opts, issues });
  const tagTables = sectionTables ? null : await parseDynsymFromDynamicTags({ ...opts, issues });
  const tables = sectionTables ?? tagTables;
  if (!tables) return null;

  const symbols = parseDynsym(tables.symtab, tables.strtab, opts.is64, opts.littleEndian, issues);
  const importSymbols = symbols.filter(sym => sym.shndx === SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);
  const exportSymbols = symbols.filter(sym => sym.shndx !== SHN_UNDEF && sym.bind !== STB_LOCAL && sym.name.length > 0);

  return {
    total: symbols.length,
    importSymbols,
    exportSymbols,
    issues
  };
}
