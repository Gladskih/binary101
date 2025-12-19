"use strict";

import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";

const STT_FUNC = 2;
const STT_GNU_IFUNC = 10;
const SHN_UNDEF = 0;

const SHT_SYMTAB = 2;
const SHT_DYNSYM = 11;
const SHT_INIT_ARRAY = 14;
const SHT_FINI_ARRAY = 15;
const SHT_PREINIT_ARRAY = 16;

const PT_LOAD = 1;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const readSectionBytes = async (
  file: File,
  section: { offset: bigint; size: bigint },
  label: string,
  issues: string[]
): Promise<Uint8Array<ArrayBuffer> | null> => {
  const start = toSafeIndex(section.offset, `${label} offset`, issues);
  const size = toSafeIndex(section.size, `${label} size`, issues);
  if (start == null || size == null || size <= 0) return null;
  const end = Math.min(file.size, start + size);
  if (start >= file.size || end <= start) return null;
  if (end !== start + size) {
    issues.push(`${label} extends past end of file; truncating to available bytes.`);
  }
  return new Uint8Array(await file.slice(start, end).arrayBuffer());
};

const hasLoadSegments = (programHeaders: ElfProgramHeader[]): boolean =>
  programHeaders.some(ph => ph.type === PT_LOAD && ph.filesz > 0n);

const isFunctionType = (typeNibble: number): boolean => typeNibble === STT_FUNC || typeNibble === STT_GNU_IFUNC;

const readPointerArray = (
  bytes: Uint8Array<ArrayBuffer>,
  pointerSize: 4 | 8,
  littleEndian: boolean,
  issues: string[],
  label: string
): bigint[] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: bigint[] = [];
  if (bytes.byteLength % pointerSize !== 0) {
    issues.push(`${label} size is not aligned to pointer size (${pointerSize} bytes).`);
  }
  const count = Math.floor(dv.byteLength / pointerSize);
  for (let index = 0; index < count; index += 1) {
    const off = index * pointerSize;
    const value = pointerSize === 8 ? dv.getBigUint64(off, littleEndian) : BigInt(dv.getUint32(off, littleEndian));
    if (value !== 0n) out.push(value);
  }
  return out;
};

const readSymbolVaddrs = (
  bytes: Uint8Array<ArrayBuffer>,
  opts: {
    is64: boolean;
    littleEndian: boolean;
    hasLoadSegments: boolean;
    sections: ElfSectionHeader[];
  },
  issues: string[],
  label: string,
  entsize: number
): bigint[] => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entrySize =
    Number.isSafeInteger(entsize) && entsize > 0 ? entsize : opts.is64 ? 24 : 16;
  if (entrySize <= 0) return [];
  if (dv.byteLength % entrySize !== 0) {
    issues.push(`${label} size is not aligned to entry size (${entrySize} bytes).`);
  }
  const count = Math.floor(dv.byteLength / entrySize);
  const out: bigint[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = index * entrySize;
    if (opts.is64) {
      if (base + 24 > dv.byteLength) break;
      const stInfo = dv.getUint8(base + 4);
      const stShndx = dv.getUint16(base + 6, opts.littleEndian);
      const stValue = dv.getBigUint64(base + 8, opts.littleEndian);
      const type = stInfo & 0x0f;
      if (!isFunctionType(type)) continue;
      if (stShndx === SHN_UNDEF) continue;
      if (stValue === 0n) continue;
      if (opts.hasLoadSegments) {
        out.push(stValue);
        continue;
      }
      const section = opts.sections[stShndx];
      const addr = section ? section.addr : 0n;
      out.push(addr + stValue);
      continue;
    }
    if (base + 16 > dv.byteLength) break;
    const stValue = BigInt(dv.getUint32(base + 4, opts.littleEndian));
    const stInfo = dv.getUint8(base + 12);
    const stShndx = dv.getUint16(base + 14, opts.littleEndian);
    const type = stInfo & 0x0f;
    if (!isFunctionType(type)) continue;
    if (stShndx === SHN_UNDEF) continue;
    if (stValue === 0n) continue;
    if (opts.hasLoadSegments) {
      out.push(stValue);
      continue;
    }
    const section = opts.sections[stShndx];
    const addr = section ? section.addr : 0n;
    out.push(addr + stValue);
  }
  return out;
};

export async function collectElfDisassemblySeedsFromSections(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<ElfDisassemblySeedGroup[]> {
  const groups: ElfDisassemblySeedGroup[] = [];
  const pointerSize: 4 | 8 = opts.is64 ? 8 : 4;

  const arraySections = opts.sections.filter(sec =>
    sec.type === SHT_PREINIT_ARRAY || sec.type === SHT_INIT_ARRAY || sec.type === SHT_FINI_ARRAY
  );
  for (const sec of arraySections) {
    const label = sec.name ? `${sec.name} (SHT_${sec.type === SHT_INIT_ARRAY ? "INIT" : sec.type === SHT_FINI_ARRAY ? "FINI" : "PREINIT"}_ARRAY)` : `Section #${sec.index} (SHT_${sec.type})`;
    const bytes = await readSectionBytes(opts.file, sec, label, opts.issues);
    if (!bytes) continue;
    const vaddrs = readPointerArray(bytes, pointerSize, opts.littleEndian, opts.issues, label);
    if (vaddrs.length) groups.push({ source: label, vaddrs });
  }

  const symbolTableSections = opts.sections.filter(sec => sec.type === SHT_SYMTAB || sec.type === SHT_DYNSYM);
  const hasLoads = hasLoadSegments(opts.programHeaders);
  for (const sec of symbolTableSections) {
    const tableLabel = sec.name ? sec.name : sec.type === SHT_DYNSYM ? "SHT_DYNSYM" : "SHT_SYMTAB";
    const label = `${tableLabel} function symbols`;
    const bytes = await readSectionBytes(opts.file, sec, tableLabel, opts.issues);
    if (!bytes) continue;
    const entsize = Number(sec.entsize);
    const vaddrs = readSymbolVaddrs(
      bytes,
      { is64: opts.is64, littleEndian: opts.littleEndian, hasLoadSegments: hasLoads, sections: opts.sections },
      opts.issues,
      tableLabel,
      entsize
    );
    if (vaddrs.length) groups.push({ source: label, vaddrs });
  }

  return groups;
}

