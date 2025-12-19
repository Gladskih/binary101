"use strict";

import { readAsciiString } from "../../binary-utils.js";
import type { ElfDynamicInfo, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { vaddrToFileOffset } from "./vaddr-to-file-offset.js";

const PT_DYNAMIC = 2;
const SHT_DYNAMIC = 6;

const DT_NULL = 0;
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

const locateDynStringTable = async (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
  entries: DynEntry[];
  issues: string[];
}): Promise<DataView | null> => {
  const strtabEntry = opts.entries.find(entry => entry.tag === DT_STRTAB);
  const strszEntry = opts.entries.find(entry => entry.tag === DT_STRSZ);
  if (strtabEntry && strtabEntry.value !== 0n) {
    const fileOffset = vaddrToFileOffset(opts.programHeaders, strtabEntry.value);
    if (fileOffset != null) {
      const start = toSafeIndex(fileOffset, "DT_STRTAB file offset", opts.issues);
      const size = strszEntry ? toSafeIndex(strszEntry.value, "DT_STRSZ", opts.issues) : null;
      if (start != null && size != null && size > 0) {
        const end = Math.min(opts.file.size, start + size);
        if (end !== start + size) opts.issues.push("DT_STRTAB extends past end of file; truncating.");
        const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());
        return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      }
    } else {
      opts.issues.push("DT_STRTAB does not map into a PT_LOAD segment.");
    }
  }

  const dynstr = opts.sections.find(sec => sec.name === ".dynstr" && sec.size > 0n);
  if (!dynstr) return null;
  const start = toSafeIndex(dynstr.offset, ".dynstr offset", opts.issues);
  const size = toSafeIndex(dynstr.size, ".dynstr size", opts.issues);
  if (start == null || size == null || size <= 0) return null;
  const end = Math.min(opts.file.size, start + size);
  if (end !== start + size) opts.issues.push(".dynstr extends past end of file; truncating.");
  const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
};

const getTagValue = (entries: DynEntry[], tag: number): bigint | null =>
  entries.find(entry => entry.tag === tag)?.value ?? null;
const getTagValues = (entries: DynEntry[], tag: number): bigint[] =>
  entries.filter(entry => entry.tag === tag).map(entry => entry.value);

export async function parseElfDynamicInfo(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  sections: ElfSectionHeader[];
  is64: boolean;
  littleEndian: boolean;
}): Promise<ElfDynamicInfo | null> {
  const issues: string[] = [];

  const dynamicPh = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  const dynamicSection =
    dynamicPh == null ? opts.sections.find(sec => sec.type === SHT_DYNAMIC && sec.size > 0n) : null;
  const offset = dynamicPh?.offset ?? dynamicSection?.offset ?? 0n;
  const size = dynamicPh?.filesz ?? dynamicSection?.size ?? 0n;
  if (size <= 0n) return null;

  const start = toSafeIndex(offset, "Dynamic section offset", issues);
  const byteSize = toSafeIndex(size, "Dynamic section size", issues);
  if (start == null || byteSize == null || byteSize <= 0) return null;
  const end = Math.min(opts.file.size, start + byteSize);
  if (start >= opts.file.size || end <= start) return null;
  if (end !== start + byteSize) issues.push("Dynamic section is truncated.");
  const bytes = new Uint8Array(await opts.file.slice(start, end).arrayBuffer());

  const entries = parseDynamicEntries(bytes, opts.is64, opts.littleEndian);
  const strtab = await locateDynStringTable({ ...opts, entries, issues });

  const needed = getTagValues(entries, DT_NEEDED)
    .map(value => readString(strtab, Number(value)))
    .filter(name => name.length > 0);

  const readNamedTag = (tag: number): string | null => {
    const value = getTagValue(entries, tag);
    if (value == null || value === 0n) return null;
    const offsetNum = Number(value);
    if (!Number.isSafeInteger(offsetNum) || offsetNum < 0) return null;
    const text = readString(strtab, offsetNum);
    return text.length ? text : null;
  };

  const readArrayTag = (baseTag: number, sizeTag: number): { vaddr: bigint; size: bigint } | null => {
    const base = getTagValue(entries, baseTag);
    const byteCount = getTagValue(entries, sizeTag);
    if (base == null || byteCount == null) return null;
    if (base === 0n || byteCount === 0n) return null;
    return { vaddr: base, size: byteCount };
  };

  const flagsValue = getTagValue(entries, DT_FLAGS);
  const flags1Value = getTagValue(entries, DT_FLAGS_1);
  const flags = flagsValue != null && flagsValue <= 0xffffffffn ? Number(flagsValue) : null;
  const flags1 = flags1Value != null && flags1Value <= 0xffffffffn ? Number(flags1Value) : null;

  return {
    needed,
    soname: readNamedTag(DT_SONAME),
    rpath: readNamedTag(DT_RPATH),
    runpath: readNamedTag(DT_RUNPATH),
    init: getTagValue(entries, DT_INIT),
    fini: getTagValue(entries, DT_FINI),
    preinitArray: readArrayTag(DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ),
    initArray: readArrayTag(DT_INIT_ARRAY, DT_INIT_ARRAYSZ),
    finiArray: readArrayTag(DT_FINI_ARRAY, DT_FINI_ARRAYSZ),
    flags,
    flags1,
    issues
  };
}
