"use strict";

import type { ElfProgramHeader } from "./types.js";
import type { ElfDisassemblySeedGroup } from "./disassembly-seeds-types.js";
import { readDynsymCountFromGnuHash, readDynsymCountFromSysvHash } from "./dynsym-count.js";
import { elfLoadFilePrefix } from "./load-file-tail.js";

const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const DT_NULL = 0;
const DT_HASH = 4;
const DT_GNU_HASH = 0x6ffffef5;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_SYMENT = 11;
const DT_INIT = 12;
const DT_FINI = 13;
const DT_INIT_ARRAY = 25;
const DT_FINI_ARRAY = 26;
const DT_INIT_ARRAYSZ = 27;
const DT_FINI_ARRAYSZ = 28;
const DT_PREINIT_ARRAY = 32;
const DT_PREINIT_ARRAYSZ = 33;

const STT_FUNC = 2;
const STT_GNU_IFUNC = 10;
const SHN_UNDEF = 0;

const isFunctionType = (typeNibble: number): boolean => typeNibble === STT_FUNC || typeNibble === STT_GNU_IFUNC;

const toSafeIndex = (value: bigint, label: string, issues: string[]): number | null => {
  const num = Number(value);
  if (!Number.isSafeInteger(num) || num < 0) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

const hasLoadSegments = (programHeaders: ElfProgramHeader[]): boolean =>
  programHeaders.some(ph => ph.type === PT_LOAD && ph.filesz > 0n);

type DynTagMap = Map<number, bigint>;

const parseDynamicTags = (bytes: Uint8Array<ArrayBuffer>, is64: boolean, littleEndian: boolean): DynTagMap => {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entrySize = is64 ? 16 : 8;
  const out = new Map<number, bigint>();
  const count = Math.floor(dv.byteLength / entrySize);
  for (let index = 0; index < count; index += 1) {
    const base = index * entrySize;
    const tag = is64 ? Number(dv.getBigInt64(base, littleEndian)) : dv.getInt32(base, littleEndian);
    const value = is64 ? dv.getBigUint64(base + 8, littleEndian) : BigInt(dv.getUint32(base + 4, littleEndian));
    if (tag === DT_NULL) break;
    if (!out.has(tag)) out.set(tag, value);
  }
  return out;
};

type MappedSeedInput = {
  file: File;
  programHeaders: ElfProgramHeader[];
  vaddr: bigint;
  byteSize: bigint;
  issues: string[];
  label: string;
};

const readMappedSeedBytes = async (opts: MappedSeedInput): Promise<DataView | null> => {
  const range = elfLoadFilePrefix(opts.programHeaders, opts.vaddr, opts.byteSize, opts.file.size);
  if (!range) {
    opts.issues.push(`${opts.label} does not map to an unambiguous file-backed PT_LOAD range.`);
    return null;
  }
  if (BigInt(range.size) < opts.byteSize) {
    opts.issues.push(`${opts.label} extends past its file-backed PT_LOAD range or the end of the file. ` +
      "Reading the available prefix.");
  }
  return new DataView(await opts.file.slice(range.offset, range.offset + range.size).arrayBuffer());
};

const readPointerArrayAtVaddr = async (
  opts: MappedSeedInput & { is64: boolean; littleEndian: boolean }
): Promise<bigint[]> => {
  const dv = await readMappedSeedBytes(opts);
  if (!dv) return [];
  const pointerSize = opts.is64 ? 8 : 4;
  if (dv.byteLength % pointerSize !== 0) {
    opts.issues.push(`${opts.label} size is not aligned to pointer size (${pointerSize} bytes).`);
  }
  const count = Math.floor(dv.byteLength / pointerSize);
  const out: bigint[] = [];
  for (let index = 0; index < count; index += 1) {
    const off = index * pointerSize;
    const value =
      pointerSize === 8
        ? dv.getBigUint64(off, opts.littleEndian)
        : BigInt(dv.getUint32(off, opts.littleEndian));
    if (value !== 0n) out.push(value);
  }
  return out;
};

const readDynsymFunctionVaddrs = async (opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  symtabVaddr: bigint;
  entrySize: number;
  symbolCount: number;
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<bigint[]> => {
  const dv = await readMappedSeedBytes({ ...opts, vaddr: opts.symtabVaddr,
    byteSize: BigInt(opts.entrySize) * BigInt(opts.symbolCount), label: "DT_SYMTAB" });
  if (!dv) return [];
  const count = Math.floor(dv.byteLength / opts.entrySize);
  const out: bigint[] = [];
  for (let index = 0; index < count; index += 1) {
    const base = index * opts.entrySize;
    if (opts.is64) {
      if (base + 24 > dv.byteLength) break;
      const stInfo = dv.getUint8(base + 4);
      const stShndx = dv.getUint16(base + 6, opts.littleEndian);
      const stValue = dv.getBigUint64(base + 8, opts.littleEndian);
      const type = stInfo & 0x0f;
      if (!isFunctionType(type)) continue;
      if (stShndx === SHN_UNDEF) continue;
      if (stValue === 0n) continue;
      out.push(stValue);
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
    out.push(stValue);
  }
  return out;
};

export async function collectElfDisassemblySeedsFromDynamic(opts: {
  file: File;
  programHeaders: ElfProgramHeader[];
  is64: boolean;
  littleEndian: boolean;
  issues: string[];
}): Promise<ElfDisassemblySeedGroup[]> {
  const groups: ElfDisassemblySeedGroup[] = [];
  if (!hasLoadSegments(opts.programHeaders)) return groups;

  const dynamicPh = opts.programHeaders.find(ph => ph.type === PT_DYNAMIC && ph.filesz > 0n);
  if (!dynamicPh) return groups;

  const dynStart = toSafeIndex(dynamicPh.offset, "PT_DYNAMIC offset", opts.issues);
  const dynSize = toSafeIndex(dynamicPh.filesz, "PT_DYNAMIC size", opts.issues);
  if (dynStart == null || dynSize == null || dynSize <= 0) return groups;
  const dynEnd = Math.min(opts.file.size, dynStart + dynSize);
  if (dynStart >= opts.file.size || dynEnd <= dynStart) return groups;
  const dynBytes = new Uint8Array(await opts.file.slice(dynStart, dynEnd).arrayBuffer());
  const tags = parseDynamicTags(dynBytes, opts.is64, opts.littleEndian);

  const addPointerTag = (tag: number, label: string): void => {
    const value = tags.get(tag);
    if (value && value !== 0n) groups.push({ source: label, vaddrs: [value] });
  };
  addPointerTag(DT_INIT, "DT_INIT");
  addPointerTag(DT_FINI, "DT_FINI");

  const addArrayTag = async (baseTag: number, sizeTag: number, label: string): Promise<void> => {
    const base = tags.get(baseTag);
    const size = tags.get(sizeTag);
    if (!base || !size || base === 0n || size === 0n) return;
    const vaddrs = await readPointerArrayAtVaddr({
      file: opts.file,
      programHeaders: opts.programHeaders,
      vaddr: base,
      byteSize: size,
      is64: opts.is64,
      littleEndian: opts.littleEndian,
      issues: opts.issues,
      label
    });
    if (vaddrs.length) groups.push({ source: label, vaddrs });
  };
  await addArrayTag(DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ, "DT_PREINIT_ARRAY");
  await addArrayTag(DT_INIT_ARRAY, DT_INIT_ARRAYSZ, "DT_INIT_ARRAY");
  await addArrayTag(DT_FINI_ARRAY, DT_FINI_ARRAYSZ, "DT_FINI_ARRAY");

  const symtab = tags.get(DT_SYMTAB);
  const syment = tags.get(DT_SYMENT);
  const hash = tags.get(DT_HASH);
  const gnuHash = tags.get(DT_GNU_HASH);
  if (
    symtab &&
    syment &&
    symtab !== 0n &&
    syment !== 0n &&
    ((hash && hash !== 0n) || (gnuHash && gnuHash !== 0n))
  ) {
    const entrySize = Number(syment);
    const count =
      (hash && hash !== 0n
        ? await readDynsymCountFromSysvHash({
            file: opts.file,
            programHeaders: opts.programHeaders,
            hashVaddr: hash,
            littleEndian: opts.littleEndian,
            issues: opts.issues
          })
        : null) ??
      (gnuHash && gnuHash !== 0n
        ? await readDynsymCountFromGnuHash({
            file: opts.file,
            programHeaders: opts.programHeaders,
            hashVaddr: gnuHash,
            is64: opts.is64,
            littleEndian: opts.littleEndian,
            issues: opts.issues
          })
        : null);
    if (Number.isSafeInteger(entrySize) && entrySize > 0 && count) {
      const vaddrs = await readDynsymFunctionVaddrs({
        file: opts.file,
        programHeaders: opts.programHeaders,
        symtabVaddr: symtab,
        entrySize,
        symbolCount: count,
        is64: opts.is64,
        littleEndian: opts.littleEndian,
        issues: opts.issues
      });
      if (vaddrs.length) groups.push({ source: "DT_SYMTAB (function symbols)", vaddrs });
    }
  }

  // DT_STRTAB is currently unused: we don't need names for disassembly seeding.
  void tags.get(DT_STRTAB);

  return groups;
}
