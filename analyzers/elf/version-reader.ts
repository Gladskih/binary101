import type { FileRangeReader } from "../file-range-reader.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";

export interface ElfVersionTable {
  offset: number;
  size: number;
  count: number;
  strings: { offset: number; size: number } | null;
}

// LSB 10.7 and glibc elf/elf.h: section types and corresponding dynamic tags.
// https://refspecs.linuxfoundation.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic/symversion.html
// https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h
const versionSources = {
  definitions: { section: 0x6ffffffd, tag: 0x6ffffffc, count: 0x6ffffffd },
  requirements: { section: 0x6ffffffe, tag: 0x6ffffffe, count: 0x6fffffff },
  symbols: { section: 0x6fffffff, tag: 0x6ffffff0, count: 0 }
} as const;

export const locateElfVersionTable = (
  elf: ElfParseResult, entries: ElfDynamicEntry[], kind: keyof typeof versionSources,
  symbolCount: number, issues: string[]
): ElfVersionTable | null => {
  const source = versionSources[kind];
  const section = elf.sections.find(item => item.type === source.section);
  if (section) {
    const range = elfFileRange(section.offset, section.size, elf.fileSize);
    const strings = elf.sections.find(item => item.index === section.link && item.type === 3);
    if (!range) issues.push(`${kind}: version section is truncated or outside the file.`);
    return range ? { ...range, count: kind === "symbols" ? symbolCount : section.info,
      strings: strings ? elfFileRange(strings.offset, strings.size, elf.fileSize) : null } : null;
  }
  const address = entries.find(item => item.tag === source.tag)?.value;
  if (address == null) return null;
  const segment = elf.programHeaders.find(item => item.type === 1 &&
    address >= item.vaddr && address < item.vaddr + item.filesz);
  const range = segment && elfVirtualRange(elf.programHeaders, address,
    kind === "symbols" ? BigInt(symbolCount) * 2n : segment.vaddr + segment.filesz - address,
    elf.fileSize);
  if (!range) issues.push(`${kind}: version address is outside file-backed PT_LOAD data.`);
  const stringAddress = entries.find(item => item.tag === 5)?.value;
  const stringSize = entries.find(item => item.tag === 10)?.value;
  const count = kind === "symbols" ? symbolCount : Number(
    entries.find(item => item.tag === source.count)?.value ?? 0n);
  if (!Number.isSafeInteger(count) || count <= 0) {
    issues.push(`${kind}: missing or invalid version record count.`);
    return null;
  }
  return range ? { ...range, count, strings: stringAddress != null && stringSize != null
    ? elfVirtualRange(elf.programHeaders, stringAddress, stringSize, elf.fileSize) : null } : null;
};

export const readVersionBytes = async (
  reader: FileRangeReader, table: ElfVersionTable, offset: number, size: number,
  issues: string[]
): Promise<DataView | null> => {
  if (offset < 0 || offset > table.size - size) {
    issues.push("Version record is truncated or outside its table.");
    return null;
  }
  const view = await reader.read(table.offset + offset, size);
  if (view.byteLength === size) return view;
  issues.push("Version record is truncated.");
  return null;
};

export const createVersionStringReader = (
  reader: FileRangeReader, table: ElfVersionTable, issues: string[]
): ((offset: number) => Promise<string>) => {
  const cache = new Map<number, string>();
  return async offset => {
    const cached = cache.get(offset);
    if (cached != null) return cached;
    if (!table.strings || offset >= table.strings.size) {
      issues.push("Version string has an invalid string table reference.");
      return "";
    }
    const bytes: number[] = [];
    // Resource policy: a metadata name cannot allocate unbounded memory.
    const limit = Math.min(table.strings.size - offset, 65536);
    for (let index = 0; index < limit; index += 1) {
      const view = await reader.read(table.strings.offset + offset + index, 1);
      if (!view.byteLength) break;
      if (view.getUint8(0) === 0) {
        const name = new TextDecoder().decode(new Uint8Array(bytes));
        cache.set(offset, name);
        return name;
      }
      bytes.push(view.getUint8(0));
    }
    issues.push("Version string is unterminated or exceeds the 64 KiB name limit.");
    return "";
  };
};
