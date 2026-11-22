import type { FileRangeReader } from "../file-range-reader.js";
import { elfFileRange, elfVirtualRange } from "./relocation-reader.js";
import type { ElfParseResult, ElfSectionHeader } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import { ELF_SECTION_COMPRESSED } from "./section-data.js";

export interface ElfVersionTable {
  offset: number;
  size: number;
  count: number;
  strings: { offset: number; size: number } | null;
}

// LSB 10.7 and glibc elf/elf.h: section types and corresponding dynamic tags.
// https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.pdf
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
  if (section) return sectionVersionTable(elf, section, kind, symbolCount, issues);
  return dynamicVersionTable(elf, entries, kind, symbolCount, issues);
};

const sectionVersionTable = (
  elf: ElfParseResult, section: ElfSectionHeader, kind: keyof typeof versionSources,
  symbolCount: number, issues: string[]
): ElfVersionTable | null => {
  if (section.flags & ELF_SECTION_COMPRESSED) {
    issues.push(`${kind}: compressed version section cannot be read as a version table.`);
    return null;
  }
  const range = elfFileRange(section.offset, section.size, elf.fileSize);
  if (!range) {
    issues.push(`${kind}: version section is truncated or outside the file.`);
    return null;
  }
  if (kind === "symbols") {
    return { ...range, count: sectionVersionSymbolCount(elf, section, symbolCount, issues), strings: null };
  }
  const strings = elf.sections.find(item => item.index === section.link && item.type === 3);
  return { ...range, count: section.info,
    strings: strings ? elfFileRange(strings.offset, strings.size, elf.fileSize) : null };
};

const sectionVersionSymbolCount = (
  elf: ElfParseResult, section: ElfSectionHeader, fallback: number, issues: string[]
): number => {
  const dynsym = elf.sections.find(item => item.index === section.link && item.type === 11);
  const stride = elf.is64 ? 24n : 16n; // gABI 5: Elf64_Sym and Elf32_Sym widths.
  if (!dynsym || dynsym.flags & ELF_SECTION_COMPRESSED || dynsym.entsize !== stride ||
    dynsym.size % stride !== 0n || !elfFileRange(dynsym.offset, dynsym.size, elf.fileSize)) return fallback;
  const count = Number(dynsym.size / stride);
  if (section.size / 2n > BigInt(count)) {
    issues.push(`Symbol version table contains ${section.size / 2n} entries for ${count} dynamic symbols.`);
  }
  return count;
};

const dynamicVersionStrings = (
  elf: ElfParseResult, entries: ElfDynamicEntry[]
): { offset: number; size: number } | null => {
  const address = entries.find(item => item.tag === 5)?.value;
  const size = entries.find(item => item.tag === 10)?.value;
  return address != null && size != null ? elfVirtualRange(elf.programHeaders, address, size, elf.fileSize) : null;
};

const dynamicVersionTable = (
  elf: ElfParseResult, entries: ElfDynamicEntry[], kind: keyof typeof versionSources,
  symbolCount: number, issues: string[]
): ElfVersionTable | null => {
  const source = versionSources[kind];
  const address = entries.find(item => item.tag === source.tag)?.value;
  if (address == null) return null;
  const range = dynamicVersionRange(elf, address, kind === "symbols" ? BigInt(symbolCount) * 2n : null);
  if (!range) issues.push(`${kind}: version address is outside file-backed PT_LOAD data.`);
  const count = dynamicVersionCount(entries, kind, symbolCount, issues);
  if (count == null) return null;
  return range ? { ...range, count, strings: dynamicVersionStrings(elf, entries) } : null;
};

const dynamicVersionCount = (
  entries: ElfDynamicEntry[], kind: keyof typeof versionSources, symbolCount: number, issues: string[]
): number | null => {
  const count = kind === "symbols" ? symbolCount : Number(
    entries.find(item => item.tag === versionSources[kind].count)?.value ?? 0n);
  if (Number.isSafeInteger(count) && count > 0) return count;
  issues.push(`${kind}: missing or invalid version record count.`);
  return null;
};

const dynamicVersionRange = (
  elf: ElfParseResult, address: bigint, size: bigint | null
): { offset: number; size: number } | null => {
  const segment = elf.programHeaders.find(item => item.type === 1 &&
    address >= item.vaddr && address < item.vaddr + item.filesz);
  return segment ? elfVirtualRange(elf.programHeaders, address,
    size ?? segment.vaddr + segment.filesz - address, elf.fileSize) : null;
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
