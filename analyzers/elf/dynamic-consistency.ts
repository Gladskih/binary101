import { findElfDynamicSegment, type ElfDynamicEntry, type ElfDynamicTable } from "./dynamic-entries.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { elfVirtualRange } from "./relocation-reader.js";
import { ELF_DYNAMIC_TAG, ELF_SECTION_FLAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { ELF_SECTION_COMPRESSED, hasCompressedSectionAt } from "./section-data.js";
import { elfLoadMappingCovers } from "./range-coverage.js";
import { ELF_DYNAMIC_TAG_DESCRIPTIONS } from "./dynamic-tags.js";

type DynamicDescription = {
  file: File; is64: boolean; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
};

export const elfSingleDynamicTag = (entries: ElfDynamicEntry[], tag: number): bigint | null | undefined => {
  let value: bigint | undefined;
  for (const entry of entries) {
    if (entry.tag !== tag) continue;
    if (value !== undefined && value !== entry.value) return null;
    value = entry.value;
  }
  return value;
};

export const elfDynamicStringRange = (
  image: DynamicDescription, entries: ElfDynamicEntry[], issues?: string[]
): { offset: number; size: number } | null => {
  const address = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.STRTAB);
  const size = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.STRSZ);
  if (address === null || size === null) {
    issues?.push("Conflicting DT_STRTAB or DT_STRSZ values.");
    return null;
  }
  if (address === undefined || size === undefined) return null;
  const range = elfVirtualRange(image.programHeaders, address, size, image.file.size);
  if (range && !hasCompressedSectionAt(image.sections, ELF_SECTION_TYPE.STRTAB, range.offset)) return range;
  issues?.push(range ? "DT_STRTAB points into a compressed string table." :
    "DT_STRTAB does not map into a PT_LOAD segment for the full DT_STRSZ range.");
  return null;
};

export const elfRuntimeStringsForSectionSymbols = (
  image: DynamicDescription, entries: ElfDynamicEntry[], symbolOffset: number
): { offset: number; size: number } | null => {
  if (!findElfDynamicSegment(image.programHeaders)) return null;
  const address = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.SYMTAB);
  if (address === null) return null;
  if (address !== undefined &&
    elfVirtualRange(image.programHeaders, address, 1n, image.file.size)?.offset !== symbolOffset) return null;
  return elfDynamicStringRange(image, entries);
};

// gABI 8.2/8.3: the loader reads the dynamic records at p_vaddr. Use only
// the bytes observed through DT_NULL, since PT_DYNAMIC can include padding.
// https://gabi.xinuos.com/elf/08-dynamic.html
const checkDynamicMapping = (
  image: DynamicDescription, segment: ElfProgramHeader, size: bigint, issues: string[]
): void => {
  const label = `PT_DYNAMIC #${segment.index}`;
  if (segment.memsz < size) issues.push(`${label}: p_memsz does not contain all of the dynamic table.`);
  const loads = image.programHeaders.filter(header => header.type === ELF_SEGMENT_TYPE.LOAD);
  if (!elfLoadMappingCovers(loads, segment.offset, segment.vaddr, size)) {
    issues.push(`${label}: the dynamic table lacks file-backed PT_LOAD coverage at p_vaddr.`);
  }
};

// gABI 8.3 Table 8.1. The symbol reader validates DT_SYMENT before choosing a source.
const checkRequiredTableTags = (table: ElfDynamicTable, issues: string[]): void => {
  if (!table.terminated) return;
  for (const tag of [ELF_DYNAMIC_TAG.STRTAB, ELF_DYNAMIC_TAG.STRSZ, ELF_DYNAMIC_TAG.SYMTAB]) {
    if (!table.entries.some(entry => entry.tag === tag)) {
      issues.push(`ELF dynamic table is missing required ${ELF_DYNAMIC_TAG_DESCRIPTIONS[tag]![0]}.`);
    }
  }
};

// gABI 7.5 and 8.3: PT_DYNAMIC points to SHT_DYNAMIC and contains its records.
// It can contain padding, so limit the reported disagreement to missing coverage.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
const checkDynamicSegment = (
  segment: ElfProgramHeader, section: ElfSectionHeader, table: ElfDynamicTable,
  size: bigint, issues: string[]
): void => {
  if (segment.offset !== section.offset) {
    issues.push(`PT_DYNAMIC #${segment.index} p_offset disagrees with SHT_DYNAMIC #${section.index} sh_offset.`);
    return;
  }
  if ((section.flags & ELF_SECTION_FLAG.ALLOC) && segment.vaddr !== section.addr) {
    issues.push(`PT_DYNAMIC #${segment.index} p_vaddr disagrees with SHT_DYNAMIC #${section.index} sh_addr.`);
  }
  if (segment.filesz < section.size) {
    issues.push(`PT_DYNAMIC #${segment.index} p_filesz does not contain all of SHT_DYNAMIC #${section.index}.`);
  }
  if ((section.flags & ELF_SECTION_FLAG.ALLOC) && segment.memsz >= size && segment.memsz < section.size) {
    issues.push(`PT_DYNAMIC #${segment.index} p_memsz does not contain all of SHT_DYNAMIC #${section.index}.`);
  }
  if (table.terminated && size > section.size) {
    issues.push(`PT_DYNAMIC #${segment.index} reaches DT_NULL beyond SHT_DYNAMIC #${section.index} sh_size.`);
  }
};

const checkStringSection = (
  image: DynamicDescription, entries: ElfDynamicEntry[], section: ElfSectionHeader,
  issues: string[]
): void => {
  const address = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.STRTAB);
  const size = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.STRSZ);
  if (address != null && (section.flags & ELF_SECTION_FLAG.ALLOC) && section.addr !== address) {
    issues.push(`DT_STRTAB disagrees with the linked string section #${section.index} sh_addr.`);
  }
  if (size != null && size !== section.size) {
    issues.push(`DT_STRSZ (${size} bytes) disagrees with linked string section #${section.index} sh_size (${section.size} bytes).`);
  }
  const range = elfDynamicStringRange(image, entries);
  if (range && BigInt(range.offset) !== section.offset) {
    issues.push(`DT_STRTAB maps to a different file offset than linked string section #${section.index}.`);
  }
};

const checkSymbolSection = (
  image: DynamicDescription, entries: ElfDynamicEntry[], section: ElfSectionHeader,
  issues: string[]
): void => {
  const address = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.SYMTAB);
  if (address == null) return;
  const range = elfVirtualRange(image.programHeaders, address, 1n, image.file.size);
  if ((range && BigInt(range.offset) !== section.offset) ||
    ((section.flags & ELF_SECTION_FLAG.ALLOC) && address !== section.addr)) {
    issues.push(`DT_SYMTAB disagrees with the location of SHT_DYNSYM #${section.index}.`);
    return;
  }
  if (!range) {
    issues.push("DT_SYMTAB is outside a file-backed PT_LOAD range.");
    return;
  }
  const size = elfSingleDynamicTag(entries, ELF_DYNAMIC_TAG.SYMTABSZ);
  if (size != null && size !== section.size && !(section.flags & ELF_SECTION_COMPRESSED)) {
    issues.push(`DT_SYMTABSZ (${size} bytes) disagrees with SHT_DYNSYM #${section.index} sh_size (${section.size} bytes).`);
  }
};

export const validateElfDynamicConsistency = (
  image: DynamicDescription, table: ElfDynamicTable
): string[] => {
  const segment = findElfDynamicSegment(image.programHeaders);
  if (!segment) return [];
  const issues: string[] = [];
  const size = BigInt(table.entries.length + Number(table.terminated)) * (image.is64 ? 16n : 8n);
  checkDynamicMapping(image, segment, size, issues);
  checkRequiredTableTags(table, issues);
  const dynamic = image.sections.find(section => section.type === ELF_SECTION_TYPE.DYNAMIC);
  if (dynamic) checkDynamicSegment(segment, dynamic, table, size, issues);
  const dynsym = image.sections.find(section => section.type === ELF_SECTION_TYPE.DYNSYM);
  if (dynsym) checkSymbolSection(image, table.entries, dynsym, issues);
  const links = new Set([dynamic?.offset === segment.offset ? dynamic.link : undefined, dynsym?.link]);
  for (const section of image.sections) {
    if (section.type === ELF_SECTION_TYPE.STRTAB && links.has(section.index)) {
      checkStringSection(image, table.entries, section, issues);
    }
  }
  return issues;
};
