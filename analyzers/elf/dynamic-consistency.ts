import type { ElfDynamicEntry, ElfDynamicTable } from "./dynamic-entries.js";
import type { ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { elfVirtualRange } from "./relocation-reader.js";
import { ELF_DYNAMIC_TAG, ELF_SECTION_FLAG, ELF_SECTION_TYPE, ELF_SEGMENT_TYPE } from "./abi-constants.js";
import { hasCompressedSectionAt } from "./section-data.js";

type DynamicDescription = {
  file: File; is64: boolean; programHeaders: ElfProgramHeader[]; sections: ElfSectionHeader[];
};

const tagValue = (entries: ElfDynamicEntry[], tag: number): bigint | null | undefined => {
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
  const address = tagValue(entries, ELF_DYNAMIC_TAG.STRTAB);
  const size = tagValue(entries, ELF_DYNAMIC_TAG.STRSZ);
  if (address === null || size === null) {
    issues?.push("Conflicting DT_STRTAB or DT_STRSZ values.");
    return null;
  }
  if (address === undefined) return null;
  const range = size === undefined ? null :
    elfVirtualRange(image.programHeaders, address, size, image.file.size);
  if (range && !hasCompressedSectionAt(image.sections, ELF_SECTION_TYPE.STRTAB, range.offset)) return range;
  issues?.push(range ? "DT_STRTAB points into a compressed string table." :
    "DT_STRTAB does not map into a PT_LOAD segment for the full DT_STRSZ range.");
  return null;
};

export const elfRuntimeStringsForSectionSymbols = (
  image: DynamicDescription, entries: ElfDynamicEntry[], symbolOffset: number
): { offset: number; size: number } | null => {
  if (!image.programHeaders.some(header => header.type === ELF_SEGMENT_TYPE.DYNAMIC)) return null;
  const address = tagValue(entries, ELF_DYNAMIC_TAG.SYMTAB);
  if (address === null) return null;
  if (address !== undefined &&
    elfVirtualRange(image.programHeaders, address, 1n, image.file.size)?.offset !== symbolOffset) return null;
  return elfDynamicStringRange(image, entries);
};

// gABI 7.5 and 8.3: PT_DYNAMIC points to SHT_DYNAMIC and contains its records.
// It can contain padding, so limit the reported disagreement to missing coverage.
// https://gabi.xinuos.com/elf/08-dynamic.html#dynamic-section
const checkDynamicSegment = (
  segment: ElfProgramHeader, section: ElfSectionHeader, table: ElfDynamicTable,
  stride: number, issues: string[]
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
  if ((section.flags & ELF_SECTION_FLAG.ALLOC) && segment.memsz < section.size) {
    issues.push(`PT_DYNAMIC #${segment.index} p_memsz does not contain all of SHT_DYNAMIC #${section.index}.`);
  }
  if (table.terminated && (BigInt(table.entries.length) + 1n) * BigInt(stride) > section.size) {
    issues.push(`PT_DYNAMIC #${segment.index} reaches DT_NULL beyond SHT_DYNAMIC #${section.index} sh_size.`);
  }
};

const checkStringSection = (
  image: DynamicDescription, entries: ElfDynamicEntry[], section: ElfSectionHeader,
  issues: string[]
): void => {
  const address = tagValue(entries, ELF_DYNAMIC_TAG.STRTAB);
  const size = tagValue(entries, ELF_DYNAMIC_TAG.STRSZ);
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
  const address = tagValue(entries, ELF_DYNAMIC_TAG.SYMTAB);
  if (address == null) return;
  const range = elfVirtualRange(image.programHeaders, address, 1n, image.file.size);
  if ((range && BigInt(range.offset) !== section.offset) ||
    ((section.flags & ELF_SECTION_FLAG.ALLOC) && address !== section.addr)) {
    issues.push(`DT_SYMTAB disagrees with the location of SHT_DYNSYM #${section.index}.`);
  }
};

export const validateElfDynamicConsistency = (
  image: DynamicDescription, table: ElfDynamicTable
): string[] => {
  const segment = image.programHeaders.find(header => header.type === ELF_SEGMENT_TYPE.DYNAMIC);
  if (!segment) return [];
  const issues: string[] = [];
  const dynamic = image.sections.find(section => section.type === ELF_SECTION_TYPE.DYNAMIC);
  if (dynamic) checkDynamicSegment(segment, dynamic, table, image.is64 ? 16 : 8, issues);
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
