"use strict";

import { createFileRangeReader } from "../file-range-reader.js";
import { createElfStringTableReader } from "./string-table.js";
import { elfFileRange } from "./relocation-reader.js";
import { locateElfHeaderTable } from "./header-table-range.js";
import {
  PROGRAM_FLAGS,
  PROGRAM_TYPES,
  SECTION_FLAGS,
  SECTION_TYPES,
  decodeFlags,
  decodeOption
} from "./constants.js";
import type { ElfHeader, ElfProgramHeader, ElfSectionHeader } from "./types.js";
import { validateElfProgramHeaders } from "./program-header-validation.js";
import { validateElfSectionHeaders } from "./section-header-validation.js";

const bigFrom32 = (value: number): bigint => BigInt.asUintN(32, BigInt(value));

const toSafeNumber = (value: number | bigint, label: string, issues: string[]): number | null => {
  if (typeof value === "number") return value;
  const num = Number(value);
  if (!Number.isSafeInteger(num)) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};

async function sliceView(file: File, offset: number, length: number): Promise<DataView | null> {
  const end = offset + length;
  const bounded = end > file.size ? file.size : end;
  if (offset >= file.size || bounded <= offset) return null;
  const buffer = await file.slice(offset, bounded).arrayBuffer();
  return new DataView(buffer);
}

function parseProgramHeader64(view: DataView, littleEndian: boolean): Omit<ElfProgramHeader, "index"> {
  const u32 = (offset: number): number => view.getUint32(offset, littleEndian);
  const u64 = (offset: number): bigint => view.getBigUint64(offset, littleEndian);
  const type = u32(0);
  const flags = u32(4);
  return {
    type,
    typeName: decodeOption(type, PROGRAM_TYPES) || null,
    offset: u64(8),
    vaddr: u64(16),
    paddr: u64(24),
    filesz: u64(32),
    memsz: u64(40),
    flags,
    flagNames: decodeFlags(flags, PROGRAM_FLAGS),
    align: u64(48)
  };
}

function parseProgramHeader32(view: DataView, littleEndian: boolean): Omit<ElfProgramHeader, "index"> {
  const u32 = (offset: number): number => view.getUint32(offset, littleEndian);
  const type = u32(0);
  const offset = bigFrom32(u32(4));
  const vaddr = bigFrom32(u32(8));
  const paddr = bigFrom32(u32(12));
  const filesz = bigFrom32(u32(16));
  const memsz = bigFrom32(u32(20));
  const flags = u32(24);
  return {
    type,
    typeName: decodeOption(type, PROGRAM_TYPES) || null,
    offset,
    vaddr,
    paddr,
    filesz,
    memsz,
    flags,
    flagNames: decodeFlags(flags, PROGRAM_FLAGS),
    align: bigFrom32(u32(28))
  };
}

function parseSectionHeader64(view: DataView, littleEndian: boolean): Omit<ElfSectionHeader, "index" | "name"> {
  const u32 = (offset: number): number => view.getUint32(offset, littleEndian);
  const u64 = (offset: number): bigint => view.getBigUint64(offset, littleEndian);
  const nameOff = u32(0);
  const type = u32(4);
  const flags = u64(8);
  return {
    nameOff,
    type,
    typeName: decodeOption(type, SECTION_TYPES) || null,
    flags,
    flagNames: decodeFlags(Number(flags & 0xffffffffn), SECTION_FLAGS),
    addr: u64(16),
    offset: u64(24),
    size: u64(32),
    link: u32(40),
    info: u32(44),
    addralign: u64(48),
    entsize: u64(56)
  };
}

function parseSectionHeader32(view: DataView, littleEndian: boolean): Omit<ElfSectionHeader, "index" | "name"> {
  const u32 = (offset: number): number => view.getUint32(offset, littleEndian);
  const nameOff = u32(0);
  const type = u32(4);
  const flags = bigFrom32(u32(8));
  return {
    nameOff,
    type,
    typeName: decodeOption(type, SECTION_TYPES) || null,
    flags,
    flagNames: decodeFlags(Number(flags), SECTION_FLAGS),
    addr: bigFrom32(u32(12)),
    offset: bigFrom32(u32(16)),
    size: bigFrom32(u32(20)),
    link: u32(24),
    info: u32(28),
    addralign: bigFrom32(u32(32)),
    entsize: bigFrom32(u32(36))
  };
}

function locateSectionNameTable(
  file: File,
  sections: ElfSectionHeader[],
  header: ElfHeader,
  issues: string[]
): { offset: number; size: number } | null {
  // gABI 2: SHN_UNDEF means that the file has no section name table.
  // https://gabi.xinuos.com/elf/02-eheader.html
  if (header.shstrndx === 0) return null;
  const shstr = sections[header.shstrndx];
  if (!shstr) {
    issues.push("Section name table header is missing.");
    return null;
  }
  if (shstr.type !== 3) { // SHT_STRTAB, gABI 3.
    issues.push("Section name table must have type SHT_STRTAB.");
    return null;
  }
  const range = elfFileRange(shstr.offset, shstr.size, file.size);
  if (!range) issues.push("Section name table is truncated or falls outside the file.");
  return range;
}

const readSectionZero = async (
  file: File, header: ElfHeader, expectedSize: number, issues: string[]
): Promise<DataView | null> => {
  const tableOffset = toSafeNumber(header.shoff, "Section header offset", issues);
  if (tableOffset == null) return null;
  const view = await sliceView(file, tableOffset, expectedSize);
  if (!view) {
    issues.push("Section header #0 falls outside the file; cannot resolve extended numbering.");
    return null;
  }
  if (view.byteLength < expectedSize) {
    issues.push("Section header #0 is truncated; cannot resolve extended numbering.");
    return null;
  }
  return view;
};

export async function resolveExtendedHeaderCounts(
  file: File,
  header: ElfHeader,
  is64: boolean,
  littleEndian: boolean,
  issues: string[],
  expectedSectionHeaderSize: number
): Promise<ElfHeader> {
  // gABI 2: e_shnum uses zero, not SHN_XINDEX, for extended numbering.
  // https://gabi.xinuos.com/elf/02-eheader.html
  if (header.shnum >= 0xff00) {
    issues.push("ELF e_shnum uses a reserved value; extended counts require e_shnum=0.");
    return { ...header, shnum: 0 };
  }
  // ELF extended-numbering sentinels: PN_XNUM/SHN_XINDEX=0xffff, SHN_UNDEF=0.
  const needsPhnum = header.phnum === 0xffff;
  const needsShnum = header.shnum === 0 && header.shoff !== 0n;
  const needsShstrndx = header.shstrndx === 0xffff;
  if (!needsPhnum && !needsShnum && !needsShstrndx) return header;
  const unresolvedHeader = (): ElfHeader => ({
    ...header,
    phnum: needsPhnum ? 0 : header.phnum,
    shnum: needsShnum ? 0 : header.shnum,
    shstrndx: needsShstrndx ? 0 : header.shstrndx
  });
  if (header.shoff === 0n) {
    issues.push("ELF extended numbering requires section header #0, but the section header table is missing.");
    return unresolvedHeader();
  }
  if (header.shentsize < expectedSectionHeaderSize) {
    issues.push(
      `Section header entry size (${header.shentsize}) is smaller than ELF${is64 ? "64" : "32"} minimum (${expectedSectionHeaderSize}); cannot resolve extended numbering.`
    );
    return unresolvedHeader();
  }
  const dv = await readSectionZero(file, header, expectedSectionHeaderSize, issues);
  if (!dv) return unresolvedHeader();
  const sectionZero = is64 ? parseSectionHeader64(dv, littleEndian) : parseSectionHeader32(dv, littleEndian);
  const resolvedShnum = needsShnum
    ? (toSafeNumber(sectionZero.size, "Section count from section header #0", issues) ?? 0)
    : header.shnum;
  return {
    ...header,
    phnum: needsPhnum ? sectionZero.info : header.phnum,
    shnum: resolvedShnum,
    shstrndx: needsShstrndx ? sectionZero.link : header.shstrndx
  };
}

export async function parseProgramHeadersWithGuards(
  file: File,
  header: ElfHeader,
  is64: boolean,
  littleEndian: boolean,
  issues: string[]
): Promise<ElfProgramHeader[]> {
  // ELF program header size from spec: sizeof(Elf32_Phdr)=0x20, sizeof(Elf64_Phdr)=0x38.
  const expectedProgramHeaderSize = is64 ? 0x38 : 0x20;
  const table = locateElfHeaderTable(file.size, header.phoff, header.phnum,
    header.phentsize, expectedProgramHeaderSize, "Program header", issues);
  if (!table) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const entries: ElfProgramHeader[] = [];
  for (let index = 0; index < table.count; index += 1) {
    const view = await reader.read(table.offset + index * header.phentsize, expectedProgramHeaderSize);
    if (view.byteLength < expectedProgramHeaderSize) {
      issues.push(`Program header #${index} is truncated.`);
      break;
    }
    const parsed = is64 ? parseProgramHeader64(view, littleEndian) : parseProgramHeader32(view, littleEndian);
    entries.push({ ...parsed, index });
  }
  validateElfProgramHeaders(entries, file.size, issues);
  return entries;
}

export async function parseSectionHeadersWithNames(
  file: File,
  header: ElfHeader,
  is64: boolean,
  littleEndian: boolean,
  issues: string[],
  expectedSectionHeaderSize: number
): Promise<ElfSectionHeader[]> {
  const table = locateElfHeaderTable(file.size, header.shoff, header.shnum,
    header.shentsize, expectedSectionHeaderSize, "Section header", issues);
  if (!table) return [];
  const reader = createFileRangeReader(file, 0, file.size);
  const sections: ElfSectionHeader[] = [];
  for (let index = 0; index < table.count; index += 1) {
    const view = await reader.read(table.offset + index * header.shentsize, expectedSectionHeaderSize);
    if (view.byteLength < expectedSectionHeaderSize) {
      issues.push(`Section header #${index} is truncated.`);
      break;
    }
    const parsed = is64 ? parseSectionHeader64(view, littleEndian) : parseSectionHeader32(view, littleEndian);
    sections.push({ ...parsed, index });
  }
  validateElfSectionHeaders(sections, file.size, issues);
  const namesTable = locateSectionNameTable(file, sections, header, issues);
  if (namesTable) {
    const readName = createElfStringTableReader(reader, namesTable, issues);
    for (const section of sections) section.name = await readName(section.nameOff) ?? "";
  }
  return sections;
}
