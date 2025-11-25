"use strict";
import { readAsciiString } from "../../binary-utils.js";
import {
  ELF_CLASS,
  ELF_DATA,
  ELF_TYPE,
  ELF_MACHINE,
  PROGRAM_TYPES,
  SECTION_TYPES,
  SECTION_FLAGS,
  PROGRAM_FLAGS
} from "./constants.js";
import type {
  ElfHeader,
  ElfIdent,
  ElfOptionEntry,
  ElfParseResult,
  ElfProgramHeader,
  ElfSectionHeader
} from "./types.js";

const ELF_MAGIC = 0x7f454c46;
const decodeOption = (value: number, options: ElfOptionEntry[]): string | null =>
  options.find(entry => entry[0] === value)?.[1] || null;
const decodeFlags = (mask: number, flags: ElfOptionEntry[]): string[] =>
  flags
    .filter(([bit]) => (mask & bit) !== 0)
    .map(([, name]) => name);
const bigFrom32 = (value: number): bigint => BigInt(value >>> 0);
const toSafeNumber = (value: number | bigint, label: string, issues: string[]): number | null => {
  if (typeof value === "number") return value;
  const num = Number(value);
  if (!Number.isSafeInteger(num)) {
    issues.push(`${label} (${value.toString()}) is too large to index into the file.`);
    return null;
  }
  return num;
};
async function sliceView(
  file: File,
  offset: number,
  length: number
): Promise<{ dv: DataView | null; truncated: boolean }> {
  const end = offset + length;
  const bounded = end > file.size ? file.size : end;
  if (offset >= file.size || bounded <= offset) return { dv: null, truncated: true };
  const buffer = await file.slice(offset, bounded).arrayBuffer();
  const truncated = buffer.byteLength !== length;
  return { dv: new DataView(buffer), truncated };
}
function parseIdent(dv: DataView, issues: string[]): ElfIdent {
  const cls = dv.getUint8(4);
  const data = dv.getUint8(5);
  const version = dv.getUint8(6);
  const osabi = dv.getUint8(7);
  const abiVersion = dv.getUint8(8);
  const className = decodeOption(cls, ELF_CLASS) || "Unknown";
  const dataName = decodeOption(data, ELF_DATA) || "Unknown";
  if (version !== 1) issues.push(`Unexpected ELF version ${version}.`);
  return { classByte: cls, className, dataByte: data, dataName, osabi, abiVersion };
}

function parseElfHeader(dv: DataView, is64: boolean, little: boolean, issues: string[]): ElfHeader {
  const u16 = (offset: number): number => dv.getUint16(offset, little);
  const u32 = (offset: number): number => dv.getUint32(offset, little);
  const u64 = (offset: number): bigint => dv.getBigUint64(offset, little);
  const type = u16(0x10);
  const machine = u16(0x12);
  const version = u32(0x14);
  const entry = is64 ? u64(0x18) : bigFrom32(u32(0x18));
  const phoff = is64 ? u64(0x20) : bigFrom32(u32(0x1c));
  const shoff = is64 ? u64(0x28) : bigFrom32(u32(0x20));
  const flags = u32(is64 ? 0x30 : 0x24);
  const ehsize = u16(is64 ? 0x34 : 0x28);
  const phentsize = u16(is64 ? 0x36 : 0x2a);
  const phnum = u16(is64 ? 0x38 : 0x2c);
  const shentsize = u16(is64 ? 0x3a : 0x2e);
  const shnum = u16(is64 ? 0x3c : 0x30);
  const shstrndx = u16(is64 ? 0x3e : 0x32);
  if (version !== 1) issues.push(`Unexpected ELF header version ${version}.`);
  return {
    type,
    typeName: decodeOption(type, ELF_TYPE) || null,
    machine,
    machineName: decodeOption(machine, ELF_MACHINE) || null,
    entry,
    phoff,
    shoff,
    flags,
    ehsize,
    phentsize,
    phnum,
    shentsize,
    shnum,
    shstrndx
  };
}

function parseProgramHeader(
  view: DataView,
  is64: boolean,
  little: boolean
): Omit<ElfProgramHeader, "index"> {
  const u32 = (offset: number): number => view.getUint32(offset, little);
  const u64 = (offset: number): bigint => view.getBigUint64(offset, little);
  if (is64) {
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

function parseSectionHeader(
  view: DataView,
  is64: boolean,
  little: boolean
): Omit<ElfSectionHeader, "index" | "name"> {
  const u32 = (offset: number): number => view.getUint32(offset, little);
  const u64 = (offset: number): bigint => view.getBigUint64(offset, little);
  if (is64) {
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

async function parseProgramHeaders(
  file: File,
  header: ElfHeader,
  is64: boolean,
  little: boolean,
  issues: string[]
): Promise<ElfProgramHeader[]> {
  if (!header.phoff || !header.phnum) return [];
  const tableOffset = toSafeNumber(header.phoff, "Program header offset", issues);
  if (tableOffset == null) return [];
  const tableSize = header.phentsize * header.phnum;
  const { dv, truncated } = await sliceView(file, tableOffset, tableSize);
  if (!dv) {
    issues.push("Program header table falls outside the file.");
    return [];
  }
  if (truncated) issues.push("Program header table is truncated.");
  const entries: ElfProgramHeader[] = [];
  const usableCount = Math.min(header.phnum, Math.floor(dv.byteLength / header.phentsize));
  for (let index = 0; index < usableCount; index += 1) {
    const begin = index * header.phentsize;
    const view = new DataView(
      dv.buffer,
      begin,
      Math.min(header.phentsize, dv.byteLength - begin)
    );
    entries.push({ ...parseProgramHeader(view, is64, little), index });
  }
  return entries;
}
function readStringFromTable(tableDv: DataView | null, offset: number): string {
  if (!tableDv || offset >= tableDv.byteLength) return "";
  return readAsciiString(tableDv, offset, tableDv.byteLength - offset);
}

async function loadSectionNameTable(
  file: File,
  sections: ElfSectionHeader[],
  header: ElfHeader,
  issues: string[]
): Promise<DataView | null> {
  if (!sections.length || header.shstrndx >= sections.length) return null;
  const shstr = sections[header.shstrndx];
  if (!shstr) {
    issues.push("Section name table header is missing.");
    return null;
  }
  const off = toSafeNumber(shstr.offset, "Section name table offset", issues);
  const size = toSafeNumber(shstr.size, "Section name table size", issues);
  if (off == null || size == null) return null;
  const { dv, truncated } = await sliceView(file, off, size);
  if (!dv) {
    issues.push("Section name table falls outside the file.");
    return null;
  }
  if (truncated) issues.push("Section name table is truncated.");
  return dv;
}
async function parseSectionHeaders(
  file: File,
  header: ElfHeader,
  is64: boolean,
  little: boolean,
  issues: string[]
): Promise<ElfSectionHeader[]> {
  if (!header.shoff || !header.shnum) return [];
  const tableOffset = toSafeNumber(header.shoff, "Section header offset", issues);
  if (tableOffset == null) return [];
  const tableSize = header.shentsize * header.shnum;
  const { dv, truncated } = await sliceView(file, tableOffset, tableSize);
  if (!dv) {
    issues.push("Section header table falls outside the file.");
    return [];
  }
  if (truncated) issues.push("Section header table is truncated.");
  const sections: ElfSectionHeader[] = [];
  const usableCount = Math.min(header.shnum, Math.floor(dv.byteLength / header.shentsize));
  for (let index = 0; index < usableCount; index += 1) {
    const begin = index * header.shentsize;
    const view = new DataView(
      dv.buffer,
      begin,
      Math.min(header.shentsize, dv.byteLength - begin)
    );
    sections.push({ ...parseSectionHeader(view, is64, little), index });
  }
  const namesTable = await loadSectionNameTable(file, sections, header, issues);
  if (namesTable) {
    sections.forEach(section => {
      section.name = readStringFromTable(namesTable, section.nameOff);
    });
  }
  return sections;
}
export async function parseElf(file: File): Promise<ElfParseResult | null> {
  const buffer = await file.slice(0, Math.min(file.size, 4096)).arrayBuffer();
  const dv = new DataView(buffer);
  if (dv.byteLength < 0x34 || dv.getUint32(0, false) !== ELF_MAGIC) return null;
  const issues: string[] = [];
  const ident = parseIdent(dv, issues);
  const is64 = ident.classByte === 2;
  const little = ident.dataByte === 1;
  const header = parseElfHeader(dv, is64, little, issues);
  const programHeaders = await parseProgramHeaders(file, header, is64, little, issues);
  const sections = await parseSectionHeaders(file, header, is64, little, issues);
  return {
    ident,
    header,
    programHeaders,
    sections,
    issues,
    is64,
    littleEndian: little,
    fileSize: file.size
  };
}
