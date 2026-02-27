"use strict";
import {
  ELF_CLASS,
  ELF_DATA,
  ELF_TYPE,
  ELF_MACHINE,
  decodeOption
} from "./constants.js";
import { parseElfComment } from "./comment.js";
import { parseElfDebugLink } from "./debug-link.js";
import { parseElfDynamicInfo } from "./dynamic-info.js";
import { parseElfDynamicSymbols } from "./dynamic-symbols.js";
import { parseElfInterpreter } from "./interpreter.js";
import { parseElfNotes } from "./notes.js";
import { parseElfTlsInfo } from "./tls.js";
import {
  parseProgramHeadersWithGuards,
  parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts
} from "./header-tables.js";
import type { ElfHeader, ElfIdent, ElfParseResult, ElfProgramHeader, ElfSectionHeader } from "./types.js";
const ELF_MAGIC = 0x7f454c46;
const bigFrom32 = (value: number): bigint => BigInt.asUintN(32, BigInt(value));
const emptyElfHeader = (): ElfHeader => ({
  type: 0,
  typeName: null,
  machine: 0,
  machineName: null,
  entry: 0n,
  phoff: 0n,
  shoff: 0n,
  flags: 0,
  ehsize: 0,
  phentsize: 0,
  phnum: 0,
  shentsize: 0,
  shnum: 0,
  shstrndx: 0
});
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
export async function parseElf(file: File): Promise<ElfParseResult | null> {
  const buffer = await file.slice(0, Math.min(file.size, 4096)).arrayBuffer();
  const dv = new DataView(buffer);
  // Minimum ELF header for ident + base fields: sizeof(Elf32_Ehdr) = 0x34.
  if (dv.byteLength < 0x34 || dv.getUint32(0, false) !== ELF_MAGIC) return null;
  const issues: string[] = [];
  const ident = parseIdent(dv, issues);
  const is64 = ident.classByte === 2;
  const little = ident.dataByte === 1;
  const buildResult = (
    header: ElfHeader,
    programHeaders: ElfProgramHeader[],
    sections: ElfSectionHeader[]
  ): ElfParseResult => ({
    ident,
    header,
    programHeaders,
    sections,
    issues,
    is64,
    littleEndian: little,
    fileSize: file.size
  });
  // ELF header size from spec: sizeof(Elf32_Ehdr)=0x34, sizeof(Elf64_Ehdr)=0x40.
  const minHeaderSize = is64 ? 0x40 : 0x34;
  // ELF section header size from spec: sizeof(Elf32_Shdr)=0x28, sizeof(Elf64_Shdr)=0x40.
  const expectedSectionHeaderSize = is64 ? 0x40 : 0x28;
  if (dv.byteLength < minHeaderSize) {
    issues.push(`ELF${is64 ? "64" : "32"} header is truncated: expected at least ${minHeaderSize} bytes, got ${dv.byteLength}.`);
    return buildResult(emptyElfHeader(), [], []);
  }
  const parsedHeader = parseElfHeader(dv, is64, little, issues);
  const header = await resolveExtendedHeaderCounts(file, parsedHeader, is64, little, issues, expectedSectionHeaderSize);
  if (header.ehsize < minHeaderSize) {
    issues.push(
      `ELF header size e_ehsize (${header.ehsize}) is smaller than ELF${is64 ? "64" : "32"} minimum (${minHeaderSize}).`
    );
    return buildResult(header, [], []);
  }
  if (header.ehsize > file.size) {
    issues.push(`ELF header size e_ehsize (${header.ehsize}) exceeds file size (${file.size}).`);
  }
  const programHeaders = await parseProgramHeadersWithGuards(file, header, is64, little, issues);
  const sections = await parseSectionHeadersWithNames(file, header, is64, little, issues, expectedSectionHeaderSize);
  const tls = parseElfTlsInfo(programHeaders, sections);
  const [interpreter, dynamic, dynSymbols, notes, comment, debugLink] = await Promise.all([
    parseElfInterpreter(file, programHeaders),
    parseElfDynamicInfo({ file, programHeaders, sections, is64, littleEndian: little }),
    parseElfDynamicSymbols({ file, programHeaders, sections, is64, littleEndian: little }),
    parseElfNotes({ file, programHeaders, sections, littleEndian: little }),
    parseElfComment(file, sections),
    parseElfDebugLink(file, sections, little)
  ]);
  const result = buildResult(header, programHeaders, sections);
  if (interpreter) result.interpreter = interpreter;
  if (dynamic) result.dynamic = dynamic;
  if (dynSymbols) result.dynSymbols = dynSymbols;
  if (tls) result.tls = tls;
  if (notes) result.notes = notes;
  if (comment) result.comment = comment;
  if (debugLink) result.debugLink = debugLink;
  return result;
}
