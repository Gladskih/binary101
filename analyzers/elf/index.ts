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
import { analyzeElfDwarf } from "./dwarf.js";
import { parseElfDynamicInfo } from "./dynamic-info.js";
import { parseElfDynamicSymbols } from "./dynamic-symbols.js";
import { parseElfSymbolVersions } from "./symbol-versions.js";
import { parseElfSymbolTables } from "./symbol-tables.js";
import { parseElfSectionGroups } from "./section-groups.js";
import { parseElfUnwind } from "./unwind.js";
import { parseElfHashTables } from "./hash-tables.js";
import { parseElfAttributes } from "./attributes.js";
import { validateElfHashSymbols } from "./hash-symbols.js";
import { parseElfInterpreter } from "./interpreter.js";
import { parseElfNotes } from "./notes.js";
import { analyzeElfNativeAot } from "./native-aot.js";
import { parseElfTlsInfo } from "./tls.js";
import { parseElfRelocations } from "./relocations.js";
import { readElfDynamicEntries } from "./dynamic-entries.js";
import { createFileRangeReader } from "../file-range-reader.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { selectElfBinaryLayout } from "./binary-layout.js";
import type { ElfFileHeaderRecord } from "./binary-layout-types.js";
import {
  parseProgramHeadersWithGuards,
  parseSectionHeadersWithNames,
  resolveExtendedHeaderCounts
} from "./header-tables.js";
import type { ElfHeader, ElfIdent, ElfParseResult, ElfProgramHeader, ElfSectionHeader } from "./types.js";
const ELF_MAGIC = 0x7f454c46;
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
  // gABI 2.2: only ELFCLASS32/64 and ELFDATA2LSB/MSB define supported layouts.
  // https://gabi.xinuos.com/elf/02-eheader.html
  if (cls !== 1 && cls !== 2) issues.push(`Unsupported ELF class ${cls}; layout is unknown.`);
  if (data !== 1 && data !== 2) {
    issues.push(`Unsupported ELF data encoding ${data}; byte order is unknown.`);
  }
  if (version !== 1) issues.push(`Unexpected ELF version ${version}.`);
  return { classByte: cls, className, dataByte: data, dataName, osabi, abiVersion };
}
function describeElfHeader(record: ElfFileHeaderRecord, issues: string[]): ElfHeader {
  const { version, ...header } = record;
  if (version !== 1) issues.push(`Unexpected ELF header version ${version}.`);
  return {
    ...header,
    typeName: decodeOption(header.type, ELF_TYPE) || null,
    machineName: decodeOption(header.machine, ELF_MACHINE) || null
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
  if ((ident.classByte !== 1 && ident.classByte !== 2) ||
      (ident.dataByte !== 1 && ident.dataByte !== 2)) {
    return buildResult(emptyElfHeader(), [], []);
  }
  const layout = selectElfBinaryLayout({ is64, littleEndian: little });
  const minHeaderSize = layout.headerSize;
  const expectedSectionHeaderSize = layout.sectionHeaderSize;
  const headerRecord = layout.readHeader(dv);
  if (!headerRecord) {
    issues.push(`ELF${is64 ? "64" : "32"} header is truncated: expected at least ${minHeaderSize} bytes, got ${dv.byteLength}.`);
    return buildResult(emptyElfHeader(), [], []);
  }
  const parsedHeader = describeElfHeader(headerRecord, issues);
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
  const result = buildResult(header, programHeaders, sections);
  const attributes = await parseElfAttributes(file, result);
  if (attributes.length) result.attributes = attributes;
  const dynamicIssues: string[] = [];
  const dynamicEntries = await readElfDynamicEntries(
    createFileRangeReader(file, 0, file.size), result, dynamicIssues, layout);
  const symbolCache = new Map<number, ElfRelocationSymbol>();
  const hashes = await parseElfHashTables(file, result, dynamicEntries);
  if (hashes.length) result.hashTables = hashes;
  const [interpreter, dynamic, dynSymbols, notes, comment, debugLink, dwarf] =
    await Promise.all([
      parseElfInterpreter(file, programHeaders),
      parseElfDynamicInfo({ file, programHeaders, sections, is64, littleEndian: little }, dynamicEntries),
      parseElfDynamicSymbols({ file, programHeaders, sections, is64, littleEndian: little },
        dynamicEntries, symbolCache, layout, hashes),
      parseElfNotes({ file, programHeaders, sections, is64, littleEndian: little,
        ...(header.type === 4 ? { coreMachine: header.machine } : {}) }),
      parseElfComment(file, sections),
      parseElfDebugLink(file, sections, little),
      analyzeElfDwarf(file, sections, is64 ? "elf64" : "elf32", little, issues)
    ]);
  validateElfHashSymbols(hashes, dynSymbols, is64 ? 64 : 32);
  const symbolTables = await parseElfSymbolTables(file, result, symbolCache);
  if (symbolTables.length) result.symbolTables = symbolTables;
  const sectionGroups = await parseElfSectionGroups(file, result);
  if (sectionGroups.length) result.sectionGroups = sectionGroups;
  const unwind = await parseElfUnwind(file, result);
  if (unwind.length) result.unwind = unwind;
  const relocations = await parseElfRelocations(file, result, dynamicEntries, symbolCache, layout);
  const symbolVersions = await parseElfSymbolVersions(file, result, dynamicEntries,
    dynSymbols?.total ?? 0);
  if (symbolVersions) result.symbolVersions = symbolVersions;
  if (relocations) relocations.issues.unshift(...dynamicIssues);
  else issues.push(...dynamicIssues);
  const nativeAot = dynamicIssues.length ? null : await analyzeElfNativeAot(
    file, result, issues, relocations, layout);
  if (relocations) result.relocations = relocations;
  if (interpreter) result.interpreter = interpreter;
  if (dynamic) result.dynamic = dynamic;
  if (dynSymbols) result.dynSymbols = dynSymbols;
  if (tls) result.tls = tls;
  if (notes) result.notes = notes;
  if (comment) result.comment = comment;
  if (debugLink) result.debugLink = debugLink;
  if (dwarf) result.dwarf = dwarf;
  if (nativeAot) result.nativeAot = nativeAot;
  return result;
}
