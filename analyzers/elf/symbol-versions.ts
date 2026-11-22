import { createFileRangeReader } from "../file-range-reader.js";
import type { FileRangeReader } from "../file-range-reader.js";
import type { ElfParseResult } from "./types.js";
import type { ElfDynamicEntry } from "./dynamic-entries.js";
import type { ElfSymbolVersions } from "./version-types.js";
import type { ElfVersionTable } from "./version-reader.js";
import { locateElfVersionTable, readVersionBytes } from "./version-reader.js";
import { readElfVersionDefinitions, readElfVersionRequirements } from "./version-records.js";

const readSymbolIndices = async (
  reader: FileRangeReader, table: ElfVersionTable, little: boolean, issues: string[]
): Promise<number[]> => {
  const symbols: number[] = [];
  // LSB 10.7.2: one Elf*_Half per dynamic symbol. Limit bounds output memory.
  const count = Math.min(table.count, Math.floor(table.size / 2));
  if (count !== table.count) {
    issues.push(`Symbol version table is truncated: decoded ${count} of ${table.count} entries.`);
  }
  if (table.size % 2) {
    issues.push("Symbol version table has a partial 2-byte entry.");
  }
  for (let index = 0; index < count; index += 1) {
    const view = await readVersionBytes(reader, table, index * 2, 2, issues);
    if (!view) break;
    symbols.push(view.getUint16(0, little));
  }
  return symbols;
};

const validateVersionReferences = (result: ElfSymbolVersions): void => {
  // The high bit is visibility. Indices 0 and 1 and the reserved range
  // starting at VER_NDX_LORESERVE have special meanings (glibc elf.h).
  // https://github.com/bminor/glibc/blob/master/elf/dl-version.c
  const known = new Set([0, 1]);
  for (const definition of result.definitions) {
    if (!(definition.flags & 1)) known.add(definition.index & 0x7fff); // VER_FLG_BASE
  }
  for (const requirement of result.requirements) {
    for (const version of requirement.versions) known.add(version.index & 0x7fff);
  }
  result.symbols.forEach((raw, symbol) => {
    const index = raw & 0x7fff;
    if (raw >= 0xff00 || known.has(index)) return;
    result.issues.push(`Dynamic symbol #${symbol} uses version index ${index} absent from VERDEF or VERNEED.`);
    known.add(index);
  });
};

export const parseElfSymbolVersions = async (
  file: File, elf: ElfParseResult, entries: ElfDynamicEntry[], symbolCount: number
): Promise<ElfSymbolVersions | null> => {
  const issues: string[] = [];
  const definitions = locateElfVersionTable(elf, entries, "definitions", symbolCount, issues);
  const requirements = locateElfVersionTable(elf, entries, "requirements", symbolCount, issues);
  const reader = createFileRangeReader(file, 0, file.size);
  const result: ElfSymbolVersions = {
    definitions: definitions
      ? await readElfVersionDefinitions(reader, definitions, elf.littleEndian, issues) : [],
    requirements: requirements
      ? await readElfVersionRequirements(reader, requirements, elf.littleEndian, issues) : [],
    symbols: [],
    issues
  };
  const readDynamic = elf.dynamic?.terminated ?? !(elf.programHeaders.some(header => header.type === 2) ||
    elf.sections.some(section => section.type === 6));
  const complete = !issues.length && readDynamic &&
    elf.sections.length >= elf.header.shnum;
  const symbols = locateElfVersionTable(elf, entries, "symbols", symbolCount, issues);
  if (!definitions && !requirements && !symbols && !issues.length) return null;
  if (symbols) result.symbols = await readSymbolIndices(reader, symbols, elf.littleEndian, issues);
  if (complete) validateVersionReferences(result);
  return result;
};
