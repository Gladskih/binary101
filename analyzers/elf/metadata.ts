import type { ElfParseResult } from "./types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { createFileRangeReader } from "../file-range-reader.js";
import { readElfDynamicEntries, type ElfDynamicEntry } from "./dynamic-entries.js";
import { parseElfDynamicInfo } from "./dynamic-info.js";
import { parseElfDynamicSymbols } from "./dynamic-symbols.js";
import { parseElfHashTables } from "./hash-tables.js";
import { validateElfHashSymbols } from "./hash-symbols.js";
import { parseElfSymbolTables } from "./symbol-tables.js";
import { parseElfSymbolVersions } from "./symbol-versions.js";
import { parseElfSectionGroups } from "./section-groups.js";
import { parseElfRelocations } from "./relocations.js";
import { analyzeElfNativeAot } from "./native-aot.js";
import { parseElfInterpreter } from "./interpreter.js";
import { parseElfNotes } from "./notes.js";
import { parseElfComment } from "./comment.js";
import { parseElfDebugLink } from "./debug-link.js";
import { analyzeElfDwarf } from "./dwarf.js";
import { parseElfAttributes } from "./attributes.js";
import { parseElfMips } from "./mips.js";
import { parseElfTlsInfo } from "./tls.js";
import { parseElfUnwind } from "./unwind.js";
import { parseElfLsda } from "./lsda.js";
import { parseElfArmEhabi } from "./arm-ehabi.js";

const retainMetadata = <Key extends keyof ElfParseResult>(result: ElfParseResult,
  key: Key, value: ElfParseResult[Key] | null): void => {
  if (value == null || (Array.isArray(value) && !value.length)) return;
  result[key] = value;
};

const parseLinkingTables = async (file: File, result: ElfParseResult, entries: ElfDynamicEntry[],
  cache: Map<number, ElfRelocationSymbol>, layout: ElfBinaryLayout): Promise<void> => {
  retainMetadata(result, "symbolTables", await parseElfSymbolTables(file, result, cache));
  retainMetadata(result, "sectionGroups", await parseElfSectionGroups(file, result));
  retainMetadata(result, "relocations", await parseElfRelocations(file, result, entries, cache, layout));
  retainMetadata(result, "symbolVersions", await parseElfSymbolVersions(file, result, entries,
    result.dynSymbols?.total ?? 0));
};

const parseLinkingMetadata = async (file: File, result: ElfParseResult, layout: ElfBinaryLayout): Promise<void> => {
  const issues: string[] = [];
  const entries = await readElfDynamicEntries(createFileRangeReader(file, 0, file.size), result, issues, layout);
  const cache = new Map<number, ElfRelocationSymbol>();
  const hashes = await parseElfHashTables(file, result, entries);
  retainMetadata(result, "hashTables", hashes);
  const [dynamic, symbols] = await Promise.all([
    parseElfDynamicInfo({ file, ...result }, entries),
    parseElfDynamicSymbols({ file, ...result }, entries, cache, layout, hashes)
  ]);
  retainMetadata(result, "dynamic", dynamic);
  retainMetadata(result, "dynSymbols", symbols);
  validateElfHashSymbols(hashes, symbols, result.is64 ? 64 : 32);
  await parseLinkingTables(file, result, entries, cache, layout);
  if (result.relocations) result.relocations.issues.unshift(...issues);
  else result.issues.push(...issues);
  if (!issues.length) retainMetadata(result, "nativeAot", await analyzeElfNativeAot(
    file, result, result.issues, result.relocations ?? null, layout));
};

const parseAuxiliaryMetadata = async (file: File, result: ElfParseResult): Promise<void> => {
  const [interpreter, notes, comment, debugLink, dwarf] = await Promise.all([
    parseElfInterpreter(file, result.programHeaders),
    parseElfNotes({ file, ...result, ...(result.header.type === 4 ? { coreMachine: result.header.machine } : {}) }),
    parseElfComment(file, result.sections),
    parseElfDebugLink(file, result.sections, result.littleEndian),
    analyzeElfDwarf(file, result.sections, result.is64 ? "elf64" : "elf32", result.littleEndian, result.issues)
  ]);
  retainMetadata(result, "interpreter", interpreter);
  retainMetadata(result, "notes", notes);
  retainMetadata(result, "comment", comment);
  retainMetadata(result, "debugLink", debugLink);
  retainMetadata(result, "dwarf", dwarf);
};

const parseArchitectureMetadata = async (file: File, result: ElfParseResult): Promise<void> => {
  retainMetadata(result, "tls", parseElfTlsInfo(result.programHeaders, result.sections));
  retainMetadata(result, "attributes", await parseElfAttributes(file, result));
  retainMetadata(result, "mips", await parseElfMips(file, result));
  retainMetadata(result, "unwind", await parseElfUnwind(file, result));
  retainMetadata(result, "lsdas", await parseElfLsda(file, result));
  retainMetadata(result, "armEhabi", await parseElfArmEhabi(file, result));
};

export const parseElfMetadata = async (file: File, result: ElfParseResult,
  layout: ElfBinaryLayout): Promise<void> => {
  await Promise.all([parseLinkingMetadata(file, result, layout), parseAuxiliaryMetadata(file, result),
    parseArchitectureMetadata(file, result)]);
};
