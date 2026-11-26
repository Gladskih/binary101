import type { ElfParseResult } from "./types.js";
import type { ElfBinaryLayout } from "./binary-layout-types.js";
import type { ElfRelocationSymbol } from "./relocation-types.js";
import { createFileRangeReader } from "../file-range-reader.js";
import { readElfDynamicTable, type ElfDynamicTable } from "./dynamic-entries.js";
import { parseElfDynamicInfo } from "./dynamic-info.js";
import { parseElfDynamicSymbols } from "./dynamic-symbols.js";
import { parseElfHashTables } from "./hash-tables.js";
import { parseElfSymbolTables } from "./symbol-tables.js";
import { parseElfSymbolVersions } from "./symbol-versions.js";
import { parseElfSectionGroups } from "./section-groups.js";
import { parseElfRelocations } from "./relocations.js";
import { analyzeElfNativeAot } from "./native-aot.js";
import { parseElfInterpreter } from "./interpreter.js";
import { parseElfNotes } from "./notes.js";
import { parseElfComment } from "./comment.js";
import { parseElfDebugLink } from "./debug-link.js";
import { parseElfMiniDebugInfo } from "./mini-debug-info.js";
import { analyzeElfDwarf, prepareElfDwarfSources, elfDwarfLogicalSizes } from "./dwarf.js";
import { parseElfAttributes } from "./attributes.js";
import { parseElfMips } from "./mips.js";
import { parseElfTlsInfo } from "./tls.js";
import { parseElfUnwind } from "./unwind.js";
import { parseElfSFrame } from "./sframe.js";
import { parseElfLsda } from "./lsda.js";
import { readElfNativeAotGc } from "./native-aot-gc.js";
import { parseElfArmEhabi } from "./arm-ehabi.js";
import { parseGoBuildInfo } from "./go-build-info.js";
import { decodeElfSymbolNames } from "./symbol-names.js";
import { analyzeElfEmbeddedResources } from "./embedded-resources.js";
import { analyzeElfSanitizers } from "./sanitizers.js";
import { analyzeElfImportLinkage } from "./import-linkage.js";
import { elfLinuxLoadProfile } from "./linux-load-validation.js";

const retainMetadata = <Key extends keyof ElfParseResult>(result: ElfParseResult,
  key: Key, value: ElfParseResult[Key] | null): void => {
  if (value == null || (Array.isArray(value) && !value.length)) return;
  result[key] = value;
};

const parseLinkingTables = async (file: File, result: ElfParseResult, dynamic: ElfDynamicTable,
  cache: Map<number, ElfRelocationSymbol>, layout: ElfBinaryLayout,
  logicalSizes: Map<number, bigint>): Promise<void> => {
  retainMetadata(result, "symbolTables", await parseElfSymbolTables(file, result, cache));
  retainMetadata(result, "sectionGroups", await parseElfSectionGroups(file, result));
  retainMetadata(result, "relocations", await parseElfRelocations(file, result, dynamic, cache, layout, logicalSizes));
  retainMetadata(result, "symbolVersions", await parseElfSymbolVersions(file, result, dynamic.entries,
    result.dynSymbols?.total ?? 0));
};

const parseLinkingMetadata = async (file: File, result: ElfParseResult, layout: ElfBinaryLayout,
  logicalSizes: Map<number, bigint>): Promise<void> => {
  const issues: string[] = [];
  const table = await readElfDynamicTable(
    createFileRangeReader(file, 0, file.size), result, issues, layout);
  const { entries } = table;
  const cache = new Map<number, ElfRelocationSymbol>();
  const hashes = await parseElfHashTables(file, result, entries);
  retainMetadata(result, "hashTables", hashes);
  const [dynamic, symbols] = await Promise.all([
    parseElfDynamicInfo({ file, ...result }, table),
    parseElfDynamicSymbols({ file, ...result }, table, cache, layout, hashes)
  ]);
  retainMetadata(result, "dynamic", dynamic);
  retainMetadata(result, "dynSymbols", symbols);
  await parseLinkingTables(file, result, table, cache, layout, logicalSizes);
  await decodeElfSymbolNames(result);
  result.embeddedResources = await analyzeElfEmbeddedResources(file, result);
  if (result.relocations) result.relocations.issues.unshift(...issues);
  else result.issues.push(...issues);
  if (!issues.length) retainMetadata(result, "nativeAot", await analyzeElfNativeAot(
    file, result, result.issues, result.relocations ?? null, layout));
};

const parseAuxiliaryMetadata = async (file: File, result: ElfParseResult): Promise<void> => {
  retainMetadata(result, "goBuildInfo", await parseGoBuildInfo(file, result.sections, result.issues));
  const [interpreter, notes, comment, debugLink, miniDebugInfo] = await Promise.all([
    parseElfInterpreter(file, result.programHeaders, elfLinuxLoadProfile(result.ident, result.header)),
    parseElfNotes({ file, ...result, ...(result.header.type === 4 ? { coreMachine: result.header.machine } : {}) }),
    parseElfComment(file, result),
    parseElfDebugLink(file, result),
    parseElfMiniDebugInfo(file, result)
  ]);
  retainMetadata(result, "interpreter", interpreter);
  retainMetadata(result, "notes", notes);
  retainMetadata(result, "comment", comment);
  retainMetadata(result, "debugLink", debugLink);
  retainMetadata(result, "miniDebugInfo", miniDebugInfo);
};

const parseArchitectureMetadata = async (file: File, result: ElfParseResult): Promise<void> => {
  retainMetadata(result, "tls", parseElfTlsInfo(result.programHeaders, result.sections, result.header.type));
  retainMetadata(result, "attributes", await parseElfAttributes(file, result));
  retainMetadata(result, "mips", await parseElfMips(file, result));
  retainMetadata(result, "armEhabi", await parseElfArmEhabi(file, result));
};

export const parseElfMetadata = async (file: File, result: ElfParseResult,
  layout: ElfBinaryLayout): Promise<void> => {
  const prepared = await prepareElfDwarfSources(file, result.sections,
    result.is64 ? "elf64" : "elf32", result.littleEndian, result.issues);
  await Promise.all([parseLinkingMetadata(file, result, layout, elfDwarfLogicalSizes(result.sections, prepared)),
    parseAuxiliaryMetadata(file, result),
    parseArchitectureMetadata(file, result)]);
  if (prepared) retainMetadata(result, "dwarf", await analyzeElfDwarf(file, result.sections,
    result.is64 ? "elf64" : "elf32", result.littleEndian, result.issues, result, result.relocations, prepared));
  retainMetadata(result, "unwind", await parseElfUnwind(file, result));
  retainMetadata(result, "sframe", await parseElfSFrame(file, result));
  retainMetadata(result, "lsdas", await parseElfLsda(file, result, await readElfNativeAotGc(file, result)));
  result.sanitizerEvidence = analyzeElfSanitizers(result);
  retainMetadata(result, "importLinkage", analyzeElfImportLinkage(result));
};
