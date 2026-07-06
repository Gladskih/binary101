"use strict";

import { DOMParser as XmlDomParser } from "@xmldom/xmldom";
import { open, readFile, readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createFileRangeReader } from "../../analyzers/file-range-reader.js";
import {
  isPeWindowsParseResult,
  parsePe,
  type PeWindowsParseResult
} from "../../analyzers/pe/index.js";
import { analyzePeEntrypointDisassembly } from "../../analyzers/pe/disassembly/index.js";
import {
  createPeImportMetadataLookup,
  enrichPeImportMetadata
} from "../../analyzers/pe/imports/winapi-metadata.js";
import { IMAGE_FILE_MACHINE_I386 } from "../../analyzers/coff/machine.js";
import { getCanonicalPeMachine } from "../../analyzers/pe/machine.js";
import { PE32_OPTIONAL_HEADER_MAGIC } from "../../analyzers/pe/optional-header/magic.js";
import type { ManifestXmlDocumentParser } from "../../analyzers/pe/resources/preview/manifest-xml.js";
import type { PeImportMetadataEntry } from "../../pe-import-metadata-schema.js";
import { createDiskBackedFile, type FileLike } from "./disk-file.js";
import {
  addDllImpact,
  buildReport,
  cleanErrorMessage,
  increment,
  initialState,
  type ImportedFunction,
  type ScanOptions,
  type ScanReport,
  type ScanState
} from "./report-model.js";

const parseManifestXmlDocument: ManifestXmlDocumentParser = text =>
  new XmlDomParser({ onError: () => undefined }).parseFromString(text, "application/xml");

const readMetadataJson = async (path: string): Promise<unknown | null> => {
  try {
    return JSON.parse(await readFile(join(process.cwd(), "public", path), "utf8")) as unknown;
  } catch {
    return null;
  }
};

const readMzSignature = async (path: string): Promise<boolean> => {
  const handle = await open(path, "r");
  try {
    const bytes = new Uint8Array(2);
    const { bytesRead } = await handle.read(bytes, 0, bytes.byteLength, 0);
    return bytesRead === 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  } finally {
    await handle.close();
  }
};

const importedFunctions = (pe: PeWindowsParseResult): ImportedFunction[] => [
  ...pe.imports.entries.flatMap(entry =>
    entry.functions.map(fn => ({
      dll: entry.dll,
      name: fn.name ?? null,
      metadata: fn.apiMetadata ?? fn.winapiMetadata ?? null
    }))),
  ...(pe.delayImports?.entries.flatMap(entry =>
    entry.functions.map(fn => ({
      dll: entry.name,
      name: fn.name ?? null,
      metadata: fn.apiMetadata ?? fn.winapiMetadata ?? null
    }))) ?? [])
];

const isCleanupConvention = (metadata: PeImportMetadataEntry): boolean =>
  !metadata.variadic && (metadata.callingConvention === "winapi" || metadata.callingConvention === "stdcall");

const hasCompleteX86StackSizes = (metadata: PeImportMetadataEntry): boolean =>
  metadata.parameters.every(parameter => parameter.x86StackBytes != null);

const recordImportMetadata = (path: string, imported: ImportedFunction[], state: ScanState): void => {
  state.importFunctions += imported.length;
  for (const fn of imported) {
    if (!fn.name) continue;
    state.namedImportFunctions += 1;
    if (!fn.metadata) {
      addDllImpact(state.missingMetadataByDll, fn.dll.trim().toLowerCase() || "<empty>", path);
      continue;
    }
    state.metadataMatched += 1;
    increment(state.metadataMatchesBySource, fn.metadata.sourceKind);
    if (!isCleanupConvention(fn.metadata)) continue;
    state.cleanupCandidates += 1;
    if (hasCompleteX86StackSizes(fn.metadata)) state.cleanupComplete += 1;
    else recordUnknownStackSize(fn.metadata, state);
  }
};

const recordUnknownStackSize = (metadata: PeImportMetadataEntry, state: ScanState): void => {
  state.cleanupUnknownSize += 1;
  increment(state.unknownStackSizeByFunction, `${metadata.module}!${metadata.entrypoint}`);
};

const analyzeEntrypoint = async (
  path: string,
  file: FileLike,
  pe: PeWindowsParseResult,
  state: ScanState
): Promise<void> => {
  const report = await analyzePeEntrypointDisassembly(createFileRangeReader(file as File, 0, file.size), {
    coffMachine: pe.coff.Machine,
    is64Bit: pe.opt.Magic !== PE32_OPTIONAL_HEADER_MAGIC,
    imageBase: pe.opt.ImageBase,
    headerRvaLimit: pe.opt.SizeOfHeaders,
    entrypointRva: pe.opt.AddressOfEntryPoint,
    imports: pe.imports,
    delayImports: pe.delayImports,
    loadcfg: pe.loadcfg,
    rvaToOff: pe.rvaToOff,
    sections: pe.sections
  });
  const importReturnBlocks = report.blocks.filter(block => block.kind === "followed-import-return").length;
  state.x86EntrypointsAnalyzed += 1;
  if (importReturnBlocks > 0) state.x86EntrypointsWithImportReturns += 1;
  report.issues.forEach(issue => increment(state.entrypointIssues, issue));
  if (report.instructionCount === 0) increment(state.entrypointIssues, `${path}: zero entrypoint instructions`);
};

const isX86Pe32 = (pe: PeWindowsParseResult): boolean =>
  getCanonicalPeMachine(pe.coff.Machine) === IMAGE_FILE_MACHINE_I386 &&
  pe.opt.Magic === PE32_OPTIONAL_HEADER_MAGIC;

const analyzeCandidate = async (path: string, options: ScanOptions, state: ScanState): Promise<void> => {
  const info = await stat(path);
  if (!info.isFile()) return;
  state.filesVisited += 1;
  if (!(await readMzSignature(path))) return;
  state.mzCandidates += 1;
  const file = createDiskBackedFile(path, info.size);
  const parsed = await parsePe(file as File, parseManifestXmlDocument);
  if (!parsed) return;
  state.peFiles += 1;
  if (!isPeWindowsParseResult(parsed)) return;
  const pe = await enrichPeImportMetadata(parsed, createPeImportMetadataLookup(readMetadataJson));
  if (!isX86Pe32(pe)) return;
  state.x86PeFiles += 1;
  recordImportMetadata(path, importedFunctions(pe), state);
  if (state.x86EntrypointsAnalyzed < options.maxEntrypoints) await analyzeEntrypoint(path, file, pe, state);
};

const reachedPeLimit = (options: ScanOptions, state: ScanState): boolean =>
  options.maxPeFiles != null && state.peFiles >= options.maxPeFiles;

const scanPath = async (path: string, options: ScanOptions, state: ScanState): Promise<void> => {
  if (reachedPeLimit(options, state)) return;
  let info;
  try {
    info = await stat(path);
  } catch (error) {
    state.errors.push({ path, message: cleanErrorMessage(error) });
    return;
  }
  if (info.isDirectory()) {
    let entries;
    try {
      entries = await readdir(path, { withFileTypes: true });
    } catch (error) {
      state.errors.push({ path, message: cleanErrorMessage(error) });
      return;
    }
    for (const entry of entries) await scanPath(resolve(path, entry.name), options, state);
    return;
  }
  try {
    await analyzeCandidate(path, options, state);
  } catch (error) {
    state.errors.push({ path, message: cleanErrorMessage(error) });
  }
};

export const scanPeImportMetadata = async (options: ScanOptions): Promise<ScanReport> => {
  const state = initialState();
  for (const root of options.roots) await scanPath(root, options, state);
  return buildReport(options, state);
};
