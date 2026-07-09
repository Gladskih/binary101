"use strict";

import type { FileRangeReader } from "../file-range-reader.js";
import { computePeAuthenticodeDigest, verifyAuthenticodeWithBundledTrust } from "./authenticode/verify.js";
import { parseCoffDebugInfoFromFileHeader } from "../coff/debug.js";
import { collectDebugExceptionConsistencyFindings } from "./debug/exception-consistency.js";
import { parseDebugDirectory } from "./debug/directory.js";
import { parseArchitectureDirectory } from "./directories/architecture-directory.js";
import { parseExportDirectory } from "./directories/exports.js";
import { parseGlobalPtrDirectory } from "./directories/globalptr-directory.js";
import { parseBaseRelocations } from "./directories/reloc.js";
import type { parseTlsDirectory32 } from "./directories/tls.js";
import { parseExceptionDirectory } from "./exception/index.js";
import { parseBoundImports } from "./imports/bound.js";
import type { parseDelayImports32 } from "./imports/delay.js";
import { parseIatDirectory } from "./imports/iat.js";
import type { parseImportDirectory32 } from "./imports/index.js";
import { analyzeImportLinking } from "./imports/linking.js";
import { parseLinuxBootProtocol } from "./linux-boot.js";
import { collectLoadConfigChecks } from "./load-config/checks.js";
import { getCanonicalPeMachine } from "./machine.js";
import { detectNativeAotCandidate } from "./native-aot.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";
import { analyzePeOverlay } from "./overlay.js";
import { analyzePePackers } from "./packers/index.js";
import type { PeWindowsParseResult } from "./core/parse-result.js";
import { analyzeManifestConsistency } from "./resources/manifest-consistency.js";
import type { ManifestXmlDocumentParser } from "./resources/preview/manifest-xml.js";
import { parseResources } from "./resources/index.js";
import { parseClrDirectory } from "./clr/index.js";
import { parseSecurityDirectory } from "./security/index.js";
import { addSecurityTailWarning } from "./security/tail-warning.js";
import { detectPeSubtype } from "./subtype.js";
import type { PeDataDirectory, PeWindowsCore } from "./types.js";
import { buildWindowsPeResult, withWindowsPeLayoutWarnings } from "./parse-windows-result.js";
import { selectPeVariantParsers, type PeVariantParsers } from "./parse-variant.js";

export type PeWindowsParseContext = {
  file: File;
  reader: FileRangeReader;
  core: PeWindowsCore;
  parseManifestXmlDocument: ManifestXmlDocumentParser;
  canonicalMachine: number;
  peVariant: PeVariantParsers;
  securityDir: PeDataDirectory | undefined;
  linuxBoot: Awaited<ReturnType<typeof parseLinuxBootProtocol>>;
};

export type PeDebugArtifacts = {
  debugResult: Awaited<ReturnType<typeof parseDebugDirectory>>;
  coffDebug: Awaited<ReturnType<typeof parseCoffDebugInfoFromFileHeader>> | null;
  debugNotes: string[] | undefined;
  debugWarning: string | null;
};

export type PeDirectoryArtifacts = {
  importResult: Awaited<ReturnType<typeof parseImportDirectory32>>;
  exportsInfo: Awaited<ReturnType<typeof parseExportDirectory>>;
  tls: Awaited<ReturnType<typeof parseTlsDirectory32>>;
  resources: Awaited<ReturnType<typeof parseResources>>;
  reloc: Awaited<ReturnType<typeof parseBaseRelocations>>;
  clr: Awaited<ReturnType<typeof parseClrDirectory>>;
  nativeAotCandidate: ReturnType<typeof detectNativeAotCandidate>;
  exception: Awaited<ReturnType<typeof parseExceptionDirectory>>;
  boundImports: Awaited<ReturnType<typeof parseBoundImports>>;
  delayImports: Awaited<ReturnType<typeof parseDelayImports32>>;
  subtype: ReturnType<typeof detectPeSubtype>;
  loadcfg: Awaited<ReturnType<PeVariantParsers["parseAndEnrichLoadConfig"]>>;
  iat: ReturnType<typeof parseIatDirectory>;
  architecture: ReturnType<typeof parseArchitectureDirectory>;
  globalPtr: ReturnType<typeof parseGlobalPtrDirectory>;
  manifestValidation: ReturnType<typeof analyzeManifestConsistency>;
};

export type PeOverlayArtifacts = {
  overlay: Awaited<ReturnType<typeof analyzePeOverlay>>;
  packers: Awaited<ReturnType<typeof analyzePePackers>>;
};

const appendUniqueMessages = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

const appendDebugWarnings = (existing: string | null, messages: string[]): string | null => {
  if (!messages.length) return existing;
  return [...new Set([...(existing ? existing.split(" | ") : []), ...messages])].join(" | ");
};

const digestCacheKey = (algorithm: AlgorithmIdentifier): string =>
  typeof algorithm === "string" ? algorithm : JSON.stringify(algorithm);

export const parseWindowsPe = async (
  file: File,
  reader: FileRangeReader,
  core: PeWindowsCore,
  parseManifestXmlDocument: ManifestXmlDocumentParser
): Promise<PeWindowsParseResult> => {
  const canonicalMachine = getCanonicalPeMachine(core.coff.Machine);
  const context: PeWindowsParseContext = {
    file,
    reader,
    core,
    parseManifestXmlDocument,
    canonicalMachine,
    peVariant: selectPeVariantParsers(core.opt.Magic, canonicalMachine),
    securityDir: core.dataDirs.find(d => d.name === "SECURITY"),
    linuxBoot: await parseLinuxBootProtocol(reader, file)
  };
  const debugArtifacts = await parsePeDebugArtifacts(context);
  const directories = await parsePeDirectoryArtifacts(context);
  const security = await parsePeSecurity(context, debugArtifacts.debugResult);
  const overlayArtifacts = await parsePeOverlayArtifacts(context, debugArtifacts.debugResult);
  const importLinking = analyzeImportLinking(
    directories.importResult,
    directories.boundImports,
    directories.delayImports,
    directories.iat,
    directories.loadcfg,
    core.sections
  );
  applyLoadConfigChecks(context, directories, importLinking);
  return withWindowsPeLayoutWarnings(
    buildWindowsPeResult(context, debugArtifacts, directories, overlayArtifacts, security, importLinking),
    file.size
  );
};

const parsePeDebugArtifacts = async (
  context: PeWindowsParseContext
): Promise<PeDebugArtifacts> => {
  const { reader, core, canonicalMachine } = context;
  const debugResult = await parseDebugDirectory(reader, core.dataDirs, core.rvaToOff, canonicalMachine);
  const hasMatchingCoffEntry = debugResult.entries.some(entry =>
    entry.coff?.symbolTableOffset === core.coff.PointerToSymbolTable
  );
  const coffDebug = hasMatchingCoffEntry
    ? null
    : await parseCoffDebugInfoFromFileHeader(
        reader,
        core.coff.PointerToSymbolTable,
        core.coff.NumberOfSymbols,
        core.sections,
        () => undefined
      );
  const debugExceptionFindings = await collectDebugExceptionConsistencyFindings(
    reader,
    core.dataDirs,
    core.rvaToOff,
    debugResult.entries
  );
  return {
    debugResult,
    coffDebug,
    debugNotes: appendUniqueMessages(undefined, debugExceptionFindings.notes),
    debugWarning: appendDebugWarnings(debugResult.warning, debugExceptionFindings.warnings)
  };
};

const parsePeDirectoryArtifacts = async (
  context: PeWindowsParseContext
): Promise<PeDirectoryArtifacts> => {
  const { reader, core, peVariant, parseManifestXmlDocument, canonicalMachine } = context;
  const loadcfg = await peVariant.parseAndEnrichLoadConfig(
    reader,
    core.dataDirs,
    core.rvaToOff,
    core.opt.ImageBase,
    core.opt.SizeOfImage,
    core.sections
  );
  const importResult = await peVariant.parseImportDirectory(reader, core.dataDirs, core.rvaToOff);
  const exportsInfo = await parseExportDirectory(reader, core.dataDirs, core.rvaToOff);
  const tls = await peVariant.parseTlsDirectory(
    reader,
    core.dataDirs,
    core.rvaToOff,
    core.opt.ImageBase,
    core.sections
  );
  const resources = await parseResources(reader, core.dataDirs, core.rvaToOff, parseManifestXmlDocument);
  const reloc = await parseBaseRelocations(reader, core.dataDirs, core.rvaToOff);
  const clr = await parseClrDirectory(reader, core.dataDirs, core.rvaToOff);
  const nativeAotCandidate = detectNativeAotCandidate(clr != null, exportsInfo, core.sections);
  const exception = await parseExceptionDirectory(
    reader,
    core.dataDirs,
    core.rvaToOff,
    canonicalMachine,
    clr?.readyToRun,
    nativeAotCandidate
  );
  const boundImports = await parseBoundImports(reader, core.dataDirs, core.rvaToOff);
  const delayImports = await peVariant.parseDelayImports(
    reader,
    core.dataDirs,
    core.rvaToOff,
    { sizeOfImage: core.opt.SizeOfImage }
  );
  return {
    importResult,
    exportsInfo,
    tls,
    resources,
    reloc,
    clr,
    nativeAotCandidate,
    exception,
    boundImports,
    delayImports,
    subtype: detectPeSubtype(clr, resources?.muiResourceConfiguration, core.opt.AddressOfEntryPoint, core.sections,
      context.linuxBoot, core.dos),
    loadcfg,
    iat: parseIatDirectory(core.dataDirs, core.rvaToOff),
    architecture: parseArchitectureDirectory(core.dataDirs),
    globalPtr: parseGlobalPtrDirectory(core.dataDirs, core.opt.SizeOfImage),
    manifestValidation: analyzeManifestConsistency(resources, canonicalMachine, clr)
  };
};

const parsePeSecurity = async (
  context: PeWindowsParseContext,
  debugResult: PeDebugArtifacts["debugResult"]
): Promise<Awaited<ReturnType<typeof parseSecurityDirectory>>> => {
  const authenticodeDigestCache = new Map<string, Promise<string | null>>();
  const getCachedAuthenticodeDigest = (algorithm: AlgorithmIdentifier): Promise<string | null> => {
    const cacheKey = digestCacheKey(algorithm);
    const cached = authenticodeDigestCache.get(cacheKey);
    if (cached) return cached;
    const computed = computePeAuthenticodeDigest(context.reader, context.core, context.securityDir, algorithm);
    authenticodeDigestCache.set(cacheKey, computed);
    return computed;
  };
  const security = await parseSecurityDirectory(context.reader, context.core.dataDirs, async (payload, certificate) =>
    certificate.authenticode
      ? verifyAuthenticodeWithBundledTrust(
          context.reader,
          context.core,
          context.securityDir,
          certificate.authenticode,
          payload,
          undefined,
          getCachedAuthenticodeDigest
        )
      : undefined
  );
  return addSecurityTailWarning(
    context.file.size,
    security,
    context.securityDir,
    debugResult.rawDataRanges
  );
};

const parsePeOverlayArtifacts = async (
  context: PeWindowsParseContext,
  debugResult: PeDebugArtifacts["debugResult"]
): Promise<PeOverlayArtifacts> => {
  const { file, reader, core } = context;
  const overlay = await analyzePeOverlay({
    file,
    reader,
    optionalHeaderOffset: core.optOff,
    optionalHeaderSize: core.coff.SizeOfOptionalHeader,
    sectionCount: core.coff.NumberOfSections,
    declaredSizeOfHeaders: core.opt.SizeOfHeaders,
    sections: core.sections,
    ...(core.trailingAlignmentPaddingSize ? { trailingAlignmentPaddingSize: core.trailingAlignmentPaddingSize } : {}),
    dataDirs: core.dataDirs,
    debugRawDataRanges: debugResult.rawDataRanges,
    pointerToSymbolTable: core.coff.PointerToSymbolTable,
    numberOfSymbols: core.coff.NumberOfSymbols,
    ...(core.coffStringTableSize != null ? { coffStringTableSize: core.coffStringTableSize } : {})
  });
  return {
    overlay,
    packers: await analyzePePackers({
      reader,
      sections: core.sections,
      overlay,
      // Bun's .bun Offsets.byte_count is a usize, so it follows the PE image pointer width.
      // https://github.com/oven-sh/bun/blob/main/src/standalone_graph/StandaloneModuleGraph.zig
      imagePointerBytes: core.opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC ? 8 : 4
    })
  };
};

const applyLoadConfigChecks = (
  context: PeWindowsParseContext,
  directories: PeDirectoryArtifacts,
  importLinking: PeWindowsParseResult["importLinking"]
): void => {
  if (!directories.loadcfg) return;
  directories.loadcfg.checks = collectLoadConfigChecks(
    directories.loadcfg,
    context.core.opt,
    context.canonicalMachine,
    context.core.sections,
    directories.delayImports?.entries.length ?? 0,
    importLinking
  );
};
