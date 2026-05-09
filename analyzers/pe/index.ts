"use strict";
import { createFileRangeReader } from "../file-range-reader.js";
import { isPeWindowsCore, parsePeHeaders } from "./core/index.js";
import { computePeAuthenticodeDigest, verifyAuthenticodeWithBundledTrust } from "./authenticode/verify.js";
import { parseDebugDirectory } from "./debug/directory.js";
import { parseLoadConfigDirectory32, parseLoadConfigDirectory64 } from "./load-config/index.js";
import { readSafeSehHandlerTable } from "./load-config/tables.js";
import { parseAndEnrichLoadConfig } from "./load-config/enrich.js";
import { collectLoadConfigChecks } from "./load-config/checks.js";
import { parseImportDirectory32, parseImportDirectory64 } from "./imports/index.js";
import { parseExportDirectory } from "./directories/exports.js";
import { parseTlsDirectory32, parseTlsDirectory64 } from "./directories/tls.js";
import { parseResources } from "./resources/index.js";
import { parseClrDirectory } from "./clr/index.js";
import { parseSecurityDirectory } from "./security/index.js";
import { addSecurityTailWarning } from "./security/tail-warning.js";
import { parseBaseRelocations } from "./directories/reloc.js";
import { parseExceptionDirectory } from "./exception/index.js";
import { parseBoundImports } from "./imports/bound.js";
import { parseDelayImports32, parseDelayImports64 } from "./imports/delay.js";
import { parseDynamicRelocationsFromLoadConfig32, parseDynamicRelocationsFromLoadConfig64 } from "./dynamic-relocations/index.js";
import { parseIatDirectory } from "./imports/iat.js";
import { parseArchitectureDirectory } from "./directories/architecture-directory.js";
import { parseGlobalPtrDirectory } from "./directories/globalptr-directory.js";
import { detectNativeAotCandidate } from "./native-aot.js";
import { analyzeImportLinking } from "./imports/linking.js";
import {
  analyzeManifestConsistency,
  attachManifestValidation
} from "./resources/manifest-consistency.js";
import {
  parseBrowserManifestXmlDocument,
  type ManifestXmlDocumentParser
} from "./resources/preview/manifest-xml.js";
import { buildHeaderOnlyPeParseResult } from "./core/header-only-result.js";
import { collectPeLayoutWarnings } from "./layout/warnings.js";
export {
  isPeRomParseResult,
  isPeWindowsParseResult
} from "./core/parse-result.js";
export type {
  PeDebugSection,
  PeHeaderParseResult,
  PeParseResult,
  PeWindowsParseResult
} from "./core/parse-result.js";
import { PE32_PLUS_OPTIONAL_HEADER_MAGIC } from "./optional-header/magic.js";
import type { PeParseResult } from "./core/parse-result.js";

// Microsoft PE format, "Machine Types":
// IMAGE_FILE_MACHINE_I386 is the only PE32 machine where SafeSEH applies.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_I386 = 0x014c;

const appendUniqueWarnings = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

const digestCacheKey = (algorithm: AlgorithmIdentifier): string =>
  typeof algorithm === "string" ? algorithm : JSON.stringify(algorithm);

const withLayoutWarnings = <T extends PeParseResult>(result: T, fileSize: number): T => {
  const mergedWarnings = appendUniqueWarnings(result.warnings, collectPeLayoutWarnings(result, fileSize));
  return mergedWarnings?.length ? { ...result, warnings: mergedWarnings } : result;
};

export async function parsePe(
  file: File,
  parseManifestXmlDocument: ManifestXmlDocumentParser = parseBrowserManifestXmlDocument
): Promise<PeParseResult | null> {
  const reader = createFileRangeReader(file, 0, file.size);
  const core = await parsePeHeaders(reader);
  if (!core) return null;
  if (!isPeWindowsCore(core)) {
    return withLayoutWarnings(buildHeaderOnlyPeParseResult(core), file.size);
  }
  const { dos, coff, opt, dataDirs, sections, entrySection, rvaToOff, overlaySize, imageEnd, imageSizeMismatch } = core;
  const { ImageBase } = opt;
  const peVariant = opt.Magic === PE32_PLUS_OPTIONAL_HEADER_MAGIC
    ? {
        parseLoadConfigDirectory: parseLoadConfigDirectory64,
        parseImportDirectory: parseImportDirectory64,
        parseTlsDirectory: parseTlsDirectory64,
        parseDelayImports: parseDelayImports64,
        parseDynamicRelocationsFromLoadConfig: parseDynamicRelocationsFromLoadConfig64,
        readSafeSehHandlerTable: null
      }
    : {
        parseLoadConfigDirectory: parseLoadConfigDirectory32,
        parseImportDirectory: parseImportDirectory32,
        parseTlsDirectory: parseTlsDirectory32,
        parseDelayImports: parseDelayImports32,
        parseDynamicRelocationsFromLoadConfig: parseDynamicRelocationsFromLoadConfig32,
        readSafeSehHandlerTable:
          // Microsoft PE format: SafeSEH applies only to IMAGE_FILE_MACHINE_I386 PE32 images.
          coff.Machine === IMAGE_FILE_MACHINE_I386 ? readSafeSehHandlerTable : null
  };

  const debugResult = await parseDebugDirectory(reader, dataDirs, rvaToOff);
  const loadcfg = await parseAndEnrichLoadConfig(
    reader,
    file.size,
    dataDirs,
    rvaToOff,
    ImageBase,
    opt.SizeOfImage,
    sections,
    peVariant.parseLoadConfigDirectory,
    peVariant.parseDynamicRelocationsFromLoadConfig,
    peVariant.readSafeSehHandlerTable
  );
  const importResult = await peVariant.parseImportDirectory(reader, dataDirs, rvaToOff);
  const exportsInfo = await parseExportDirectory(reader, dataDirs, rvaToOff);
  const tls = await peVariant.parseTlsDirectory(reader, dataDirs, rvaToOff, ImageBase);
  const resources = await parseResources(reader, dataDirs, rvaToOff, parseManifestXmlDocument);
  const reloc = await parseBaseRelocations(reader, dataDirs, rvaToOff);
  const exception = await parseExceptionDirectory(reader, dataDirs, rvaToOff, coff.Machine);
  const boundImports = await parseBoundImports(reader, dataDirs, rvaToOff);
  const delayImports = await peVariant.parseDelayImports(reader, dataDirs, rvaToOff);
  const clr = await parseClrDirectory(reader, dataDirs, rvaToOff);
  const nativeAotCandidate = detectNativeAotCandidate(clr != null, exportsInfo, sections);
  const securityDir = dataDirs.find(d => d.name === "SECURITY");
  const authenticodeDigestCache = new Map<string, Promise<string | null>>();
  const getCachedAuthenticodeDigest = (algorithm: AlgorithmIdentifier): Promise<string | null> => {
    const cacheKey = digestCacheKey(algorithm);
    const cached = authenticodeDigestCache.get(cacheKey);
    if (cached) return cached;
    const computed = computePeAuthenticodeDigest(reader, core, securityDir, algorithm);
    authenticodeDigestCache.set(cacheKey, computed);
    return computed;
  };
  let security = await parseSecurityDirectory(reader, dataDirs, async (payload, certificate) =>
    certificate.authenticode
      ? verifyAuthenticodeWithBundledTrust(
          reader,
          core,
          securityDir,
          certificate.authenticode,
          payload,
          undefined,
          getCachedAuthenticodeDigest
        )
      : undefined
  );
  security = addSecurityTailWarning(file.size, security, dataDirs.find(d => d.name === "SECURITY"), debugResult.rawDataRanges);
  const iat = parseIatDirectory(dataDirs, rvaToOff);
  const importLinking = analyzeImportLinking(
    importResult,
    boundImports,
    delayImports,
    iat,
    loadcfg,
    sections
  );
  if (loadcfg) {
    loadcfg.checks = collectLoadConfigChecks(
      loadcfg,
      opt,
      coff.Machine,
      sections,
      delayImports?.entries.length ?? 0,
      importLinking
    );
  }
  const architecture = parseArchitectureDirectory(dataDirs);
  const globalPtr = parseGlobalPtrDirectory(dataDirs, rvaToOff);
  const manifestValidation = analyzeManifestConsistency(resources, coff.Machine, clr);
  const warnings = appendUniqueWarnings(
    core.warnings,
    manifestValidation?.warnings ?? []
  );
  return withLayoutWarnings({
    debug:
      debugResult.entry || debugResult.warning || debugResult.entries.length
        ? {
            entry: debugResult.entry,
            ...(debugResult.entries.length ? { entries: debugResult.entries } : {}),
            ...(debugResult.rawDataRanges.length ? { rawDataRanges: debugResult.rawDataRanges } : {}),
            ...(debugResult.warning ? { warning: debugResult.warning } : {})
          }
        : null,
    dos,
    signature: "PE",
    coff,
    ...(core.coffStringTableSize != null ? { coffStringTableSize: core.coffStringTableSize } : {}),
    ...(core.trailingAlignmentPaddingSize ? { trailingAlignmentPaddingSize: core.trailingAlignmentPaddingSize } : {}),
    opt,
    ...(warnings?.length ? { warnings } : {}),
    dirs: dataDirs,
    sections,
    entrySection,
    rvaToOff,
    imports: importResult,
    loadcfg,
    exports: exportsInfo,
    tls,
    reloc,
    exception,
    boundImports,
    delayImports,
    clr,
    security,
    iat,
    importLinking,
    architecture,
    globalPtr,
    nativeAotCandidate,
    resources: attachManifestValidation(resources, manifestValidation),
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    hasCert: !!security?.count,
  }, file.size);
}
