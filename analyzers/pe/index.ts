"use strict";
import { createFileRangeReader } from "../file-range-reader.js";
import { isPeWindowsCore, parsePeHeaders } from "./core.js";
import { computePeAuthenticodeDigest, verifyAuthenticode } from "./authenticode-verify.js";
import { parseDebugDirectory } from "./debug-directory.js";
import { parseLoadConfigDirectory32, parseLoadConfigDirectory64, type PeLoadConfig, type PeLoadConfigTables } from "./load-config/index.js";
import { readGuardAddressTakenIatEntryTableRvas, readGuardCFFunctionTableRvas, readGuardEhContinuationTableRvas, readGuardLongJumpTargetTableRvas, readSafeSehHandlerTableRvas } from "./load-config/tables.js";
import { collectLoadConfigWarnings } from "./load-config/warnings.js";
import { parseImportDirectory32, parseImportDirectory64 } from "./imports.js";
import { parseExportDirectory } from "./exports.js";
import { parseTlsDirectory32, parseTlsDirectory64 } from "./tls.js";
import { parseResources } from "./resources/index.js";
import { parseClrDirectory } from "./clr/index.js";
import { parseSecurityDirectory } from "./security.js";
import { addSecurityTailWarning } from "./security-tail-warning.js";
import { parseBaseRelocations } from "./reloc.js";
import { parseExceptionDirectory } from "./exception.js";
import { parseBoundImports } from "./bound-imports.js";
import { parseDelayImports32, parseDelayImports64 } from "./delay-imports.js";
import { parseDynamicRelocationsFromLoadConfig32, parseDynamicRelocationsFromLoadConfig64 } from "./dynamic-relocations.js";
import { parseIatDirectory } from "./iat-directory.js";
import { parseArchitectureDirectory } from "./architecture-directory.js";
import { parseGlobalPtrDirectory } from "./globalptr-directory.js";
import { analyzeImportLinking } from "./import-linking.js";
import {
  analyzeManifestConsistency,
  attachManifestValidation
} from "./manifest-consistency.js";
import {
  parseBrowserManifestXmlDocument,
  type ManifestXmlDocumentParser
} from "./resources/preview/manifest-xml.js";
import { buildHeaderOnlyPeParseResult } from "./header-only-result.js";
import { collectPeLayoutWarnings } from "./layout-warnings.js";
export {
  isPeRomParseResult,
  isPeWindowsParseResult
} from "./parse-result.js";
export type {
  PeDebugSection,
  PeHeaderParseResult,
  PeParseResult,
  PeWindowsParseResult
} from "./parse-result.js";
import {
  PE32_PLUS_OPTIONAL_HEADER_MAGIC
} from "./optional-header-magic.js";
import type { PeParseResult } from "./parse-result.js";

// Microsoft PE format, "Machine Types":
// IMAGE_FILE_MACHINE_I386 is the only PE32 machine where SafeSEH applies.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_I386 = 0x014c;

const appendUniqueWarnings = (existing: string[] | undefined, messages: string[]): string[] | undefined =>
  messages.length ? [...new Set([...(existing ?? []), ...messages])] : existing;

const digestCacheKey = (algorithm: AlgorithmIdentifier): string =>
  typeof algorithm === "string" ? algorithm : JSON.stringify(algorithm);

const mergeLoadConfigWarnings = (loadcfg: PeLoadConfig, messages: string[]): void => {
  const merged = appendUniqueWarnings(loadcfg.warnings, messages);
  if (merged?.length) loadcfg.warnings = merged;
};

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
        readSafeSehHandlerTableRvas: null
      }
    : {
        parseLoadConfigDirectory: parseLoadConfigDirectory32,
        parseImportDirectory: parseImportDirectory32,
        parseTlsDirectory: parseTlsDirectory32,
        parseDelayImports: parseDelayImports32,
        parseDynamicRelocationsFromLoadConfig: parseDynamicRelocationsFromLoadConfig32,
        readSafeSehHandlerTableRvas:
          // Microsoft PE format: SafeSEH applies only to IMAGE_FILE_MACHINE_I386 PE32 images.
          coff.Machine === IMAGE_FILE_MACHINE_I386 ? readSafeSehHandlerTableRvas : null
      };

  const debugResult = await parseDebugDirectory(reader, dataDirs, rvaToOff);
  const loadcfg = await peVariant.parseLoadConfigDirectory(reader, dataDirs, rvaToOff);
  if (loadcfg) {
    const warnings = collectLoadConfigWarnings(file.size, rvaToOff, ImageBase, opt.SizeOfImage, loadcfg);
    mergeLoadConfigWarnings(loadcfg, warnings);

    const tables: PeLoadConfigTables = {};
    const guardFlags = loadcfg.GuardFlags;
    const addLoadConfigWarning = (message: string): void => {
      mergeLoadConfigWarnings(loadcfg, [message]);
    };

    if (Number.isSafeInteger(loadcfg.GuardCFFunctionCount) && loadcfg.GuardCFFunctionCount > 0) {
      try {
        tables.guardFidRvas = await readGuardCFFunctionTableRvas(
          reader,
          rvaToOff,
          ImageBase,
          loadcfg.GuardCFFunctionTable,
          loadcfg.GuardCFFunctionCount,
          guardFlags
        );
      } catch (error) {
        addLoadConfigWarning(`LOAD_CONFIG: failed to read GuardCFFunctionTable (${String(error)}).`);
      }
    }

    if (Number.isSafeInteger(loadcfg.GuardEHContinuationCount) && loadcfg.GuardEHContinuationCount > 0) {
      try {
        tables.guardEhContinuationRvas = await readGuardEhContinuationTableRvas(
          reader,
          rvaToOff,
          ImageBase,
          loadcfg.GuardEHContinuationTable,
          loadcfg.GuardEHContinuationCount,
          guardFlags
        );
      } catch (error) {
        addLoadConfigWarning(`LOAD_CONFIG: failed to read GuardEHContinuationTable (${String(error)}).`);
      }
    }

    if (Number.isSafeInteger(loadcfg.GuardLongJumpTargetCount) && loadcfg.GuardLongJumpTargetCount > 0) {
      try {
        tables.guardLongJumpTargetRvas = await readGuardLongJumpTargetTableRvas(
          reader,
          rvaToOff,
          ImageBase,
          loadcfg.GuardLongJumpTargetTable,
          loadcfg.GuardLongJumpTargetCount,
          guardFlags
        );
      } catch (error) {
        addLoadConfigWarning(`LOAD_CONFIG: failed to read GuardLongJumpTargetTable (${String(error)}).`);
      }
    }

    if (Number.isSafeInteger(loadcfg.GuardAddressTakenIatEntryCount) && loadcfg.GuardAddressTakenIatEntryCount > 0) {
      try {
        tables.guardIatRvas = await readGuardAddressTakenIatEntryTableRvas(
          reader,
          rvaToOff,
          ImageBase,
          loadcfg.GuardAddressTakenIatEntryTable,
          loadcfg.GuardAddressTakenIatEntryCount,
          guardFlags
        );
      } catch (error) {
        addLoadConfigWarning(`LOAD_CONFIG: failed to read GuardAddressTakenIatEntryTable (${String(error)}).`);
      }
    }

    if (
      peVariant.readSafeSehHandlerTableRvas &&
      Number.isSafeInteger(loadcfg.SEHandlerCount) &&
      loadcfg.SEHandlerCount > 0
    ) {
      try {
        tables.safeSehHandlerRvas = await peVariant.readSafeSehHandlerTableRvas(
          reader,
          rvaToOff,
          ImageBase,
          loadcfg.SEHandlerTable,
          loadcfg.SEHandlerCount
        );
      } catch (error) {
        addLoadConfigWarning(`LOAD_CONFIG: failed to read SEHandlerTable (${String(error)}).`);
      }
    }

    if (Object.keys(tables).length) {
      loadcfg.tables = tables;
    }

    try {
      loadcfg.dynamicRelocations = await peVariant.parseDynamicRelocationsFromLoadConfig(
        reader,
        sections,
        rvaToOff,
        ImageBase,
        loadcfg
      );
    } catch (error) {
      addLoadConfigWarning(`LOAD_CONFIG: failed to read dynamic relocations (${String(error)}).`);
      loadcfg.dynamicRelocations = null;
    }
  }
  const importResult = await peVariant.parseImportDirectory(reader, dataDirs, rvaToOff);
  const exportsInfo = await parseExportDirectory(reader, dataDirs, rvaToOff);
  const tls = await peVariant.parseTlsDirectory(reader, dataDirs, rvaToOff, ImageBase);
  const resources = await parseResources(reader, dataDirs, rvaToOff, parseManifestXmlDocument);
  const reloc = await parseBaseRelocations(reader, dataDirs, rvaToOff);
  const exception = await parseExceptionDirectory(reader, dataDirs, rvaToOff, coff.Machine);
  const boundImports = await parseBoundImports(reader, dataDirs, rvaToOff);
  const delayImports = await peVariant.parseDelayImports(reader, dataDirs, rvaToOff);
  const clr = await parseClrDirectory(reader, dataDirs, rvaToOff);
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
      ? verifyAuthenticode(
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
    resources: attachManifestValidation(resources, manifestValidation),
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    hasCert: !!security?.count,
  }, file.size);
}
