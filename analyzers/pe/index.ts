"use strict";
import { isPeWindowsCore, parsePeHeaders } from "./core.js";
import { verifyAuthenticodeFileDigest } from "./authenticode-verify.js";
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

const mergeLoadConfigWarnings = (loadcfg: PeLoadConfig, messages: string[]): void => {
  const merged = appendUniqueWarnings(loadcfg.warnings, messages);
  if (merged?.length) loadcfg.warnings = merged;
};

const withLayoutWarnings = <T extends PeParseResult>(result: T, fileSize: number): T => {
  const mergedWarnings = appendUniqueWarnings(result.warnings, collectPeLayoutWarnings(result, fileSize));
  return mergedWarnings?.length ? { ...result, warnings: mergedWarnings } : result;
};

export async function parsePe(file: File): Promise<PeParseResult | null> {
  const core = await parsePeHeaders(file);
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

  const debugResult = await parseDebugDirectory(file, dataDirs, rvaToOff);
  const loadcfg = await peVariant.parseLoadConfigDirectory(file, dataDirs, rvaToOff);
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
          file,
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
          file,
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
          file,
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
          file,
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
          file,
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
        file,
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
  const importResult = await peVariant.parseImportDirectory(file, dataDirs, rvaToOff);
  const exportsInfo = await parseExportDirectory(file, dataDirs, rvaToOff);
  const tls = await peVariant.parseTlsDirectory(file, dataDirs, rvaToOff, ImageBase);
  const resources = await parseResources(file, dataDirs, rvaToOff);
  const reloc = await parseBaseRelocations(file, dataDirs, rvaToOff);
  const exception = await parseExceptionDirectory(file, dataDirs, rvaToOff, coff.Machine);
  const boundImports = await parseBoundImports(file, dataDirs, rvaToOff);
  const delayImports = await peVariant.parseDelayImports(file, dataDirs, rvaToOff);
  const clr = await parseClrDirectory(file, dataDirs, rvaToOff);
  let security = await parseSecurityDirectory(file, dataDirs);
  security = addSecurityTailWarning(file.size, security, dataDirs.find(d => d.name === "SECURITY"), debugResult.rawDataRanges);
  if (security?.certs?.length) {
    const securityDir = dataDirs.find(d => d.name === "SECURITY");
    const certs = await Promise.all(
      security.certs.map(async cert => {
        if (!cert.authenticode) return cert;
        const verification = await verifyAuthenticodeFileDigest(file, core, securityDir, cert.authenticode);
        return {
          ...cert,
          authenticode: { ...cert.authenticode, verification }
        };
      })
    );
    security = { ...security, certs };
  }
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
    ...(core.warnings?.length ? { warnings: core.warnings } : {}),
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
    resources,
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    hasCert: !!security?.count,
  }, file.size);
}
