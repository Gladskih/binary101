"use strict";
import { parsePeHeaders } from "./core.js";
import { verifyAuthenticodeFileDigest } from "./authenticode-verify.js";
import { parseDebugDirectory, type PeCodeViewEntry, type PeDebugDirectoryEntry } from "./debug-directory.js";
import { parseLoadConfigDirectory32, parseLoadConfigDirectory64, type PeLoadConfig, type PeLoadConfigTables } from "./load-config/index.js";
import {
  readGuardAddressTakenIatEntryTableRvas,
  readGuardCFFunctionTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas, readSafeSehHandlerTableRvas
} from "./load-config/tables.js";
import { collectLoadConfigWarnings } from "./load-config/warnings.js";
import { parseImportDirectory32, parseImportDirectory64, type PeImportParseResult } from "./imports.js";
import { parseExportDirectory } from "./exports.js";
import { parseTlsDirectory32, parseTlsDirectory64 } from "./tls.js";
import { parseResources, type PeResources } from "./resources/index.js";
import { parseClrDirectory, type PeClrHeader } from "./clr/index.js";
import { parseSecurityDirectory, type ParsedSecurityDirectory } from "./security.js";
import { addSecurityTailWarning } from "./security-tail-warning.js";
import { parseBaseRelocations } from "./reloc.js";
import { parseExceptionDirectory } from "./exception.js";
import { parseBoundImports } from "./bound-imports.js";
import { parseDelayImports32, parseDelayImports64 } from "./delay-imports.js";
import { parseDynamicRelocationsFromLoadConfig32, parseDynamicRelocationsFromLoadConfig64 } from "./dynamic-relocations.js";
import { parseIatDirectory, type PeIatDirectory } from "./iat-directory.js";
import { parseArchitectureDirectory, type PeArchitectureDirectory } from "./architecture-directory.js";
import { parseGlobalPtrDirectory, type PeGlobalPtrDirectory } from "./globalptr-directory.js";
import { buildHeaderOnlyPeParseResult } from "./header-only-result.js";
import { isPePlusOptionalHeader, isPeWindowsOptionalHeader } from "./optional-header-kind.js";
import type { PeInstructionSetReport } from "./disassembly.js";
import type { PeCore, PeDataDirectory, PeTlsDirectory, RvaToOffset } from "./types.js";

// Microsoft PE format, "Machine Types":
// IMAGE_FILE_MACHINE_I386 is the only PE32 machine where SafeSEH applies.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types
const IMAGE_FILE_MACHINE_I386 = 0x014c;

const appendUniqueWarnings = (
  existing: string[] | undefined,
  messages: string[]
): string[] | undefined => {
  if (!messages.length) return existing;
  const merged = new Set(existing ?? []);
  messages.forEach(message => merged.add(message));
  return [...merged];
};

const mergeLoadConfigWarnings = (loadcfg: PeLoadConfig, messages: string[]): void => {
  const merged = appendUniqueWarnings(loadcfg.warnings, messages);
  if (merged?.length) loadcfg.warnings = merged;
};

export interface PeDebugSection {
  entry: PeCodeViewEntry | null;
  entries?: PeDebugDirectoryEntry[];
  warning?: string;
  rawDataRanges?: Array<{ start: number; end: number }>;
}

export interface PeParseResult {
  debug: PeDebugSection | null;
  dos: PeCore["dos"];
  signature: "PE";
  coff: PeCore["coff"];
  opt: PeCore["opt"];
  warnings?: string[];
  dirs: PeDataDirectory[];
  sections: PeCore["sections"];
  entrySection: PeCore["entrySection"];
  rvaToOff: RvaToOffset;
  imports: PeImportParseResult;
  loadcfg: PeLoadConfig | null;
  exports: Awaited<ReturnType<typeof parseExportDirectory>>;
  tls: PeTlsDirectory | null;
  reloc: Awaited<ReturnType<typeof parseBaseRelocations>>;
  exception: Awaited<ReturnType<typeof parseExceptionDirectory>>;
  boundImports: Awaited<ReturnType<typeof parseBoundImports>>;
  delayImports: Awaited<ReturnType<typeof parseDelayImports32>>;
  clr: PeClrHeader | null;
  security: ParsedSecurityDirectory | null;
  iat: PeIatDirectory | null;
  architecture?: PeArchitectureDirectory | null;
  globalPtr?: PeGlobalPtrDirectory | null;
  resources: PeResources | null;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
  hasCert: boolean;
  disassembly?: PeInstructionSetReport;
}

export async function parsePe(file: File): Promise<PeParseResult | null> {
  const core = await parsePeHeaders(file);
  if (!core) return null;
  const { dos, coff, opt, dataDirs, sections, entrySection, rvaToOff, overlaySize, imageEnd, imageSizeMismatch } = core;
  if (!isPeWindowsOptionalHeader(opt)) return buildHeaderOnlyPeParseResult(core);
  const { ImageBase } = opt;
  const peVariant = isPePlusOptionalHeader(opt)
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
  const architecture = parseArchitectureDirectory(dataDirs);
  const globalPtr = parseGlobalPtrDirectory(dataDirs, rvaToOff);
  return {
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
    architecture,
    globalPtr,
    resources,
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    hasCert: !!security?.count,
  };
}
