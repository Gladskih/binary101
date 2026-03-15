"use strict";

import { parsePeHeaders } from "./core.js";
import { verifyAuthenticodeFileDigest } from "./authenticode-verify.js";
import { parseDebugDirectory } from "./debug-directory.js";
import { parseLoadConfigDirectory, type PeLoadConfig, type PeLoadConfigTables } from "./load-config.js";
import {
  readGuardAddressTakenIatEntryTableRvas,
  readGuardCFFunctionTableRvas,
  readGuardEhContinuationTableRvas,
  readGuardLongJumpTargetTableRvas,
  readSafeSehHandlerTableRvas
} from "./load-config-tables.js";
import { collectLoadConfigWarnings } from "./load-config-warnings.js";
import { parseImportDirectory, type PeImportEntry } from "./imports.js";
import { parseExportDirectory } from "./exports.js";
import { parseTlsDirectory } from "./tls.js";
import { parseResources } from "./resources.js";
import { parseClrDirectory, type PeClrHeader } from "./clr.js";
import { parseSecurityDirectory, type ParsedSecurityDirectory } from "./security.js";
import { parseBaseRelocations } from "./reloc.js";
import { parseExceptionDirectory } from "./exception.js";
import { parseBoundImports, parseDelayImports } from "./bound-delay.js";
import { parseDynamicRelocationsFromLoadConfig } from "./dynamic-relocations.js";
import type { PeInstructionSetReport } from "./disassembly.js";
import type {
  AddCoverageRegion,
  PeCore,
  PeCoverageEntry,
  PeDataDirectory,
  PeTlsDirectory,
  RvaToOffset
} from "./types.js";

interface PeIatDirectory {
  rva: number;
  size: number;
}

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

export interface PeParseResult {
  dos: PeCore["dos"];
  signature: "PE";
  coff: PeCore["coff"];
  opt: PeCore["opt"];
  dirs: PeDataDirectory[];
  sections: PeCore["sections"];
  entrySection: PeCore["entrySection"];
  rvaToOff: RvaToOffset;
  imports: PeImportEntry[];
  importsWarning?: string;
  rsds: { guid: string; age: number; path: string } | null | undefined;
  debugWarning: string | null | undefined;
  loadcfg: PeLoadConfig | null;
  exports: Awaited<ReturnType<typeof parseExportDirectory>>;
  tls: PeTlsDirectory | null;
  reloc: Awaited<ReturnType<typeof parseBaseRelocations>>;
  exception: Awaited<ReturnType<typeof parseExceptionDirectory>>;
  boundImports: Awaited<ReturnType<typeof parseBoundImports>>;
  delayImports: Awaited<ReturnType<typeof parseDelayImports>>;
  clr: PeClrHeader | null;
  security: ParsedSecurityDirectory | null;
  iat: PeIatDirectory | null;
  resources: unknown;
  overlaySize: number;
  imageEnd: number;
  imageSizeMismatch: boolean;
  coverage: PeCoverageEntry[];
  hasCert: boolean;
  disassembly?: PeInstructionSetReport;
}

function parseIatDirectory(
  dataDirs: PeDataDirectory[],
  rvaToOff: RvaToOffset,
  addCoverageRegion: AddCoverageRegion
): PeIatDirectory | null {
  const dir = dataDirs.find(d => d.name === "IAT");
  if (!dir?.rva || !dir.size) return null;
  const off = rvaToOff(dir.rva);
  if (off == null) return null;
  addCoverageRegion("IAT", off, dir.size);
  return { rva: dir.rva, size: dir.size };
}

export async function parsePe(file: File): Promise<PeParseResult | null> {
  const core = await parsePeHeaders(file);
  if (!core) return null;
  const {
    dos,
    coff,
    opt,
    dataDirs,
    sections,
    entrySection,
    rvaToOff,
    coverage,
    addCoverageRegion,
    overlaySize,
    imageEnd,
    imageSizeMismatch
  } = core;

  const { isPlus, ImageBase } = opt;

  const { entry: rsds, warning: debugWarning } =
    (await parseDebugDirectory(file, dataDirs, rvaToOff, addCoverageRegion)) || {};
  const loadcfg = await parseLoadConfigDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus);
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
      !isPlus &&
      coff.Machine === 0x014c &&
      Number.isSafeInteger(loadcfg.SEHandlerCount) &&
      loadcfg.SEHandlerCount > 0
    ) {
      try {
        tables.safeSehHandlerRvas = await readSafeSehHandlerTableRvas(
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
      loadcfg.dynamicRelocations = await parseDynamicRelocationsFromLoadConfig(
        file,
        sections,
        rvaToOff,
        ImageBase,
        isPlus,
        loadcfg
      );
    } catch (error) {
      addLoadConfigWarning(`LOAD_CONFIG: failed to read dynamic relocations (${String(error)}).`);
      loadcfg.dynamicRelocations = null;
    }
  }
  const importResult = await parseImportDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus);
  const exportsInfo = await parseExportDirectory(file, dataDirs, rvaToOff, addCoverageRegion);
  const tls = await parseTlsDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus, ImageBase);
  const resources = await parseResources(file, dataDirs, rvaToOff, addCoverageRegion);
  const reloc = await parseBaseRelocations(file, dataDirs, rvaToOff, addCoverageRegion);
  const exception = await parseExceptionDirectory(file, dataDirs, rvaToOff, addCoverageRegion, coff.Machine);
  const boundImports = await parseBoundImports(file, dataDirs, rvaToOff, addCoverageRegion);
  const delayImports = await parseDelayImports(file, dataDirs, rvaToOff, addCoverageRegion, isPlus, ImageBase);
  const clr = await parseClrDirectory(file, dataDirs, rvaToOff, addCoverageRegion);
  let security = await parseSecurityDirectory(file, dataDirs, addCoverageRegion);
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
  const iat = parseIatDirectory(dataDirs, rvaToOff, addCoverageRegion);

  const dirs = dataDirs;

  return {
    dos,
    signature: "PE",
    coff,
    opt,
    dirs,
    sections,
    entrySection,
    rvaToOff,
    imports: importResult.entries,
    ...(importResult.warning ? { importsWarning: importResult.warning } : {}),
    rsds,
    debugWarning,
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
    resources,
    overlaySize,
    imageEnd,
    imageSizeMismatch,
    coverage,
    hasCert: !!security?.count,
  };
}
