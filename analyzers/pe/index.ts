"use strict";

import { parsePeHeaders } from "./core.js";
import { parseDebugDirectory, parseLoadConfigDirectory, type PeLoadConfig } from "./debug-loadcfg.js";
import { parseImportDirectory, type PeImportEntry } from "./imports.js";
import { parseExportDirectory } from "./exports.js";
import { parseTlsDirectory } from "./tls.js";
import { parseResources } from "./resources.js";
import { parseClrDirectory, type PeClrHeader } from "./clr.js";
import { parseSecurityDirectory, type ParsedSecurityDirectory } from "./security.js";
import { parseBaseRelocations } from "./reloc.js";
import { parseExceptionDirectory } from "./exception.js";
import { parseBoundImports, parseDelayImports } from "./bound-delay.js";
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
  const importResult = await parseImportDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus);
  const exportsInfo = await parseExportDirectory(file, dataDirs, rvaToOff, addCoverageRegion);
  const tls = await parseTlsDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus, ImageBase);
  const resources = await parseResources(file, dataDirs, rvaToOff, addCoverageRegion);
  const reloc = await parseBaseRelocations(file, dataDirs, rvaToOff, addCoverageRegion);
  const exception = await parseExceptionDirectory(file, dataDirs, rvaToOff, addCoverageRegion);
  const boundImports = await parseBoundImports(file, dataDirs, rvaToOff, addCoverageRegion);
  const delayImports = await parseDelayImports(file, dataDirs, rvaToOff, addCoverageRegion, isPlus, ImageBase);
  const clr = await parseClrDirectory(file, dataDirs, rvaToOff, addCoverageRegion);
  const security = await parseSecurityDirectory(file, dataDirs, addCoverageRegion);
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
    hasCert: !!security?.count
  };
}
