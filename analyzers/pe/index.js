"use strict";

import { parsePeHeaders } from "./core.js";
import { parseDebugDirectory, parseLoadConfigDirectory } from "./debug-loadcfg.js";
import { parseImportDirectory } from "./imports.js";
import { parseExportDirectory } from "./exports.js";
import { parseTlsDirectory } from "./tls.js";
import { parseResources } from "./resources.js";
import { parseClrDirectory, parseSecurityDirectory } from "./clr-security.js";
import { parseBaseRelocations } from "./reloc.js";
import { parseExceptionDirectory } from "./exception.js";
import { parseBoundImports, parseDelayImports } from "./bound-delay.js";

function parseIatDirectory(dataDirs, rvaToOff, addCoverageRegion) {
  const dir = dataDirs.find(d => d.name === "IAT");
  if (!dir?.rva || !dir.size) return null;
  const off = rvaToOff(dir.rva);
  if (off == null) return null;
  addCoverageRegion("IAT", off, dir.size);
  return { rva: dir.rva, size: dir.size };
}

export async function parsePe(file) {
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
  const imports = await parseImportDirectory(file, dataDirs, rvaToOff, addCoverageRegion, isPlus);
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
    imports,
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
