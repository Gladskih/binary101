"use strict";

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  isPeWindowsParseResult,
  parsePe,
  type PeParseResult,
  type PeWindowsParseResult
} from "../analyzers/pe/index.js";
import { peSectionNameValue } from "../analyzers/pe/section-name.js";
import { renderPe } from "../renderers/pe/index.js";
import type { AnalyzerSummary, SuccessfulVariantResult } from "./rustPeMatrix-model.js";

const sanitizeParseResult = (value: PeParseResult): unknown =>
  JSON.parse(
    JSON.stringify(value, (_key, entry) => {
      if (typeof entry === "bigint") return `${entry}n`;
      if (typeof entry === "function") return undefined;
      return entry;
    })
  );

const collectDataDirectoryNames = (pe: PeParseResult): string[] =>
  pe.dirs
    .filter(directory => directory.rva !== 0 || directory.size !== 0)
    .map(directory => directory.name);

const collectImportFunctionNames = (pe: PeWindowsParseResult): string[] =>
  pe.imports.entries
    .flatMap(entry =>
      entry.functions.map(fn => {
        if (fn.name) return `${entry.dll}!${fn.name}`;
        return `${entry.dll}!#${fn.ordinal ?? 0}`;
      })
    )
    .sort();

const summarizeAnalyzerResult = (pe: PeWindowsParseResult, html: string): AnalyzerSummary => ({
  machine: pe.coff.Machine,
  optionalMagic: pe.opt.Magic,
  subsystem: "Subsystem" in pe.opt ? pe.opt.Subsystem : null,
  dllCharacteristics: "DllCharacteristics" in pe.opt ? pe.opt.DllCharacteristics : null,
  imageBase: "ImageBase" in pe.opt ? pe.opt.ImageBase.toString() : null,
  sectionAlignment: "SectionAlignment" in pe.opt ? pe.opt.SectionAlignment : null,
  fileAlignment: "FileAlignment" in pe.opt ? pe.opt.FileAlignment : null,
  sizeOfImage: "SizeOfImage" in pe.opt ? pe.opt.SizeOfImage : null,
  sizeOfHeaders: "SizeOfHeaders" in pe.opt ? pe.opt.SizeOfHeaders : null,
  stackReserve: "SizeOfStackReserve" in pe.opt ? pe.opt.SizeOfStackReserve.toString() : null,
  stackCommit: "SizeOfStackCommit" in pe.opt ? pe.opt.SizeOfStackCommit.toString() : null,
  heapReserve: "SizeOfHeapReserve" in pe.opt ? pe.opt.SizeOfHeapReserve.toString() : null,
  heapCommit: "SizeOfHeapCommit" in pe.opt ? pe.opt.SizeOfHeapCommit.toString() : null,
  entryPointRva: pe.opt.AddressOfEntryPoint,
  entrySection: pe.entrySection?.name ?? null,
  dataDirectories: collectDataDirectoryNames(pe),
  sectionNames: pe.sections.map(section => peSectionNameValue(section.name)),
  warningCount: pe.warnings?.length ?? 0,
  warnings: pe.warnings ?? [],
  debugWarning: pe.debug?.warning ?? null,
  overlaySize: pe.overlaySize,
  trailingAlignmentPaddingSize: pe.trailingAlignmentPaddingSize ?? 0,
  coffSymbolRecords: pe.coff.NumberOfSymbols,
  coffStringTableSize: pe.coffStringTableSize ?? 0,
  importDllCount: pe.imports.entries.length,
  importDllNames: pe.imports.entries.map(entry => entry.dll).sort(),
  importFunctionCount: pe.imports.entries.reduce((sum, entry) => sum + entry.functions.length, 0),
  importFunctionNames: collectImportFunctionNames(pe),
  tlsCallbackCount: pe.tls?.CallbackCount ?? 0,
  hasLegacyCoffTailUi: html.includes("Legacy COFF tail"),
  hasOverlayWarningUi: html.includes("Overlay after last section"),
  sanityCleanUi: html.includes("No obvious structural issues detected.")
});

export const analyzeSuccessfulBuild = async (
  binaryPath: string,
  variantDir: string
): Promise<Pick<SuccessfulVariantResult, "outputSize" | "analyzer">> => {
  const fileBytes = await readFile(binaryPath);
  const file = new File([fileBytes], binaryPath, {
    type: "application/vnd.microsoft.portable-executable"
  });
  const pe = await parsePe(file);
  if (!pe) throw new Error("parsePe returned null for a freshly built .exe.");
  if (!isPeWindowsParseResult(pe)) {
    throw new Error("parsePe returned a non-Windows PE result for a freshly built .exe.");
  }
  const html = renderPe(pe);
  await writeFile(join(variantDir, "parse.json"), `${JSON.stringify(sanitizeParseResult(pe), null, 2)}\n`, "utf8");
  await writeFile(join(variantDir, "rendered.html"), html, "utf8");
  return {
    outputSize: fileBytes.byteLength,
    analyzer: summarizeAnalyzerResult(pe, html)
  };
};
