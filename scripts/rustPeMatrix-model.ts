"use strict";

import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = resolve(fileURLToPath(new URL(".", import.meta.url)));

export const projectRoot = resolve(scriptDirectory, "..");
export const rustcExecutable = "rustc";

export const defaultOutputRoot = join(
  process.env["TEMP"] ?? projectRoot,
  "binary101-rust-hello-bin",
  "matrix"
);

export interface VariantSpec {
  id: string;
  label: string;
  sourceFile: string;
  target: string;
  rustcArgs: string[];
  notes?: string[];
}

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
  durationMs: number;
}

export interface AnalyzerSummary {
  machine: number;
  optionalMagic: number;
  subsystem: number | null;
  dllCharacteristics: number | null;
  imageBase: string | null;
  sectionAlignment: number | null;
  fileAlignment: number | null;
  sizeOfImage: number | null;
  sizeOfHeaders: number | null;
  stackReserve: string | null;
  stackCommit: string | null;
  heapReserve: string | null;
  heapCommit: string | null;
  entryPointRva: number;
  entrySection: string | null;
  dataDirectories: string[];
  sectionNames: string[];
  warningCount: number;
  warnings: string[];
  debugWarning: string | null;
  overlaySize: number;
  trailingAlignmentPaddingSize: number;
  coffSymbolRecords: number;
  coffStringTableSize: number;
  importDllCount: number;
  importDllNames: string[];
  importFunctionCount: number;
  importFunctionNames: string[];
  tlsCallbackCount: number;
  hasLegacyCoffTailUi: boolean;
  hasOverlayWarningUi: boolean;
  sanityCleanUi: boolean;
}

export interface SuccessfulVariantResult {
  kind: "success";
  id: string;
  label: string;
  commandLine: string;
  outputPath: string;
  outputSize: number;
  durationMs: number;
  analyzer: AnalyzerSummary;
}

export interface FailedVariantResult {
  kind: "failure";
  id: string;
  label: string;
  commandLine: string;
  durationMs: number;
  error: string;
}

export type VariantResult = SuccessfulVariantResult | FailedVariantResult;

export interface SummaryFile {
  generatedAt: string;
  outputRoot: string;
  hostTarget: string;
  installedRustStdTargets: string[];
  attemptedCount: number;
  successCount: number;
  failureCount: number;
  variants: VariantResult[];
}
