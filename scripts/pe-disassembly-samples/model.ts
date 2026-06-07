"use strict";

import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = resolve(fileURLToPath(new URL(".", import.meta.url)));

export const projectRoot = resolve(scriptDirectory, "..", "..");
export const sampleSourceRoot = join(projectRoot, "samples", "pe-disassembly");
export const defaultOutputRoot = join(
  process.env["TEMP"] ?? projectRoot,
  "binary101-pe-disassembly-samples"
);

export type SampleLanguage =
  | "assembly"
  | "c"
  | "cpp"
  | "csharp"
  | "d"
  | "go"
  | "pascal"
  | "rust"
  | "zig";

export interface VisualStudioToolchain {
  installationPath: string;
  vcvarsallPath: string;
}

export interface MsysToolchain {
  binDirectory: string | null;
  gcc: string | null;
  gxx: string | null;
  clang: string | null;
  clangxx: string | null;
  lldLink: string | null;
}

export interface Toolchains {
  clang: string | null;
  clangxx: string | null;
  clangCl: string | null;
  dmd: string | null;
  dotnet: string | null;
  fpc: string | null;
  go: string | null;
  lldLink: string | null;
  nasm: string | null;
  rustc: string | null;
  rustI686GnuLinker: string | null;
  rustI686GnullvmLinker: string | null;
  visualStudio: VisualStudioToolchain | null;
  zig: string | null;
  msysClang64: MsysToolchain;
  msysUcrt64: MsysToolchain;
}

export interface SampleSources {
  assemblyMasmX64: string;
  assemblyMasmX86: string;
  assemblyNasmX64: string;
  assemblyNasmX86: string;
  c: string;
  cpp: string;
  csharpProject: string;
  d: string;
  go: string;
  pascal: string;
  rust: string;
  zig: string;
}

export interface BuildStep {
  label: string;
  executable: string;
  args: string[];
  cwd: string;
  display?: string;
  env?: Record<string, string>;
  windowsVerbatimArguments?: boolean;
}

export interface BuildVariant {
  id: string;
  label: string;
  language: SampleLanguage;
  outputPath: string;
  steps: BuildStep[];
  toolchain: string;
  notes?: string[];
  skipReason?: string;
}

export interface StepResult {
  code: number;
  durationMs: number;
  label: string;
  stderr: string;
  stdout: string;
}

export interface SuccessfulSampleResult {
  kind: "success";
  id: string;
  label: string;
  language: SampleLanguage;
  outputPath: string;
  outputSize: number;
  durationMs: number;
  commandLines: string[];
  steps: StepResult[];
}

export interface FailedSampleResult {
  kind: "failure";
  id: string;
  label: string;
  language: SampleLanguage;
  durationMs: number;
  commandLines: string[];
  error: string;
  steps: StepResult[];
}

export interface SkippedSampleResult {
  kind: "skipped";
  id: string;
  label: string;
  language: SampleLanguage;
  commandLines: string[];
  reason: string;
}

export type SampleResult = FailedSampleResult | SkippedSampleResult | SuccessfulSampleResult;

export interface SampleSummary {
  generatedAt: string;
  outputRoot: string;
  attemptedCount: number;
  successCount: number;
  failureCount: number;
  skippedCount: number;
  results: SampleResult[];
}
