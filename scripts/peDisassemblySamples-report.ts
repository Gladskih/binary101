"use strict";

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  BuildVariant,
  FailedSampleResult,
  SampleResult,
  SampleSummary,
  SkippedSampleResult,
  SuccessfulSampleResult,
  Toolchains
} from "./peDisassemblySamples-model.js";
import { buildCommandLines } from "./peDisassemblySamples-variants.js";

const flatten = (value: string): string =>
  value.replace(/\r?\n/gu, " ").trim();

const renderSuccessRow = (result: SuccessfulSampleResult): string =>
  `| ${result.id} | ${result.language} | ${result.outputSize} | ${result.durationMs} | ${result.outputPath} |`;

const renderFailureRow = (result: FailedSampleResult): string =>
  `| ${result.id} | ${result.language} | ${result.durationMs} | ${flatten(result.error)} |`;

const renderSkippedRow = (result: SkippedSampleResult): string =>
  `| ${result.id} | ${result.language} | ${flatten(result.reason)} |`;

const toolchainLine = (name: string, value: string | null): string =>
  `${name}: ${value ?? "(missing)"}`;

export const buildSummaryMarkdown = (summary: SampleSummary): string => {
  const successes = summary.results.filter(
    (result): result is SuccessfulSampleResult => result.kind === "success"
  );
  const failures = summary.results.filter(
    (result): result is FailedSampleResult => result.kind === "failure"
  );
  const skipped = summary.results.filter(
    (result): result is SkippedSampleResult => result.kind === "skipped"
  );
  const lines = [
    "# PE disassembly samples",
    "",
    `Generated at: ${summary.generatedAt}`,
    "",
    `Output root: ${summary.outputRoot}`,
    "",
    `Attempted variants: ${summary.attemptedCount}`,
    "",
    `Successful builds: ${summary.successCount}`,
    "",
    `Failed builds: ${summary.failureCount}`,
    "",
    `Skipped builds: ${summary.skippedCount}`,
    "",
    "## Successful builds",
    "",
    "| id | language | size | ms | output |",
    "|---|---|---:|---:|---|",
    ...successes.map(renderSuccessRow)
  ];
  if (failures.length) {
    lines.push("", "## Failed builds", "", "| id | language | ms | error |", "|---|---|---:|---|");
    lines.push(...failures.map(renderFailureRow));
  }
  if (skipped.length) {
    lines.push("", "## Skipped builds", "", "| id | language | reason |", "|---|---|---|");
    lines.push(...skipped.map(renderSkippedRow));
  }
  return `${lines.join("\n")}\n`;
};

const renderToolchains = (toolchains: Toolchains): string[] => [
  toolchainLine("Visual Studio vcvarsall", toolchains.visualStudio?.vcvarsallPath ?? null),
  toolchainLine("clang", toolchains.clang),
  toolchainLine("clang-cl", toolchains.clangCl),
  toolchainLine("dmd", toolchains.dmd),
  toolchainLine("dotnet", toolchains.dotnet),
  toolchainLine("fpc", toolchains.fpc),
  toolchainLine("go", toolchains.go),
  toolchainLine("lld-link", toolchains.lldLink),
  toolchainLine("nasm", toolchains.nasm),
  toolchainLine("rustc", toolchains.rustc),
  toolchainLine("zig", toolchains.zig),
  toolchainLine("MSYS2 CLANG64 clang", toolchains.msysClang64.clang),
  toolchainLine("MSYS2 UCRT64 gcc", toolchains.msysUcrt64.gcc)
];

export const writeCommandsFile = async (
  outputRoot: string,
  toolchains: Toolchains,
  variants: BuildVariant[]
): Promise<void> => {
  const lines = [
    "# PE disassembly sample commands",
    "",
    "## Discovered toolchains",
    "",
    ...renderToolchains(toolchains),
    "",
    "## Variants",
    "",
    ...variants.flatMap(variant => [
      `# ${variant.id} (${variant.language}, ${variant.toolchain})`,
      ...(variant.skipReason ? [`# skipped: ${variant.skipReason}`] : buildCommandLines(variant)),
      ""
    ])
  ];
  await writeFile(join(outputRoot, "commands.txt"), `${lines.join("\n")}\n`, "utf8");
};

export const buildSummary = (
  outputRoot: string,
  results: SampleResult[]
): SampleSummary => ({
  generatedAt: new Date().toISOString(),
  outputRoot,
  attemptedCount: results.length,
  successCount: results.filter(result => result.kind === "success").length,
  failureCount: results.filter(result => result.kind === "failure").length,
  skippedCount: results.filter(result => result.kind === "skipped").length,
  results
});
