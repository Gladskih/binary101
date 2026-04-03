"use strict";

import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import type {
  FailedVariantResult,
  SummaryFile,
  SuccessfulVariantResult,
  VariantSpec
} from "./rustPeMatrix-model.js";
import { rustcExecutable } from "./rustPeMatrix-model.js";
import { toCommandLine, toRustcArgs } from "./rustPeMatrix-command.js";

const renderSuccessfulRow = (variant: SuccessfulVariantResult): string =>
  `| ${variant.id} | ${variant.outputSize} | ${variant.analyzer.warningCount} | ` +
  `${variant.analyzer.sectionNames.length} | ${variant.analyzer.hasLegacyCoffTailUi ? "yes" : "no"} | ` +
  `${variant.analyzer.sanityCleanUi ? "yes" : "no"} |`;

const renderFailureRow = (variant: FailedVariantResult): string =>
  `| ${variant.id} | ${variant.error.replace(/\r?\n/gu, " ")} |`;

export const buildSummaryMarkdown = (summary: SummaryFile): string => {
  const successfulVariants = summary.variants.filter(
    (variant): variant is SuccessfulVariantResult => variant.kind === "success"
  );
  const failedVariants = summary.variants.filter(
    (variant): variant is FailedVariantResult => variant.kind === "failure"
  );
  const lines = [
    "# Rust PE matrix",
    "",
    `Generated at: ${summary.generatedAt}`,
    "",
    `Output root: ${summary.outputRoot}`,
    "",
    `Host target: ${summary.hostTarget}`,
    "",
    `Installed Rust std targets: ${summary.installedRustStdTargets.join(", ") || "(none detected)"}`,
    "",
    `Attempted variants: ${summary.attemptedCount}`,
    "",
    `Successful builds: ${summary.successCount}`,
    "",
    `Failed builds: ${summary.failureCount}`,
    "",
    "## Successful builds",
    "",
    "| id | size | warnings | sections | legacy COFF tail | sanity clean |",
    "|---|---:|---:|---:|---|---|",
    ...successfulVariants.map(renderSuccessfulRow)
  ];
  if (!failedVariants.length) return `${lines.join("\n")}\n`;
  return `${[
    ...lines,
    "",
    "## Failed builds",
    "",
    "| id | error |",
    "|---|---|",
    ...failedVariants.map(renderFailureRow)
  ].join("\n")}\n`;
};

const buildVariantCommandLine = (
  outputRoot: string,
  variant: VariantSpec,
  sourcePaths: Record<string, string>
): string => {
  const sourcePath = sourcePaths[variant.sourceFile];
  if (!sourcePath) return `${variant.sourceFile} (missing source path)`;
  const outputPath = join(outputRoot, "variants", variant.id, `${variant.id}.exe`);
  return toCommandLine(rustcExecutable, toRustcArgs(sourcePath, outputPath, variant));
};

export const writeCommandsFile = async (
  outputRoot: string,
  hostTarget: string,
  variants: VariantSpec[],
  sourcePaths: Record<string, string>
): Promise<void> => {
  const lines = [
    "rustc -vV",
    "rustc --print sysroot",
    `# detected host target: ${hostTarget}`,
    "",
    ...variants.map(variant => buildVariantCommandLine(outputRoot, variant, sourcePaths))
  ];
  await writeFile(join(outputRoot, "commands.txt"), `${lines.join("\n")}\n`, "utf8");
};
