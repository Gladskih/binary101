"use strict";

import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { analyzeSuccessfulBuild } from "./rustPeMatrix-analyze.js";
import {
  getHostTarget,
  getInstalledRustStdTargets,
  runCommand,
  toCommandLine,
  toRustcArgs
} from "./rustPeMatrix-command.js";
import {
  defaultOutputRoot,
  projectRoot,
  rustcExecutable,
  type FailedVariantResult,
  type SummaryFile,
  type SuccessfulVariantResult,
  type VariantResult,
  type VariantSpec
} from "./rustPeMatrix-model.js";
import { buildSummaryMarkdown, writeCommandsFile } from "./rustPeMatrix-report.js";
import {
  buildCoreVariantSpecs,
  buildExperimentalVariantSpecs,
  writeSourceFiles
} from "./rustPeMatrix-variants.js";

const writeBuildLog = async (
  variantDirectory: string,
  variant: VariantSpec,
  commandLine: string,
  buildResult: { code: number; stdout: string; stderr: string }
): Promise<void> =>
  writeFile(
    join(variantDirectory, "build.log.md"),
    [
      `# ${variant.id}`,
      "",
      `Command: ${commandLine}`,
      "",
      `Exit code: ${buildResult.code}`,
      "",
      "## stdout",
      "",
      "```text",
      buildResult.stdout.trimEnd(),
      "```",
      "",
      "## stderr",
      "",
      "```text",
      buildResult.stderr.trimEnd(),
      "```",
      ""
    ].join("\n"),
    "utf8"
  );

const buildFailureResult = (
  variant: VariantSpec,
  commandLine: string,
  durationMs: number,
  error: string
): FailedVariantResult => ({
  kind: "failure",
  id: variant.id,
  label: variant.label,
  commandLine,
  durationMs,
  error
});

const buildMissingSourceFailure = (variant: VariantSpec): FailedVariantResult =>
  buildFailureResult(variant, variant.sourceFile, 0, `Missing source file mapping for ${variant.sourceFile}.`);

const buildCommandError = (build: { code: number; stdout: string; stderr: string }): string =>
  build.stderr.trim() || build.stdout.trim() || `rustc exited with code ${build.code}`;

const compileVariant = async (
  variant: VariantSpec,
  sourcePaths: Record<string, string>,
  outputRoot: string
): Promise<VariantResult> => {
  const variantDirectory = join(outputRoot, "variants", variant.id);
  await mkdir(variantDirectory, { recursive: true });
  const sourcePath = sourcePaths[variant.sourceFile];
  if (!sourcePath) return buildMissingSourceFailure(variant);
  const outputPath = join(variantDirectory, `${variant.id}.exe`);
  const args = toRustcArgs(sourcePath, outputPath, variant);
  const commandLine = toCommandLine(rustcExecutable, args);
  const build = await runCommand(rustcExecutable, args, projectRoot);
  await writeBuildLog(variantDirectory, variant, commandLine, build);
  if (build.code !== 0) {
    return buildFailureResult(variant, commandLine, build.durationMs, buildCommandError(build));
  }
  const analysis = await analyzeSuccessfulBuild(outputPath, variantDirectory);
  const success: SuccessfulVariantResult = {
    kind: "success",
    id: variant.id,
    label: variant.label,
    commandLine,
    outputPath,
    outputSize: analysis.outputSize,
    durationMs: build.durationMs,
    analyzer: analysis.analyzer
  };
  return success;
};

const buildSummary = (
  outputRoot: string,
  hostTarget: string,
  installedRustStdTargets: string[],
  variants: VariantResult[]
): SummaryFile => ({
  generatedAt: new Date().toISOString(),
  outputRoot,
  hostTarget,
  installedRustStdTargets,
  attemptedCount: variants.length,
  successCount: variants.filter(variant => variant.kind === "success").length,
  failureCount: variants.filter(variant => variant.kind === "failure").length,
  variants
});

const main = async (): Promise<void> => {
  const outputRoot = defaultOutputRoot;
  await rm(outputRoot, { recursive: true, force: true });
  await mkdir(outputRoot, { recursive: true });
  const sourcePaths = await writeSourceFiles(join(outputRoot, "sources"));
  const hostTarget = await getHostTarget();
  const installedRustStdTargets = await getInstalledRustStdTargets();
  const variants = [...buildCoreVariantSpecs(hostTarget), ...buildExperimentalVariantSpecs(hostTarget)];
  await writeCommandsFile(outputRoot, hostTarget, variants, sourcePaths);
  const results: VariantResult[] = [];
  for (const [index, variant] of variants.entries()) {
    console.warn(`[${index + 1}/${variants.length}] ${variant.id}`);
    results.push(await compileVariant(variant, sourcePaths, outputRoot));
  }
  const summary = buildSummary(outputRoot, hostTarget, installedRustStdTargets, results);
  await writeFile(join(outputRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "summary.md"), buildSummaryMarkdown(summary), "utf8");
  console.warn(`Wrote matrix output to ${outputRoot}`);
};

void main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
