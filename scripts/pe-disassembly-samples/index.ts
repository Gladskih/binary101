"use strict";

import { mkdir, rm, stat, writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  defaultOutputRoot,
  projectRoot,
  sampleSourceRoot,
  type BuildVariant,
  type SampleResult,
  type StepResult
} from "./model.js";
import { getStepCommandLine, runStep } from "./command.js";
import { buildSummary, buildSummaryMarkdown, writeCommandsFile } from "./report.js";
import { discoverToolchains } from "./toolchains.js";
import { validateNoPeCoffSymbolRecords } from "./pe-coff-symbols.js";
import { buildBinarySizeMarkdown } from "./size-table.js";
import { buildSampleVariants, buildCommandLines } from "./variants.js";

interface CliConfig {
  dryRun: boolean;
  filters: string[];
  jobs: number;
  outputRoot: string;
  sizeTablePath: string | null;
}

const parseCliConfig = (args: string[]): CliConfig => {
  const config: CliConfig = {
    dryRun: false,
    filters: [],
    jobs: Math.max(1, Math.min(availableParallelism(), 8)),
    outputRoot: defaultOutputRoot,
    sizeTablePath: null
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--dry-run") config.dryRun = true;
    if (arg === "--output") config.outputRoot = resolve(args[index += 1] ?? defaultOutputRoot);
    if (arg === "--jobs") config.jobs = Math.max(1, Number.parseInt(args[index += 1] ?? "1", 10));
    if (arg === "--filter") config.filters.push(...(args[index += 1] ?? "").split(",").filter(Boolean));
    if (arg === "--size-table") {
      config.sizeTablePath = resolve(args[index += 1] ?? join(sampleSourceRoot, "BINARY-SIZES.md"));
    }
  }
  return config;
};

const filterVariants = (variants: BuildVariant[], filters: string[]): BuildVariant[] =>
  filters.length ? variants.filter(variant => filters.some(filter => variant.id.includes(filter))) : variants;

const writeBuildLog = async (
  variant: BuildVariant,
  result: SampleResult
): Promise<void> => {
  const lines = [
    `# ${variant.id}`,
    "",
    ...buildCommandLines(variant).flatMap(command => ["Command:", "", command, ""]),
    `Result: ${result.kind}`,
    ""
  ];
  if (result.kind === "failure") lines.push("Error:", "", result.error, "");
  if (result.kind === "skipped") lines.push("Reason:", "", result.reason, "");
  if (result.kind !== "skipped") {
    for (const step of result.steps) {
      lines.push(`## ${step.label}`, "", `Exit code: ${step.code}`, "", "### stdout", "", "```text");
      lines.push(step.stdout.trimEnd(), "```", "", "### stderr", "", "```text", step.stderr.trimEnd(), "```", "");
    }
  }
  await writeFile(join(dirname(variant.outputPath), "build.log.md"), `${lines.join("\n")}\n`, "utf8");
};

const buildSkippedResult = (variant: BuildVariant, reason: string): SampleResult => ({
  kind: "skipped",
  id: variant.id,
  label: variant.label,
  language: variant.language,
  sizeTableColumns: variant.sizeTableColumns,
  commandLines: buildCommandLines(variant),
  reason
});

const buildFailureResult = (
  variant: BuildVariant,
  durationMs: number,
  steps: StepResult[],
  error: string
): SampleResult => ({
  kind: "failure",
  id: variant.id,
  label: variant.label,
  language: variant.language,
  sizeTableColumns: variant.sizeTableColumns,
  durationMs,
  commandLines: buildCommandLines(variant),
  error,
  steps
});

const getFailureError = (step: { code: number; stderr: string; stdout: string }): string =>
  step.stderr.trim() || step.stdout.trim() || `step exited with code ${step.code}`;

const compileVariant = async (variant: BuildVariant): Promise<SampleResult> => {
  await mkdir(dirname(variant.outputPath), { recursive: true });
  if (variant.skipReason) return buildSkippedResult(variant, variant.skipReason);
  const steps: StepResult[] = [];
  let durationMs = 0;
  for (const step of variant.steps) {
    const result = await runStep({ ...step, cwd: step.cwd || projectRoot });
    steps.push(result);
    durationMs += result.durationMs;
    if (result.code !== 0) return buildFailureResult(variant, durationMs, steps, getFailureError(result));
  }
  const output = await stat(variant.outputPath).catch(() => null);
  if (!output) return buildFailureResult(variant, durationMs, steps, `Output file was not created: ${variant.outputPath}`);
  const symbolResult = await validateNoPeCoffSymbolRecords(variant.outputPath);
  if (symbolResult.warnings.length) {
    steps.push({
      code: 0,
      durationMs: 0,
      label: "inspect PE COFF symbols",
      stderr: "",
      stdout: `${symbolResult.warnings.join("\n")}\n`
    });
  }
  if (symbolResult.error) return buildFailureResult(variant, durationMs, steps, symbolResult.error);
  return {
    kind: "success",
    id: variant.id,
    label: variant.label,
    language: variant.language,
    outputPath: variant.outputPath,
    outputSize: output.size,
    sizeTableColumns: variant.sizeTableColumns,
    durationMs,
    commandLines: variant.steps.map(getStepCommandLine),
    steps
  };
};

const runLimited = async (
  variants: BuildVariant[],
  jobs: number,
  worker: (variant: BuildVariant, index: number) => Promise<SampleResult>
): Promise<SampleResult[]> => {
  const results: SampleResult[] = new Array(variants.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(jobs, variants.length) }, async () => {
    while (nextIndex < variants.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await worker(variants[index]!, index);
    }
  });
  await Promise.all(workers);
  return results;
};

const runVariant = async (
  variant: BuildVariant,
  index: number,
  total: number
): Promise<SampleResult> => {
  console.warn(`[${index + 1}/${total}] ${variant.id}`);
  const result = await compileVariant(variant);
  await writeBuildLog(variant, result);
  return result;
};

const writeSummaryFiles = async (
  outputRoot: string,
  results: SampleResult[],
  sizeTablePath: string | null
): Promise<void> => {
  const summary = buildSummary(outputRoot, results);
  const binarySizeMarkdown = buildBinarySizeMarkdown(summary);
  await writeFile(join(outputRoot, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await writeFile(join(outputRoot, "summary.md"), buildSummaryMarkdown(summary), "utf8");
  await writeFile(join(outputRoot, "binary-sizes.md"), binarySizeMarkdown, "utf8");
  if (sizeTablePath) await writeFile(sizeTablePath, binarySizeMarkdown, "utf8");
};

const main = async (): Promise<void> => {
  const config = parseCliConfig(process.argv.slice(2));
  await rm(config.outputRoot, { recursive: true, force: true });
  await mkdir(config.outputRoot, { recursive: true });
  const toolchains = await discoverToolchains();
  const variants = filterVariants(buildSampleVariants(toolchains, config.outputRoot), config.filters);
  await writeCommandsFile(config.outputRoot, toolchains, variants);
  if (config.dryRun) {
    await writeSummaryFiles(
      config.outputRoot,
      variants.map(variant => buildSkippedResult(variant, "dry run")),
      config.sizeTablePath
    );
    console.warn(`Wrote dry-run commands to ${config.outputRoot}`);
    return;
  }
  const results = await runLimited(variants, config.jobs, (variant, index) =>
    runVariant(variant, index, variants.length)
  );
  await writeSummaryFiles(config.outputRoot, results, config.sizeTablePath);
  console.warn(`Wrote PE disassembly samples to ${config.outputRoot}`);
};

void main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
