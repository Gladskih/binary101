"use strict";

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DEFAULT_BATCH_SIZE,
  DEFAULT_FILE_EXE,
  defaultWorkerCount,
  scanFileTypes,
  type ScanOptions,
  type ScanSummary
} from "./file-type-disk-scan/scan.js";
import { discoverFiles, existingDefaultRoots, type WarningSink } from "./file-type-disk-scan/discovery.js";

type CliOptions = ScanOptions & {
  maxMinutes: number;
  sampleFiles: number;
  estimateOnly: boolean;
};

const DEFAULT_OUTPUT_PATH = "test-results/file-type-mismatches.jsonl";
const DEFAULT_SUMMARY_PATH = "test-results/file-type-scan-summary.json";
const DEFAULT_MAX_MINUTES = 15;
const DEFAULT_SAMPLE_FILES = 1000;
const HELP_TEXT =
  "Usage: npm run scan:file-types -- [--root <path> ...] [--out <jsonl>] " +
  "[--summary <json>] [--limit <n>] [--workers <n>] [--batch-size <n>] " +
  "[--sample-files <n>] [--max-minutes <n>] [--estimate-only] [--file-exe <path>]";

const requiredValue = (args: string[], index: number, name: string): string => {
  const value = args[index + 1];
  if (!value) throw new Error(`${name} requires a value.`);
  return value;
};

const readPositiveInteger = (value: string, name: string): number => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} requires a positive integer.`);
  return parsed;
};

const readPositiveNumber = (value: string, name: string): number => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`${name} requires a positive number.`);
  return parsed;
};

const parseScanArguments = async (args: string[]): Promise<CliOptions | null> => {
  const roots: string[] = [];
  let outputPath = DEFAULT_OUTPUT_PATH;
  let summaryPath = DEFAULT_SUMMARY_PATH;
  let fileExePath = DEFAULT_FILE_EXE;
  let workerCount = defaultWorkerCount();
  let batchSize = DEFAULT_BATCH_SIZE;
  let fileLimit: number | null = null;
  let maxMinutes = DEFAULT_MAX_MINUTES;
  let sampleFiles = DEFAULT_SAMPLE_FILES;
  let estimateOnly = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") return null;
    if (arg === "--root") roots.push(resolve(requiredValue(args, index++, "--root")));
    else if (arg === "--out") outputPath = resolve(requiredValue(args, index++, "--out"));
    else if (arg === "--summary") summaryPath = resolve(requiredValue(args, index++, "--summary"));
    else if (arg === "--file-exe") fileExePath = resolve(requiredValue(args, index++, "--file-exe"));
    else if (arg === "--workers") workerCount = readPositiveInteger(requiredValue(args, index++, "--workers"), "--workers");
    else if (arg === "--batch-size") batchSize = readPositiveInteger(requiredValue(args, index++, "--batch-size"), "--batch-size");
    else if (arg === "--limit") fileLimit = readPositiveInteger(requiredValue(args, index++, "--limit"), "--limit");
    else if (arg === "--sample-files") sampleFiles = readPositiveInteger(requiredValue(args, index++, "--sample-files"), "--sample-files");
    else if (arg === "--max-minutes") maxMinutes = readPositiveNumber(requiredValue(args, index++, "--max-minutes"), "--max-minutes");
    else if (arg === "--estimate-only") estimateOnly = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return {
    roots: roots.length ? roots : await existingDefaultRoots(),
    outputPath: resolve(outputPath),
    summaryPath: resolve(summaryPath),
    fileExePath,
    workerCount,
    batchSize,
    fileLimit,
    maxMinutes,
    sampleFiles,
    estimateOnly
  };
};

const countFiles = async (options: CliOptions): Promise<{ totalFiles: number; durationMs: number }> => {
  const started = Date.now();
  const warnings: WarningSink = { count: 0, messages: [] };
  let totalFiles = 0;
  await discoverFiles(options.roots, options.workerCount, async () => {
    totalFiles += 1;
    return true;
  }, warnings);
  return { totalFiles, durationMs: Date.now() - started };
};

const formatMinutes = (milliseconds: number): string => (milliseconds / 60000).toFixed(2);

const writeEstimateSummary = async (
  options: CliOptions,
  sample: ScanSummary,
  totalFiles: number,
  countDurationMs: number,
  estimatedDurationMs: number
): Promise<void> => {
  await mkdir(dirname(options.summaryPath), { recursive: true });
  await writeFile(options.summaryPath, `${JSON.stringify({
    roots: options.roots,
    outputPath: options.outputPath,
    estimateOnly: options.estimateOnly,
    totalFiles,
    countDurationMs,
    sample,
    estimatedDurationMs,
    estimatedMinutes: Number(formatMinutes(estimatedDurationMs)),
    maxMinutes: options.maxMinutes,
    willRunFullScan: !options.estimateOnly && estimatedDurationMs <= options.maxMinutes * 60000
  }, null, 2)}\n`, "utf8");
};

const printSummary = (summary: ScanSummary): void => {
  process.stdout.write(
    `Scanned ${summary.totals.filesScanned}/${summary.totals.filesDiscovered} file(s), ` +
    `${summary.totals.analyzerAdvantages} analyzer advantage(s), ` +
    `${summary.totals.mismatches} mismatch(es), ${summary.warningCount} warning(s): ` +
    `${summary.outputPath}\n`
  );
};

const runGuardedFullScan = async (options: CliOptions): Promise<void> => {
  const sample = await scanFileTypes({
    ...options,
    outputPath: `${options.outputPath}.sample.jsonl`,
    summaryPath: `${options.summaryPath}.sample.json`,
    fileLimit: options.sampleFiles
  });
  const { totalFiles, durationMs } = await countFiles(options);
  const measuredFiles = Math.max(1, sample.totals.filesScanned);
  const estimatedDurationMs = durationMs + (sample.durationMs / measuredFiles) * totalFiles;
  await writeEstimateSummary(options, sample, totalFiles, durationMs, estimatedDurationMs);
  process.stdout.write(
    `Estimated full scan time: ${formatMinutes(estimatedDurationMs)} minute(s) ` +
    `for ${totalFiles} file(s).\n`
  );
  if (options.estimateOnly || estimatedDurationMs > options.maxMinutes * 60000) return;
  printSummary(await scanFileTypes(options));
};

const main = async (): Promise<void> => {
  const options = await parseScanArguments(process.argv.slice(2));
  if (!options) {
    process.stdout.write(`${HELP_TEXT}\n`);
    return;
  }
  if (options.fileLimit != null) {
    printSummary(await scanFileTypes(options));
    return;
  }
  await runGuardedFullScan(options);
};

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch(error => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

export { parseScanArguments };
