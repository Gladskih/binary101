"use strict";

import { mkdir, stat, writeFile } from "node:fs/promises";
import { dirname, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanPeImportMetadata } from "./pe-import-metadata-scan/analysis.js";
import type { ScanOptions, ScanReport } from "./pe-import-metadata-scan/report-model.js";

const DEFAULT_REPORT_PATH = "test-results/pe-import-metadata-scan.json";
const HELP_TEXT =
  "Usage: npm run scan:pe-import-metadata -- [--root <path> ...] [--out <report.json>] " +
  "[--max-pe <n>] [--max-entrypoints <n>]";

const existingDefaultRoots = async (): Promise<string[]> => {
  if (process.platform !== "win32") return [parse(process.cwd()).root || "/"];
  const roots: string[] = [];
  for (const letter of "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
    try {
      if ((await stat(`${letter}:\\`)).isDirectory()) roots.push(`${letter}:\\`);
    } catch {
      // Missing drive letters are expected on Windows hosts.
    }
  }
  return roots.length ? roots : [parse(process.cwd()).root];
};

const readNonNegativeInteger = (value: string | undefined, name: string): number => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new Error(`${name} requires a non-negative integer.`);
  return parsed;
};

const requiredValue = (args: string[], index: number, name: string): string => {
  const value = args[index + 1];
  if (!value) throw new Error(`${name} requires a value.`);
  return value;
};

export const parseScanArguments = async (args: string[]): Promise<ScanOptions | null> => {
  const roots: string[] = [];
  let outputPath = DEFAULT_REPORT_PATH;
  let maxPeFiles: number | null = null;
  let maxEntrypoints = 200;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--help" || arg === "-h") return null;
    if (arg === "--root") {
      roots.push(resolve(requiredValue(args, index, "--root")));
      index += 1;
    } else if (arg === "--out") {
      outputPath = resolve(requiredValue(args, index, "--out"));
      index += 1;
    } else if (arg === "--max-pe") {
      maxPeFiles = readNonNegativeInteger(requiredValue(args, index, "--max-pe"), "--max-pe");
      index += 1;
    } else if (arg === "--max-entrypoints") {
      maxEntrypoints = readNonNegativeInteger(requiredValue(args, index, "--max-entrypoints"), "--max-entrypoints");
      index += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return {
    roots: roots.length ? roots : await existingDefaultRoots(),
    outputPath: resolve(outputPath),
    maxPeFiles,
    maxEntrypoints
  };
};

const printSummary = (report: ScanReport, outputPath: string): void => {
  process.stdout.write(
    `Wrote PE import metadata scan for ${report.totals.x86PeFiles} x86 PE file(s), ` +
    `${report.totals.metadataMatched}/${report.totals.namedImportFunctions} named import(s) matched, ` +
    `${report.totals.cleanupComplete}/${report.totals.cleanupCandidates} cleanup candidate(s) complete: ` +
    `${outputPath}\n`
  );
};

const main = async (): Promise<void> => {
  const options = await parseScanArguments(process.argv.slice(2));
  if (!options) {
    process.stdout.write(`${HELP_TEXT}\n`);
    return;
  }
  const report = await scanPeImportMetadata(options);
  await mkdir(dirname(options.outputPath), { recursive: true });
  await writeFile(options.outputPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  printSummary(report, options.outputPath);
};

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch(error => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
