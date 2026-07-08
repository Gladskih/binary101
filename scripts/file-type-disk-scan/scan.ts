"use strict";

import { createWriteStream } from "node:fs";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { dirname, resolve } from "node:path";
import type { Writable } from "node:stream";
import { detectBinaryType } from "../../analyzers/index.js";
import { AsyncQueue } from "./async-queue.js";
import { createDiskBackedFile } from "../pe-import-metadata-scan/disk-file.js";
import { discoverFiles, recordWarning, type DiscoveredFile, type WarningSink } from "./discovery.js";
import { DEFAULT_FILE_EXE, readFileMimeTypes } from "./file-command.js";
import { compareTypes, normalizeAnalyzerLabel, normalizeFileMimeType } from "./type-mapping.js";

type ScanOptions = {
  roots: string[];
  outputPath: string;
  summaryPath: string;
  fileExePath: string;
  workerCount: number;
  batchSize: number;
  fileLimit: number | null;
};

type ScanTotals = {
  filesDiscovered: number;
  filesScanned: number;
  matches: number;
  analyzerAdvantages: number;
  mismatches: number;
  analyzerErrors: number;
  fileCommandErrors: number;
};

type ScanSummary = {
  roots: string[];
  outputPath: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  workerCount: number;
  batchSize: number;
  totals: ScanTotals;
  warningCount: number;
  warnings: string[];
};

type MismatchRecord = {
  path: string;
  analyzerLabel: string;
  analyzerCanonical: string;
  fileMimeType: string;
  fileCanonical: string;
};

const DEFAULT_BATCH_SIZE = 16;
const DEFAULT_QUEUE_CAPACITY = 4096;

const defaultWorkerCount = (): number => Math.max(1, availableParallelism());

const initialTotals = (): ScanTotals => ({
  filesDiscovered: 0,
  filesScanned: 0,
  matches: 0,
  analyzerAdvantages: 0,
  mismatches: 0,
  analyzerErrors: 0,
  fileCommandErrors: 0
});

const writeJsonLine = async (stream: Writable, value: unknown): Promise<void> => {
  if (stream.write(`${JSON.stringify(value)}\n`)) return;
  await new Promise<void>(resolve => stream.once("drain", resolve));
};

const detectPath = async (file: DiscoveredFile, warnings: WarningSink): Promise<string | null> => {
  try {
    const info = file.size === 0 ? await stat(file.path) : null;
    const size = info?.size ?? file.size;
    return await detectBinaryType(createDiskBackedFile(file.path, size) as File);
  } catch (error) {
    recordWarning(warnings, file.path, error);
    return null;
  }
};

const writeMismatch = async (
  stream: Writable,
  file: DiscoveredFile,
  analyzerLabel: string,
  fileMimeType: string
): Promise<void> => {
  const record: MismatchRecord = {
    path: file.path,
    analyzerLabel,
    analyzerCanonical: normalizeAnalyzerLabel(analyzerLabel),
    fileMimeType,
    fileCanonical: normalizeFileMimeType(fileMimeType)
  };
  await writeJsonLine(stream, record);
};

const scanBatch = async (
  batch: DiscoveredFile[],
  options: ScanOptions,
  stream: Writable,
  totals: ScanTotals,
  warnings: WarningSink
): Promise<void> => {
  const analyzerLabels = await Promise.all(batch.map(file => detectPath(file, warnings)));
  const fileResults = await readFileMimeTypes(options.fileExePath, batch.map(file => file.path));
  for (let index = 0; index < batch.length; index += 1) {
    const file = batch[index];
    const analyzerLabel = analyzerLabels[index];
    const fileResult = fileResults[index];
    if (!file || !analyzerLabel) {
      totals.analyzerErrors += 1;
      continue;
    }
    if (!fileResult || fileResult.status === "error") {
      totals.fileCommandErrors += 1;
      recordWarning(warnings, file.path, fileResult?.message ?? "file.exe returned no result.");
      continue;
    }
    totals.filesScanned += 1;
    const comparison = compareTypes(analyzerLabel, fileResult.mimeType);
    if (comparison === "match") totals.matches += 1;
    else if (comparison === "analyzer-more-specific") totals.analyzerAdvantages += 1;
    else {
      totals.mismatches += 1;
      await writeMismatch(stream, file, analyzerLabel, fileResult.mimeType);
    }
  }
};

const scanWorker = async (
  queue: AsyncQueue<DiscoveredFile>,
  options: ScanOptions,
  stream: Writable,
  totals: ScanTotals,
  warnings: WarningSink
): Promise<void> => {
  for (;;) {
    const first = await queue.shift();
    if (!first) return;
    await scanBatch([first, ...queue.takeAvailable(options.batchSize - 1)], options, stream, totals, warnings);
  }
};

const discoverIntoQueue = async (
  queue: AsyncQueue<DiscoveredFile>,
  options: ScanOptions,
  totals: ScanTotals,
  warnings: WarningSink
): Promise<void> => {
  const excludedPaths = new Set([
    resolve(options.outputPath).toLowerCase(),
    resolve(options.summaryPath).toLowerCase()
  ]);
  await discoverFiles(options.roots, options.workerCount, async file => {
    if (options.fileLimit != null && totals.filesDiscovered >= options.fileLimit) return false;
    if (excludedPaths.has(resolve(file.path).toLowerCase())) return true;
    totals.filesDiscovered += 1;
    await queue.push(file);
    return true;
  }, warnings);
  queue.close();
};

const ensureFileExecutable = async (path: string): Promise<void> => {
  const info = await stat(path);
  if (!info.isFile()) throw new Error(`file.exe not found at ${path}`);
};

const finishStream = async (stream: Writable): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    stream.once("error", reject);
    stream.end(resolve);
  });
};

const scanFileTypes = async (options: ScanOptions): Promise<ScanSummary> => {
  await ensureFileExecutable(options.fileExePath);
  await mkdir(dirname(options.outputPath), { recursive: true });
  await mkdir(dirname(options.summaryPath), { recursive: true });
  const started = new Date();
  const totals = initialTotals();
  const warnings: WarningSink = { count: 0, messages: [] };
  const queue = new AsyncQueue<DiscoveredFile>(DEFAULT_QUEUE_CAPACITY);
  const stream = createWriteStream(options.outputPath, { encoding: "utf8" });
  const workers = Array.from({ length: options.workerCount }, () =>
    scanWorker(queue, options, stream, totals, warnings)
  );
  await discoverIntoQueue(queue, options, totals, warnings);
  await Promise.all(workers);
  await finishStream(stream);
  const finished = new Date();
  const summary = {
    roots: options.roots,
    outputPath: options.outputPath,
    startedAt: started.toISOString(),
    finishedAt: finished.toISOString(),
    durationMs: finished.getTime() - started.getTime(),
    workerCount: options.workerCount,
    batchSize: options.batchSize,
    totals,
    warningCount: warnings.count,
    warnings: warnings.messages
  };
  await writeFile(options.summaryPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  return summary;
};

export {
  DEFAULT_BATCH_SIZE,
  DEFAULT_FILE_EXE,
  defaultWorkerCount,
  scanFileTypes
};
export type { ScanOptions, ScanSummary };
