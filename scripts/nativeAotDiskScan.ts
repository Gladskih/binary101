"use strict";

import { createWriteStream } from "node:fs";
import { mkdir, open, writeFile } from "node:fs/promises";
import { availableParallelism } from "node:os";
import { dirname, parse, resolve } from "node:path";
import type { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { AsyncQueue } from "./file-type-disk-scan/async-queue.js";
import { discoverFiles, recordWarning, type WarningSink } from "./file-type-disk-scan/discovery.js";
import { ScanCoordinator } from "./native-aot-disk-scan/coordinator.js";

type ScanOptions = {
  roots: string[];
  outputPath: string;
  summaryPath: string;
  workerCount: number;
  slotsPerWorker: number;
  prefilterConcurrency: number;
  fileTimeoutMs: number;
};
type Totals = {
  discovered: number;
  prefiltered: number;
  mzCandidates: number;
  analyzed: number;
  peFiles: number;
  matches: number;
  errors: number;
};

const requiredValue = (args: string[], index: number, name: string): string => {
  const value = args[index + 1];
  if (!value || value.startsWith("--")) throw new Error(`${name} requires a value.`);
  return value;
};

const positiveInteger = (value: string, name: string): number => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${name} requires a positive integer.`);
  return parsed;
};

const validateOutput = (output: string, summary: string, timeout: number): void => {
  // https://nodejs.org/api/timers.html#settimeoutcallback-delay-args
  if (!Number.isSafeInteger(timeout) || timeout > 2147483647) {
    throw new Error("File timeout exceeds the supported timer range.");
  }
  if (output.toLowerCase() === summary.toLowerCase()) {
    throw new Error("Output and summary paths must be different.");
  }
};

const resolveRoots = (roots: string[]): string[] =>
  roots.length ? roots : [parse(process.cwd()).root];

const parseOptions = (args: string[]): ScanOptions => {
  const roots: string[] = [];
  let outputPath = resolve("test-results/native-aot-pe-paths.jsonl");
  let summaryPath = resolve("test-results/native-aot-pe-scan-summary.json");
  let workerCount = availableParallelism();
  // Local scheduling budgets, not PE limits: eight concurrent analyses per worker,
  // 512 tiny signature reads overall, and a 30-second job deadline. CLI-overridable.
  let slotsPerWorker = 8;
  let prefilterConcurrency = 512;
  let fileTimeoutMs = 30 * 1000;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--root") roots.push(resolve(requiredValue(args, index++, "--root")));
    else if (arg === "--out") outputPath = resolve(requiredValue(args, index++, "--out"));
    else if (arg === "--summary") summaryPath = resolve(requiredValue(args, index++, "--summary"));
    else if (arg === "--workers") {
      workerCount = positiveInteger(requiredValue(args, index++, "--workers"), "--workers");
    } else if (arg === "--slots-per-worker") {
      slotsPerWorker = positiveInteger(
        requiredValue(args, index++, "--slots-per-worker"),
        "--slots-per-worker"
      );
    } else if (arg === "--prefilter-concurrency") {
      prefilterConcurrency = positiveInteger(
        requiredValue(args, index++, "--prefilter-concurrency"),
        "--prefilter-concurrency"
      );
    } else if (arg === "--file-timeout-seconds") {
      fileTimeoutMs = positiveInteger(
        requiredValue(args, index++, "--file-timeout-seconds"),
        "--file-timeout-seconds"
      ) * 1000;
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  validateOutput(outputPath, summaryPath, fileTimeoutMs);
  return {
    roots: resolveRoots(roots),
    outputPath,
    summaryPath,
    workerCount,
    slotsPerWorker,
    prefilterConcurrency,
    fileTimeoutMs
  };
};

const writeJsonLine = async (stream: Writable, value: unknown): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    stream.write(`${JSON.stringify(value)}\n`, error => error ? reject(error) : resolve());
  });
};

const hasMzSignature = async (path: string): Promise<boolean> => {
  const handle = await open(path, "r");
  try {
    // IMAGE_DOS_HEADER.e_magic is the two-byte ASCII "MZ" signature at offset zero.
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
    const bytes = new Uint8Array(2);
    const result = await handle.read(bytes, 0, bytes.byteLength, 0);
    return result.bytesRead === 2 && bytes[0] === 0x4d && bytes[1] === 0x5a;
  } finally {
    await handle.close();
  }
};

const runPrefilter = async (
  input: AsyncQueue<string>,
  output: AsyncQueue<string>,
  totals: Totals,
  warnings: WarningSink
): Promise<void> => {
  for (;;) {
    const path = await input.shift();
    if (!path) return;
    try {
      if (await hasMzSignature(path)) {
        totals.mzCandidates += 1;
        await output.push(path);
      }
    } catch (error) {
      totals.errors += 1;
      recordWarning(warnings, path, error);
    } finally {
      totals.prefiltered += 1;
    }
  }
};

const runSlot = async (
  worker: Worker,
  coordinator: ScanCoordinator,
  queue: AsyncQueue<string>,
  stream: Writable,
  totals: Totals,
  warnings: WarningSink
): Promise<void> => {
  for (;;) {
    const path = await queue.shift();
    if (!path) return;
    const response = await coordinator.scan(worker, path);
    totals.analyzed += 1;
    if (response.error || !response.result) {
      totals.errors += 1;
      recordWarning(warnings, path, response.error ?? "Worker returned no result.");
    } else {
      if (response.result.pe) totals.peFiles += 1;
      if (response.result.match) {
        totals.matches += 1;
        await writeJsonLine(stream, response.result.match);
      }
    }
  }
};

const waitForReady = async (worker: Worker): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    const cleanup = (): void => {
      worker.off("message", onReady);
      worker.off("error", onError);
      worker.off("exit", onExit);
    };
    const onReady = (): void => {
      cleanup();
      resolve();
    };
    const onError = (error: Error): void => {
      cleanup();
      reject(error);
    };
    const onExit = (code: number): void => onError(new Error(`Worker exited before ready: ${code}.`));
    worker.once("message", onReady);
    worker.once("error", onError);
    worker.once("exit", onExit);
  });

const finishStream = async (stream: Writable): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    stream.once("error", reject);
    stream.end(resolve);
  });

const runPipeline = async (
  options: ScanOptions,
  workers: Worker[],
  stream: Writable,
  totals: Totals,
  warnings: WarningSink
): Promise<void> => {
  const coordinator = new ScanCoordinator(options.fileTimeoutMs);
  workers.forEach(worker => coordinator.attach(worker));
  // Local backpressure policy: buffer up to 16 pending paths per active slot.
  const discoveryQueue = new AsyncQueue<string>(options.prefilterConcurrency * 16);
  const analysisQueue = new AsyncQueue<string>(options.workerCount * options.slotsPerWorker * 16);
  const failure = new Promise<never>((_, reject) => stream.on("error", reject));
  try {
    await Promise.race([Promise.all(workers.map(waitForReady)), failure]);
    const slotRuns = workers.flatMap(worker =>
      Array.from({ length: options.slotsPerWorker }, () =>
        runSlot(worker, coordinator, analysisQueue, stream, totals, warnings)
      )
    );
    const prefilters = Promise.all(Array.from({ length: options.prefilterConcurrency }, () =>
      runPrefilter(discoveryQueue, analysisQueue, totals, warnings)
    )).finally(() => analysisQueue.close());
    const excluded = new Set([options.outputPath.toLowerCase(), options.summaryPath.toLowerCase()]);
    const discovery = discoverFiles(
      // Bound concurrent directory traversal separately from the tiny file prefilter reads.
      // 128 is a local filesystem scheduling budget, not a file-format limit.
      options.roots, Math.min(options.prefilterConcurrency, 128), async file => {
        if (excluded.has(resolve(file.path).toLowerCase())) return true;
        totals.discovered += 1;
        return discoveryQueue.push(file.path);
      }, warnings
    ).finally(() => discoveryQueue.close());
    await Promise.race([Promise.all([discovery, prefilters, ...slotRuns]), failure]);
    await Promise.race([finishStream(stream), failure]);
  } finally {
    discoveryQueue.closeAndDiscard();
    analysisQueue.closeAndDiscard();
    stream.destroy();
  }
};

const runWorkers = async (
  options: ScanOptions,
  totals: Totals,
  warnings: WarningSink
): Promise<void> => {
  const workers: Worker[] = [];
  const started = Date.now();
  // Emit CLI progress every five seconds (Node timer delays are milliseconds).
  const progress = setInterval(() => process.stdout.write(
    JSON.stringify({ ...totals, elapsedMs: Date.now() - started }) + "\n"
  ), 5000);
  try {
    for (let index = 0; index < options.workerCount; index += 1) {
      workers.push(new Worker(new URL("./native-aot-disk-scan/worker.ts", import.meta.url), {
        execArgv: process.execArgv.filter(argument => !argument.startsWith("--max-old-space-size"))
      }));
    }
    await runPipeline(options, workers,
      createWriteStream(options.outputPath, { encoding: "utf8" }), totals, warnings);
  } finally {
    clearInterval(progress);
    await Promise.all(workers.map(worker => worker.terminate()));
  }
};

const main = async (): Promise<void> => {
  const options = parseOptions(process.argv.slice(2));
  await Promise.all([
    mkdir(dirname(options.outputPath), { recursive: true }),
    mkdir(dirname(options.summaryPath), { recursive: true })
  ]);
  const totals: Totals = {
    discovered: 0, prefiltered: 0, mzCandidates: 0, analyzed: 0, peFiles: 0, matches: 0, errors: 0
  };
  const warnings: WarningSink = { count: 0, messages: [] };
  const started = Date.now();
  await runWorkers(options, totals, warnings);
  await writeFile(options.summaryPath,
    JSON.stringify({ ...options, totals, warnings, durationMs: Date.now() - started }, null, 2) + "\n");
  process.stdout.write(JSON.stringify({
    ...totals, outputPath: options.outputPath, elapsedMs: Date.now() - started
  }) + "\n");
};

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  main().catch(error => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

export { parseOptions };
