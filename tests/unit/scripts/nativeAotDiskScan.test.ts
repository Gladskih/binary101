import assert from "node:assert/strict";
import { test } from "node:test";
import { parseOptions } from "../../../scripts/nativeAotDiskScan.js";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { createPeWithSectionAndIat } from "../../fixtures/sample-files-pe.js";

const runCli = async (root: string, output: string, summary: string) => promisify(execFile)(
  process.execPath, ["--import", "tsx", "scripts/nativeAotDiskScan.ts", "--root", root,
    "--out", output, "--summary", summary, "--workers", "1", "--slots-per-worker", "2",
    "--prefilter-concurrency", "2"], { timeout: 15000 }
);

void test("native AOT scan rejects timeouts that overflow Node timers", () => {
  // Node timers overflow beyond a signed 32-bit millisecond delay.
  assert.throws(() => parseOptions(["--file-timeout-seconds", "2147484"]), /timeout/i);
});

void test("native AOT scan rejects identical output and summary paths", () => {
  assert.throws(() => parseOptions(["--out", "same.json", "--summary", "same.json"]), /different/i);
});

void test("native AOT scan rejects option names used as values", () => {
  assert.throws(() => parseOptions(["--root", "--workers"]), /requires a value/);
});

void test("native AOT scan parses bounded concurrency and repeated roots", () => {
  const options = parseOptions(["--root", "first", "--root", "second", "--workers", "2",
    "--slots-per-worker", "3", "--prefilter-concurrency", "4", "--file-timeout-seconds", "5"]);

  assert.equal(options.roots.length, 2);
  assert.equal(options.workerCount, 2);
  assert.equal(options.slotsPerWorker, 3);
  assert.equal(options.prefilterConcurrency, 4);
  assert.equal(options.fileTimeoutMs, 5000);
  assert.throws(() => parseOptions(["--workers", "0"]), /positive integer/);
  assert.throws(() => parseOptions(["--workers", "1.5"]), /positive integer/);
  assert.throws(() => parseOptions(["--unknown", "value"]), /Unknown argument/);
});

void test("native AOT CLI completes real worker scans and writes consistent totals", async () => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-aot-cli-"));
  const summary = join(directory, "summary.json");
  try {
    await writeFile(join(directory, "sample.exe"), createPeWithSectionAndIat());
    await writeFile(join(directory, "truncated.exe"), "MZ");
    await writeFile(join(directory, "text.txt"), "text");

    await runCli(directory, join(directory, "matches.jsonl"), summary);

    const result = JSON.parse(await readFile(summary, "utf8")) as {
      totals: { discovered: number; prefiltered: number; analyzed: number; peFiles: number; errors: number };
    };
    assert.equal(result.totals.discovered, 3);
    assert.equal(result.totals.prefiltered, 3);
    assert.equal(result.totals.analyzed, 2);
    assert.equal(result.totals.peFiles, 1);
    assert.equal(result.totals.errors, 0);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

void test("native AOT CLI exits on output errors without leaving live workers", async () => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-aot-cli-error-"));
  try {
    await assert.rejects(runCli(directory, directory, join(directory, "summary.json")),
      (error: Error & { killed?: boolean }) => {
        assert.notEqual(error.killed, true);
        assert.match(error.message, /EISDIR|EPERM|EACCES/);
        return true;
      });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
