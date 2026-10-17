import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempDisposableSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { createWindowsTrustSnapshot } from "../../fixtures/windows-trust-snapshot.js";

const createWorkspace = (context: TestContext): string => {
  const directory = mkdtempDisposableSync(join(tmpdir(), "binary101 trust "));
  context.after(() => directory.remove());
  return directory.path;
};

const runPreparation = (
  directory: string, env: Record<string, string | undefined> = process.env
) =>
  spawnSync(process.execPath, [
    "--import", import.meta.resolve("tsx"),
    fileURLToPath(new URL("../../../scripts/prepare-windows-trust.ts", import.meta.url))
  ], { cwd: directory, env, encoding: "utf8", windowsHide: true });

void test("the CLI reuses prepared data in a workspace whose path contains spaces", context => {
  const directory = createWorkspace(context);
  mkdirSync(join(directory, "generated"));
  writeFileSync(join(directory, "generated/windows-trust-store.generated.json"),
    JSON.stringify(createWindowsTrustSnapshot()));

  const result = runPreparation(directory);

  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
});

void test("the CLI reports missing snapshots on non-Windows hosts", {
  skip: process.platform === "win32"
}, context => {
  const result = runPreparation(createWorkspace(context));

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Generate the snapshot on Windows/);
});

void test("the CLI reports a missing PowerShell executable", {
  skip: process.platform !== "win32"
}, context => {
  const result = runPreparation(createWorkspace(context), { ...process.env, PATH: "" });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /powershell\.exe.*ENOENT/);
});

void test("the CLI propagates a failed certificate export", {
  skip: process.platform !== "win32"
}, context => {
  const directory = createWorkspace(context);
  mkdirSync(join(directory, "scripts"));
  writeFileSync(join(directory, "scripts/dump-windows-authenticode-trust.ps1"), "exit 1");

  const result = runPreparation(directory);

  assert.equal(result.status, 1);
  assert.match(result.stderr, /Windows certificate store export failed/);
});

void test("the CLI creates a missing snapshot using the export script", {
  skip: process.platform !== "win32"
}, context => {
  const directory = createWorkspace(context);
  mkdirSync(join(directory, "scripts"));
  mkdirSync(join(directory, "generated"));
  writeFileSync(join(directory, "fixture.json"), JSON.stringify(createWindowsTrustSnapshot()));
  writeFileSync(join(directory, "scripts/dump-windows-authenticode-trust.ps1"),
    "param([string]$OutputPath)\nCopy-Item -LiteralPath fixture.json -Destination $OutputPath\n");

  const result = runPreparation(directory);

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stderr, /Preparing Windows Authenticode trust snapshot/);
});
