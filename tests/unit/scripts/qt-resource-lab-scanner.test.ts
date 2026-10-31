import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { embeddedResourceFixture } from "../../fixtures/embedded-resource-builders.js";

const executeScanner = (input: string): Record<string, unknown> => {
  const result = spawnSync(process.execPath, ["--import", "tsx",
    fileURLToPath(new URL("../../../scripts/qt-resource-lab-scanner.ts", import.meta.url))],
  { input, encoding: "utf8", timeout: 20_000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim()) as Record<string, unknown>;
};

void test("scanner emits resource contents using only an opaque id and file path", async context => {
  const directory = await mkdtemp(join(tmpdir(), "binary101-qt-scanner-"));
  const path = join(directory, "sample.dll");
  context.after(async () => { await unlink(path); await rmdir(directory); });
  await writeFile(path, embeddedResourceFixture("qt-glib.dll"));
  const result = executeScanner(`${JSON.stringify({ id: "opaque", path })}\n`);
  assert.equal(result["id"], "opaque");
  assert.equal(result["status"], "ok");
  const bundles = result["bundles"] as Array<{ files: Array<{ path: string; sha256: string }> }>;
  assert.equal(bundles.length, 2);
  assert.equal(bundles[0]?.files.find(file => file.path.endsWith("message.txt"))?.sha256.length, 64);
});

void test("scanner reports unavailable input and malformed requests without terminating", () => {
  assert.equal(executeScanner('{"id":"opaque","path":"missing-resource-test-file"}\n')["status"], "error");
  assert.equal(executeScanner('{"id":123}\n')["status"], "error");
});
