"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import { analyzeSuccessfulBuild } from "../../scripts/rustPeMatrix-analyze.js";
import { createPeWithSectionAndIatFixture } from "../fixtures/sample-files-pe.js";

void test("analyzeSuccessfulBuild writes parse and rendered outputs for a PE image", async () => {
  const fixture = createPeWithSectionAndIatFixture();
  const variantDirectory = await mkdtemp(join(tmpdir(), "binary101-rust-analyze-"));
  const binaryPath = join(variantDirectory, "fixture.exe");

  await writeFile(binaryPath, fixture.bytes);
  const analysis = await analyzeSuccessfulBuild(binaryPath, variantDirectory);
  const parseOutput = await readFile(join(variantDirectory, "parse.json"), "utf8");
  const renderedOutput = await readFile(join(variantDirectory, "rendered.html"), "utf8");

  assert.equal(analysis.outputSize, fixture.bytes.byteLength);
  assert.deepEqual(analysis.analyzer.sectionNames, [".text"]);
  assert.ok(analysis.analyzer.dataDirectories.includes("IAT"));
  assert.equal(analysis.analyzer.overlaySize, fixture.overlaySize);
  assert.match(parseOutput, /"signature": "PE"/);
  assert.match(renderedOutput, /IAT/);
});
