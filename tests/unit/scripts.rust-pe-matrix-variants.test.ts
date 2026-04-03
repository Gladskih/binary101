"use strict";

import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";
import {
  buildCoreVariantSpecs,
  buildExperimentalVariantSpecs,
  writeSourceFiles
} from "../../scripts/rustPeMatrix-variants.js";

void test("buildCoreVariantSpecs produces 200 host variants", () => {
  const variants = buildCoreVariantSpecs("x86_64-pc-windows-gnullvm");

  assert.equal(variants.length, 200);
  assert.equal(variants[0]?.target, "x86_64-pc-windows-gnullvm");
  assert.equal(
    variants.at(-1)?.id,
    "core-optz-dbg2-panicabort-stripsymbols-cpunative"
  );
});

void test("buildExperimentalVariantSpecs includes cross-target probes", () => {
  const variants = buildExperimentalVariantSpecs("x86_64-pc-windows-gnullvm");
  const variantIds = variants.map(variant => variant.id);

  assert.ok(variantIds.includes("exp-link-filealign"));
  assert.ok(variantIds.includes("cross-i686-gnullvm"));
  assert.ok(variantIds.includes("cross-aarch64-msvc"));
});

void test("writeSourceFiles writes console and windows hello-world sources", async () => {
  const sourceDirectory = await mkdtemp(join(tmpdir(), "binary101-rust-matrix-"));

  const sourcePaths = await writeSourceFiles(sourceDirectory);
  const consoleSource = await readFile(sourcePaths["hello.rs"] ?? "", "utf8");
  const windowsSource = await readFile(sourcePaths["hello-windows.rs"] ?? "", "utf8");

  assert.match(consoleSource, /println!\("Hello, world!"\);/);
  assert.match(windowsSource, /windows_subsystem = "windows"/);
});
