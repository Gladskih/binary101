"use strict";

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { parsePe } from "../../analyzers/pe/index.js";
import { MockFile } from "../helpers/mock-file.js";

interface ManifestEntry {
  source: string;
  relativePath: string;
  size: number;
  sha: string | null;
}

interface ManifestFile {
  generatedAt: string;
  entries: ManifestEntry[];
}

const repoRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const fixturesRoot = join(repoRoot, "external-pe-fixtures");
const manifestPath = join(fixturesRoot, "manifest.json");

const isKnownMagic = (value: number): boolean => value === 0x10b || value === 0x20b || value === 0x107;

// Some entries in the external corpora are not executable PE files by design:
// - d_nonnull.dll (corkami/radare2): e_lfanew far beyond file, no PE header.
// - d_tiny.dll, dosZMXP.exe (corkami/radare2): no MZ signature at all.
// - exe2pe.exe (corkami/radare2): NE signature at e_lfanew, not PE.
// - jman.exe (radare2): e_lfanew points past file end.
void test("parsePe stays stable on external PE corpora", async () => {
  assert.ok(
    existsSync(fixturesRoot),
    "External PE fixtures are missing. Run `npm run fetch:pe-fixtures` before running this test."
  );
  assert.ok(
    existsSync(manifestPath),
    "Fixture manifest is missing. Run `npm run fetch:pe-fixtures` to rebuild it."
  );

  const manifestText = await readFile(manifestPath, "utf8");
  const manifest: ManifestFile = JSON.parse(manifestText);

  assert.ok(Array.isArray(manifest.entries) && manifest.entries.length > 0, "Fixture manifest is empty.");

  const missingFiles: string[] = [];
  const sizeMismatches: string[] = [];
  const parseErrors: string[] = [];
  const nullResults: string[] = [];
  const invalidResults: string[] = [];
  let parsedCount = 0;

  for (const entry of manifest.entries) {
    const label = `${entry.source}/${entry.relativePath}`;
    const diskPath = join(fixturesRoot, entry.source, ...entry.relativePath.split("/"));

    if (!existsSync(diskPath)) {
      missingFiles.push(label);
      continue;
    }

    const bytes = await readFile(diskPath);
    if (bytes.byteLength !== entry.size) {
      sizeMismatches.push(label);
    }

    const mock = new MockFile(
      new Uint8Array(bytes),
      basename(diskPath),
      "application/vnd.microsoft.portable-executable"
    );

    try {
      const parsed = await parsePe(mock);
      if (!parsed) {
        nullResults.push(label);
        continue;
      }
      parsedCount += 1;
      if (parsed.signature !== "PE" || !isKnownMagic(parsed.opt.Magic)) {
        invalidResults.push(label);
      }
    } catch (error) {
      const message = error instanceof Error && error.message ? error.message : "Unknown parse error";
      parseErrors.push(`${label}: ${message}`);
    }
  }

  assert.strictEqual(
    missingFiles.length,
    0,
    `Missing fixtures: ${missingFiles.slice(0, 5).join(", ")}`
  );
  assert.strictEqual(
    sizeMismatches.length,
    0,
    `Fixture size mismatch for: ${sizeMismatches.slice(0, 5).join(", ")}`
  );
  assert.strictEqual(
    parseErrors.length,
    0,
    `parsePe threw for ${parseErrors.length} fixtures; first few: ${parseErrors.slice(0, 5).join(" | ")}`
  );
  assert.ok(parsedCount > 0, "Expected at least one PE fixture to parse successfully");
  assert.strictEqual(
    invalidResults.length,
    0,
    `Parsed fixtures with unexpected signature or magic: ${invalidResults.slice(0, 5).join(", ")}`
  );
  if (nullResults.length) {
    // Warn but do not fail; parser should still be resilient to malformed corpora entries.
    console.warn(
      `parsePe returned null for ${nullResults.length} fixtures; examples: ${nullResults.slice(0, 5).join(", ")}`
    );
  }
});
