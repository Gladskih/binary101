"use strict";

import assert from "node:assert/strict";
import { basename } from "node:path";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { MockFile } from "../helpers/mock-file.js";
import { compareElfWithReadelf, type ElfReadelfCoverage } from "./elf-wsl-readelf-compare.js";
import { collectWslElfFixtures, probeWslReadelf } from "./elf-wsl-readelf-fixtures.js";

const DEFAULT_MAX_FILES = 24;
const DEFAULT_MIN_FILES = 12;
const DEFAULT_MAX_DYNSYM_FILES = 12;

const readPositiveEnv = (name: string, fallback: number): number => {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const summarizeExamples = (items: string[], limit = 8): string => items.slice(0, limit).join(" | ");

void test("parseElf matches GNU readelf across a broader WSL corpus", async context => {
  const probe = probeWslReadelf();
  if (!probe.available) {
    context.skip(probe.reason);
    return;
  }

  const maxFiles = readPositiveEnv("ELF_WSL_MAX_FILES", DEFAULT_MAX_FILES);
  const minFiles = Math.min(maxFiles, readPositiveEnv("ELF_WSL_MIN_FILES", DEFAULT_MIN_FILES));
  const maxDynSymbolFiles = Math.min(
    maxFiles,
    readPositiveEnv("ELF_WSL_MAX_DYNSYM_FILES", DEFAULT_MAX_DYNSYM_FILES)
  );
  const fixtures = collectWslElfFixtures(maxFiles, maxDynSymbolFiles);
  assert.ok(
    fixtures.length >= minFiles,
    `Expected at least ${minFiles} WSL ELF files, got ${fixtures.length}.`
  );

  const coverage: ElfReadelfCoverage = {
    header: 0,
    programHeaders: 0,
    sections: 0,
    dynamic: 0,
    dynSymbols: 0,
    buildId: 0,
    withNeeded: 0,
    withFlags: 0,
    withFlags1: 0
  };
  const parseErrors: string[] = [];
  const mismatches: string[] = [];

  for (const fixture of fixtures) {
    const file = new MockFile(fixture.bytes, basename(fixture.path), "application/x-elf");
    try {
      const parsed = await parseElf(file);
      if (!parsed) {
        mismatches.push(`${fixture.path}: parseElf returned null`);
        continue;
      }
      const fileIssues = compareElfWithReadelf(parsed, fixture.readelf, coverage);
      for (const issue of fileIssues) mismatches.push(`${fixture.path}: ${issue}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown parse error";
      parseErrors.push(`${fixture.path}: ${message}`);
    }
  }

  assert.strictEqual(
    parseErrors.length,
    0,
    `parseElf threw for ${parseErrors.length} files; examples: ${summarizeExamples(parseErrors)}`
  );
  assert.strictEqual(
    mismatches.length,
    0,
    `Mismatches found: ${mismatches.length}; examples: ${summarizeExamples(mismatches)}`
  );

  assert.strictEqual(coverage.header, fixtures.length, "Expected header comparison for each file.");
  assert.strictEqual(coverage.programHeaders, fixtures.length, "Expected program headers comparison for each file.");
  assert.strictEqual(coverage.sections, fixtures.length, "Expected section headers comparison for each file.");
  assert.ok(coverage.dynamic > 0, "Expected dynamic section checks on at least one file.");
  assert.ok(coverage.dynSymbols > 0, "Expected dynsym checks on at least one file.");
  assert.ok(coverage.buildId > 0, "Expected GNU build-id checks on at least one file.");
  assert.ok(coverage.withNeeded > 0, "Expected DT_NEEDED checks on at least one file.");
  assert.ok(coverage.withFlags > 0, "Expected DT_FLAGS checks on at least one file.");
  assert.ok(coverage.withFlags1 > 0, "Expected DT_FLAGS_1 checks on at least one file.");
});
