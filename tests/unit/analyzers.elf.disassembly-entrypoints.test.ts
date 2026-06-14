"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  addExecutableSeedVaddr,
  collectElfInstructionSetSeeds
} from "../../analyzers/elf/disassembly-entrypoints.js";
import type { AnalyzeElfInstructionSetOptions } from "../../analyzers/elf/disassembly.js";
import type { ElfSampledSection } from "../../analyzers/elf/disassembly-sampling.js";
import type { ElfExecutableRegion } from "../../analyzers/elf/executable-regions.js";
import { MockFile } from "../helpers/mock-file.js";

void test("addExecutableSeedVaddr rejects zero, duplicate, and non-executable seeds", () => {
  const entrypoints: bigint[] = [];
  const seen = new Set<bigint>();
  const regions = [createRegion(0x1000n, 4n)];
  assert.equal(addExecutableSeedVaddr(regions, entrypoints, seen, 0n), "zero");
  assert.equal(addExecutableSeedVaddr(regions, entrypoints, seen, 0x2000n), "notExecutable");
  assert.equal(addExecutableSeedVaddr(regions, entrypoints, seen, 0x1000n), "added");
  assert.equal(addExecutableSeedVaddr(regions, entrypoints, seen, 0x1000n), "duplicate");
  assert.deepEqual(entrypoints, [0x1000n]);
});

void test("collectElfInstructionSetSeeds falls back to the first sampled section", async () => {
  const issues: string[] = [];
  const seeds = await collectElfInstructionSetSeeds(
    new MockFile(new Uint8Array([0x90]), "elf"),
    createAnalyzeOptions(0n),
    [createRegion(0x1000n, 4n)],
    [createSample(0x1000n)],
    issues
  );
  assert.deepEqual(seeds?.entrypoints, [0x1000n]);
  assert.equal(seeds?.seedSummary.fallbackSource, "sample");
  assert.match(issues.join("\n"), /Falling back/);
});

const createAnalyzeOptions = (entrypointVaddr: bigint): AnalyzeElfInstructionSetOptions => ({
  machine: 62,
  is64Bit: true,
  littleEndian: true,
  entrypointVaddr,
  programHeaders: [],
  sections: []
});

const createRegion = (vaddr: bigint, fileSize: bigint): ElfExecutableRegion => ({
  label: "sample",
  fileOffset: 0n,
  fileSize,
  vaddr
});

const createSample = (vaddrStart: bigint): ElfSampledSection => ({
  vaddrStart,
  data: new Uint8Array([0x90]),
  label: "sample"
});
