"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  addExecutableSeedVaddr,
  collectElfInstructionSetSeeds
} from "../../../../../analyzers/elf/disassembly-entrypoints.js";
import type { AnalyzeElfInstructionSetOptions } from "../../../../../analyzers/elf/disassembly.js";
import type { ElfSampledSection } from "../../../../../analyzers/elf/disassembly-sampling.js";
import type { ElfExecutableRegion } from "../../../../../analyzers/elf/executable-regions.js";
import { MockFile } from "../../../../helpers/mock-file.js";
import { createNativeAotInitializerFixture } from
  "../../../../helpers/native-aot-initializer-fixture.js";

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

void test("NativeAOT initializer seeds use the ELF load base and deduplicate", async () => {
  const fixture = createNativeAotInitializerFixture();
  // Any nonzero load base distinguishes image-relative seeds from ELF virtual addresses.
  const imageBase = BigInt(fixture.header.headerRva);
  const expectedVaddrs = fixture.codeRvas.map(rva => imageBase + BigInt(rva));
  const opts = createAnalyzeOptions(expectedVaddrs[0]!);
  // ELF gABI: PT_LOAD = 1, PF_R | PF_X = 5, p_align = 1 means no alignment requirement.
  // https://gabi.xinuos.com/elf/07-pheader.html
  opts.programHeaders = [{
    index: 0, type: 1, typeName: "LOAD", offset: 0n, vaddr: imageBase,
    paddr: 0n, filesz: 0n, memsz: 0n, flags: 5, flagNames: [], align: 1n
  }];
  // ModuleHeaders.cs: ModuleInitializerList = 213.
  // https://github.com/dotnet/runtime/blob/v10.0.0/src/coreclr/tools/Common/Internal/Runtime/ModuleHeaders.cs
  opts.nativeAot = {
    ...fixture.header,
    initializers: [{ sectionType: 213, targetRvas: fixture.codeRvas, warnings: [] }]
  };

  const seeds = await collectElfInstructionSetSeeds(
    new MockFile(new Uint8Array(), "elf"), opts,
    expectedVaddrs.map(address => createRegion(address, 1n)),
    expectedVaddrs.map(createSample), []
  );

  assert.deepEqual(seeds?.entrypoints, expectedVaddrs);
  assert.equal(seeds?.seedSummary.sources[1]?.source, "NativeAOT Module initializers");
  assert.equal(seeds?.seedSummary.sources[1]?.skippedDuplicate, 1);
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
