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
import { parseElf } from "../../../../../analyzers/elf/index.js";
import { sframeElf, sframePayload } from "../../../../fixtures/elf-sframe.js";
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
  assert.equal(seeds?.seedSummary.sources[0]?.candidates, 1);
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

for (const [version, source] of [[1, "both"], [2, "both"], [3, "segment"]] as const) {
  void test(`adds SFrame v${version} function PCs through the common seed filters`, async () => {
    const address = 0x401000n;
    const payload = sframePayload(version, true, 4);
    // Bit 2 is reserved in v1. The PC-relative interpretation starts with v2 Errata 1.
    payload.bytes[3]! |= 4;
    const file = new File([sframeElf(payload.bytes, true, source)], "sframe.elf");
    const elf = await parseElf(file);
    assert.ok(elf?.sframe);
    const opts = { ...createAnalyzeOptions(address), sframe: elf.sframe,
      dataRanges: [{ start: address + 64n, end: address + 65n }] };
    const issues: string[] = [];

    const seeds = await collectElfInstructionSetSeeds(
      file, opts, [createRegion(address, 65n)], [createSample(address)], issues
    );

    assert.deepEqual(seeds?.entrypoints, [address, address + 32n]);
    assert.deepEqual(seeds?.seedSummary.sources[1], {
      source: "SFrame function descriptors", candidates: 4, added: 1,
      skippedDuplicate: 1, skippedNotExecutable: 1, skippedData: 1, skippedZero: 0
    });
  });
}

void test("skips unusable SFrame descriptors before adding seed candidates", async () => {
  const payload = sframePayload(3, true, 4);
  // GNU SFrame v3 §2.3.1: 16-byte descriptors, with function size at +8.
  payload.view.setUint32(payload.descriptorStart + 16 + 8, 0, true);
  // GNU SFrame v3 §2.3.3: the low nibble of attr.info selects the frame row PC width.
  payload.view.setUint8(payload.rowStart + 2 * 11 + 2, 0xf);
  payload.view.setBigInt64(payload.descriptorStart + 3 * 16, -0x800000n, true);
  const file = new File([sframeElf(payload.bytes)], "invalid-sframe.elf");
  const elf = await parseElf(file);
  assert.ok(elf?.sframe);
  const opts = { ...createAnalyzeOptions(0n), sframe: elf.sframe };

  const seeds = await collectElfInstructionSetSeeds(file, opts,
    [createRegion(0x401000n, 128n)], [], []);

  assert.deepEqual(seeds?.entrypoints, [0x401000n]);
  assert.equal(seeds?.seedSummary.sources[0]?.candidates, 1);
});

void test("keeps unresolved SFrame object PCs out of ISA seed collection", async () => {
  const file = new File([sframeElf(sframePayload(3).bytes, true, "object")], "sframe.o");
  const elf = await parseElf(file);
  assert.ok(elf?.sframe);
  const opts = { ...createAnalyzeOptions(0n), fileType: elf.header.type, sframe: elf.sframe };

  const region = createRegion(0x400000n, 32n);
  const seeds = await collectElfInstructionSetSeeds(file, opts, [region], [], []);

  assert.deepEqual(seeds?.seedSummary.sources, []);
  assert.deepEqual(seeds?.entrypoints, [region.vaddr]);
});
