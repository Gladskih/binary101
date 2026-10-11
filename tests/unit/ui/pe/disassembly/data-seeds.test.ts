"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import { parsePe, isPeWindowsParseResult } from "../../../../../analyzers/pe/index.js";
import { collectPeDisassemblySeeds } from "../../../../../ui/pe-disassembly-seeds.js";
import { createPeDataSeedFixture } from "../../../../fixtures/pe-data-seeds.js";
import { createFileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";

void test("PE export and MSVC RTTI seeds omit demangled data while preserving unknown names", async context => {
  const { file, targets } = createPeDataSeedFixture();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe) && pe.msvcRtti);
  assert.deepEqual(pe.msvcRtti.vftables[0]?.functionTargetRvas, targets);
  const read = context.mock.method(file, "slice");

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.exportRvas, targets.filter((_rva, index) => index !== 1 && index !== 2));
  assert.deepEqual(seeds.extraEntrypoints, [{ source: "MSVC RTTI vftables", rvas: seeds.exportRvas }]);
  assert.deepEqual(pe.msvcRtti.vftables[0]?.functionTargetRvas, targets);
  assert.equal(pe.exports?.entries[1]?.names[0], "?value@demo@@3HA");
  assert.deepEqual(await collectPeDisassemblySeeds(file, pe), seeds);
  assert.equal(read.mock.callCount(), 0);
});

void test("data seeds no longer introduce false AVX and SSE requirements", async () => {
  const { file, targets } = createPeDataSeedFixture();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe));
  const seeds = await collectPeDisassemblySeeds(file, pe);

  const options = {
    ...seeds, coffMachine: seeds.canonicalMachine, is64Bit: true,
    imageBase: pe.opt.ImageBase, sections: pe.sections, rvaToOff: pe.rvaToOff
  };
  const reader = createFileRangeReader(file, 0, file.size);
  const unfiltered = await analyzePeInstructionSets(reader, { ...options, exportRvas: targets });
  const report = await analyzePeInstructionSets(reader, options);

  assert.deepEqual(unfiltered.instructionSets.map(feature => feature.id), ["X64", "AVX", "SSE"]);
  assert.equal(unfiltered.instructionCount, 9);
  assert.deepEqual(report.instructionSets.map(feature => feature.id), ["X64"]);
  assert.equal(report.instructionCount, 5);
  assert.equal(report.bytesDecoded, 5);
  assert.equal(report.invalidInstructionCount, 0);
  assert.deepEqual(report.issues, []);
});

void test("forwarders do not mark an independent RTTI target as data", async () => {
  const { file, targets } = createPeDataSeedFixture();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe) && pe.exports);
  pe.exports.entries[1]!.forwarder = "other.value";
  pe.exports.entries[2]!.forwarder = "other.table";

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.extraEntrypoints, [{ source: "MSVC RTTI vftables", rvas: targets }]);
  assert.equal(seeds.exportRvas.length, targets.length - 2);
});

void test("an RTTI source with only known data does not create an empty seed group", async () => {
  const { file, targets } = createPeDataSeedFixture();
  const pe = await parsePe(file);
  assert.ok(pe && isPeWindowsParseResult(pe) && pe.msvcRtti);
  pe.msvcRtti.vftables[0]!.functionTargetRvas = [targets[1]!, targets[2]!];

  const seeds = await collectPeDisassemblySeeds(file, pe);

  assert.deepEqual(seeds.extraEntrypoints, []);
});
