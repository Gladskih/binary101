"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  collectPeDisassemblySamples,
  findBestCodeSection,
  normalizeRvaList,
  resolvePeDisassemblyEntrypoints
} from "../../../../../analyzers/pe/disassembly/sampling.js";
import { IMAGE_FILE_MACHINE_AMD64 } from "../../../../../analyzers/coff/machine.js";
import type { AnalyzePeInstructionSetOptions } from "../../../../../analyzers/pe/disassembly/index.js";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";
import { analyzePeInstructionSets } from "../../../../../analyzers/pe/disassembly/analyze.js";

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

void test("fallback never guesses code from section names or data/code-content flags", () => {
  // PE/COFF: CNT_CODE describes contents; MEM_EXECUTE grants execution permission.
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags
  assert.equal(findBestCodeSection([
    createSection(".text", 0x1000, 1, 0, 0x40000020),
    createSection(".rdata", 0x2000, 1, 1, 0x40000040)
  ]), null);
  assert.equal(findBestCodeSection([]), null);
});

void test("fallback prefers executable .text, including mixed-case names", () => {
  const text = createSection(".TeXt", 0x2000, 1, 1, IMAGE_SCN_MEM_EXECUTE);
  assert.equal(findBestCodeSection([
    createSection("PAGE", 0x1000, 1, 0, IMAGE_SCN_MEM_EXECUTE), text
  ]), text);
});

void test("fallback skips empty and non-executable .text before choosing executable code", () => {
  const code = createSection("PAGE", 0x3000, 1, 1, IMAGE_SCN_MEM_EXECUTE);
  assert.equal(findBestCodeSection([
    createSection(".text", 0x1000, 1, 0, 0),
    createSection(".text", 0x2000, 0, 0, IMAGE_SCN_MEM_EXECUTE), code
  ]), code);
});

void test("data-only PE is skipped without loading the decoder or reporting OUTSB", async () => {
  const report = await analyzePeInstructionSets(createMemoryReader(new Uint8Array([0x6e])), {
    ...createAnalyzeOptions(0),
    sections: [createSection(".rdata", 0x1000, 1, 0, 0)],
    rvaToOff: () => 0
  }, async () => assert.fail("A data-only PE must not load the decoder"));
  // 0x6e is OUTSB if decoded as x86; here it is data, as in the real hal.dll RSDS GUID.
  assert.equal(report.instructionCount, 0);
  assert.equal(report.bytesSampled, 0);
  assert.equal(report.bytesDecoded, 0);
  assert.deepEqual(report.instructionSets, []);
  assert.deepEqual(report.specialInstructions, []);
  assert.deepEqual(report.issues, ["No executable section with code bytes found."]);
});

void test("normalizeRvaList keeps unique positive safe RVAs", () => {
  assert.deepEqual(normalizeRvaList([0x20, 0, -1, 0x20, 0x30, Number.MAX_SAFE_INTEGER + 1]), [
    0x20,
    0x30
  ]);
});

void test("resolvePeDisassemblyEntrypoints warns for non-executable sections and falls back", () => {
  const issues: string[] = [];
  const entrypoints = resolvePeDisassemblyEntrypoints(createAnalyzeOptions(0x3000), issues);
  assert.deepEqual(entrypoints, [0x1000]);
  assert.match(issues.join("\n"), /non-executable section/);
  assert.match(issues.join("\n"), /Falling back to section \.text/);
});

void test("collectPeDisassemblySamples reads mapped section spans", async () => {
  const samples = await collectPeDisassemblySamples(
    createMemoryReader(new Uint8Array([0, 1, 2, 3, 4, 5])),
    createAnalyzeOptions(0x1000),
    [0x1000]
  );
  assert.equal(samples.length, 1);
  assert.equal(samples[0]?.rvaStart, 0x1000);
  assert.deepEqual([...samples[0]?.data ?? []], [1, 2]);
});

const createAnalyzeOptions = (entrypointRva: number): AnalyzePeInstructionSetOptions => ({
  coffMachine: IMAGE_FILE_MACHINE_AMD64,
  is64Bit: true,
  imageBase: 0n,
  entrypointRva,
  rvaToOff: rva => rva - 0x1000 + 1,
  sections: [
    createSection(".text", 0x1000, 2, 1, IMAGE_SCN_MEM_EXECUTE),
    createSection(".data", 0x3000, 4, 3, 0)
  ]
});

const createSection = (
  name: string,
  virtualAddress: number,
  sizeOfRawData: number,
  pointerToRawData: number,
  characteristics: number
): PeSection => ({
  name: inlinePeSectionName(name),
  virtualSize: sizeOfRawData,
  virtualAddress,
  sizeOfRawData,
  pointerToRawData,
  characteristics
});

const createMemoryReader = (bytes: Uint8Array): FileRangeReader => ({
  size: bytes.length,
  read: async (offset, size) =>
    new DataView(bytes.buffer, bytes.byteOffset + offset, Math.min(size, bytes.length - offset)),
  readBytes: async (offset, size) => bytes.slice(offset, offset + size)
});
