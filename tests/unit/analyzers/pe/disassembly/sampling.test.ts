"use strict";

import assert from "node:assert/strict";
import test from "node:test";
import {
  collectPeDisassemblySamples,
  normalizeRvaList,
  resolvePeDisassemblyEntrypoints
} from "../../../../../analyzers/pe/disassembly/sampling.js";
import type { AnalyzePeInstructionSetOptions } from "../../../../../analyzers/pe/disassembly/index.js";
import type { FileRangeReader } from "../../../../../analyzers/file-range-reader.js";
import type { PeSection } from "../../../../../analyzers/pe/types.js";
import { inlinePeSectionName } from "../../../../../analyzers/pe/sections/name.js";

const IMAGE_SCN_MEM_EXECUTE = 0x20000000;

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
  coffMachine: 0x8664,
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
