"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { createFileRangeReader } from "../../../../analyzers/file-range-reader.js";
import {
  createElfNativeAotImage,
  getElfImageBase
} from "../../../../analyzers/elf/native-aot-image.js";
import type { ElfProgramHeader } from "../../../../analyzers/elf/types.js";

const loadSegment = (overrides: Partial<ElfProgramHeader> = {}): ElfProgramHeader => ({
  type: 1,
  typeName: "LOAD",
  offset: 0x100n,
  vaddr: 0x40100n,
  paddr: 0n,
  filesz: 0x20n,
  memsz: 0x40n,
  flags: 6,
  flagNames: ["R", "W"],
  align: 0x100n,
  index: 0,
  ...overrides
});

void test("ELF NativeAOT image normalizes virtual addresses and separates file data from BSS", async () => {
  const bytes = new Uint8Array(0x200);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0x108, 0x40118n, true);
  view.setBigUint64(0x110, 0x40118n, true);
  const reader = createFileRangeReader(new File([bytes], "image.elf"), 0, bytes.length);
  const image = createElfNativeAotImage(reader, [loadSegment()], new Map([[0x108, 0x130]]));

  assert.equal(getElfImageBase([loadSegment()]), 0x40000n);
  assert.equal(image?.toImageAddress(0x40118n), 0x118);
  assert.equal(image?.isDataRange(0x108, 8, 8), true);
  assert.equal(image?.isDataRange(0x120, 1, 1), false);
  assert.equal(image?.isMappedRange(0x120, 1), true);
  assert.equal(await image?.readPointerValue(0x108), 0x40118n);
  assert.equal(await image?.readPointerTarget(0x108), 0x130);
  assert.equal(await image?.readPointerTarget(0x110), 0x118);
});

void test("ELF NativeAOT image rejects invalid geometry and reads", async () => {
  const reader = createFileRangeReader(new File([new Uint8Array(0x110)], "short.elf"), 0, 0x110);
  const image = createElfNativeAotImage(reader, [loadSegment()], new Map());

  assert.equal(getElfImageBase([]), null);
  assert.equal(createElfNativeAotImage(reader, [], new Map()), null);
  assert.equal(image?.toImageAddress(0x3ffffn), null);
  assert.equal(image?.isDataRange(-1, 1, 1), false);
  assert.equal(image?.isDataRange(0x108, 0, 1), false);
  assert.equal(image?.isDataRange(0x108, -1, 1), false);
  assert.equal(image?.isDataRange(1, 1, 0), false);
  assert.equal(image?.isDataRange(0, 8, 8), false);
  assert.equal(image?.isMappedRange(Number.MAX_SAFE_INTEGER, 1), false);
  assert.equal(await image?.readData(0x108, 16, 8), null);
  assert.equal(await image?.readPointerValue(0x20), null);
});

void test("getElfImageBase uses only valid load segments and selects the lowest base", () => {
  const ignoredType = loadSegment({ type: 2, vaddr: 0x100n, offset: 0n });
  const negativeBase = loadSegment({ vaddr: 0x80n, offset: 0x100n });
  const higherBase = loadSegment({ vaddr: 0x50100n, offset: 0x100n });

  const base = getElfImageBase([ignoredType, negativeBase, higherBase, loadSegment()]);

  assert.equal(base, 0x40000n);
});

void test("ELF NativeAOT image accepts exact mapped and file boundaries", () => {
  const bytes = new Uint8Array(0x120);
  const reader = createFileRangeReader(new File([bytes], "boundary.elf"), 0, bytes.length);
  const image = createElfNativeAotImage(reader, [loadSegment()], new Map());

  assert.equal(image?.toImageAddress(0x40000n), 0);
  assert.equal(image?.isDataRange(0x100, 0x20, 1), true);
  assert.equal(image?.isMappedRange(0x100, 0x40), true);
  assert.equal(image?.isMappedRange(0x100, 0), false);
});
