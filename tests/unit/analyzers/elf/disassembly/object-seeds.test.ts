import assert from "node:assert/strict";
import { test } from "node:test";
import { createCodeExclusionIndex } from "../../../../../analyzers/code-exclusions.js";
import { collectElfObjectCodeSeeds } from "../../../../../analyzers/elf/disassembly-object-seeds.js";
import type { ElfExecutableRegion } from "../../../../../analyzers/elf/executable-regions.js";
import type { ElfStaticSymbol } from "../../../../../analyzers/elf/symbol-tables.js";

const codeRegion = (sectionIndex: number, fileOffset: bigint): ElfExecutableRegion => ({
  sectionIndex, fileOffset, vaddr: fileOffset, fileSize: 16n, label: `Section ${sectionIndex}`
});

const symbol = (fields: Partial<ElfStaticSymbol> = {}): ElfStaticSymbol => ({
  info: 2, other: 0, sectionIndex: 1, value: 0n, size: 1n, name: "", ...fields
});

void test("object code seeds track callable symbols, bounds, data and duplicate offsets", () => {
  const regions = [codeRegion(1, 0x40n), codeRegion(2, 0x50n), codeRegion(3, 0x60n)];
  const tables = [{ sectionIndex: 4, issues: [], entries: [
    symbol(), symbol(), symbol({ sectionIndex: 2, info: 0x1a, value: 4n }), // STT_GNU_IFUNC.
    symbol({ info: 1 }), symbol({ value: 16n }), symbol({ value: -1n }),
    symbol({ sectionIndex: 0 }), symbol({ sectionIndex: 2 })
  ] }];
  const crossedData = createCodeExclusionIndex([{ start: 0x50n, end: 0x54n }]);
  const seeds = collectElfObjectCodeSeeds(tables, regions, crossedData);

  assert.deepEqual(seeds.entrypoints, [0x40n, 0x54n, 0x60n]);
  assert.equal(seeds.seedSummary.fallbackSource, "start of 1 executable section(s)");
  assert.deepEqual(seeds.seedSummary.sources, [{
    source: "Function symbols in section #4",
    candidates: 7, added: 2, skippedNotExecutable: 3, skippedZero: 0,
    skippedDuplicate: 1, skippedData: 1
  }]);
});

void test("a reserved index and an equally numbered extended physical section are separate", () => {
  // SHN_ABS is a 16-bit sentinel. A SHN_XINDEX extension may resolve to section 0xfff1.
  // https://gabi.xinuos.com/elf/05-symtab.html#section-index
  const regions = [codeRegion(0xfff1, 0x40n)];
  const tables = [{ sectionIndex: 5, issues: [], entries: [
    symbol({ sectionIndex: 0xfff1, value: 1n }),
    symbol({ sectionIndex: 0xfff1, rawSectionIndex: 0xffff, value: 3n })
  ] }];
  const seeds = collectElfObjectCodeSeeds(tables, regions, createCodeExclusionIndex());

  assert.deepEqual(seeds.entrypoints, [0x43n]);
  assert.equal(seeds.seedSummary.sources[0]?.skippedNotExecutable, 1);
});
