"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfProgramHeader, ElfSectionHeader } from "../../analyzers/elf/types.js";
import {
  computeElfExecutableSpan,
  computeElfImageBase,
  findElfRegionContainingVaddr,
  getElfExecutableRegions
} from "../../analyzers/elf/executable-regions.js";

const ph = (overrides: Partial<ElfProgramHeader>): ElfProgramHeader =>
  ({
    type: 1,
    typeName: "PT_LOAD",
    offset: 0n,
    vaddr: 0n,
    paddr: 0n,
    filesz: 1n,
    memsz: 1n,
    flags: 0,
    flagNames: [],
    align: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfProgramHeader;

const sec = (overrides: Partial<ElfSectionHeader>): ElfSectionHeader =>
  ({
    nameOff: 0,
    type: 1,
    typeName: "SHT_PROGBITS",
    flags: 0n,
    flagNames: [],
    addr: 0n,
    offset: 0n,
    size: 1n,
    link: 0,
    info: 0,
    addralign: 0n,
    entsize: 0n,
    index: 0,
    ...overrides
  }) as unknown as ElfSectionHeader;

void test("getElfExecutableRegions prefers executable PT_LOAD segments", () => {
  const regions = getElfExecutableRegions(
    [
      ph({ index: 1, flags: 0x1, vaddr: 0x1000n, offset: 0x200n, filesz: 0x50n }),
      ph({ index: 2, flags: 0x0, vaddr: 0x2000n, offset: 0x300n, filesz: 0x60n })
    ],
    [sec({ index: 0, name: ".text", flags: 0x4n })]
  );

  assert.equal(regions.length, 1);
  assert.ok(regions[0]?.label.includes("PT_LOAD"));
  assert.equal(regions[0]?.vaddr, 0x1000n);
  assert.equal(regions[0]?.fileOffset, 0x200n);
  assert.equal(regions[0]?.fileSize, 0x50n);
});

void test("getElfExecutableRegions falls back to SHF_EXECINSTR sections", () => {
  const regions = getElfExecutableRegions([], [
    sec({ index: 1, name: ".data", flags: 0x1n }),
    sec({ index: 2, name: ".text", flags: 0x4n, addr: 0x400000n, offset: 0x1000n, size: 0x200n }),
    sec({ index: 3, name: ".bss", type: 8, flags: 0x4n, size: 0x80n })
  ]);

  assert.equal(regions.length, 1);
  assert.ok(regions[0]?.label.includes(".text"));
  assert.equal(regions[0]?.vaddr, 0x400000n);
});

void test("computeElfImageBase and computeElfExecutableSpan use min/max executable ranges", () => {
  const regions = [
    { label: "A", vaddr: 0x1000n, fileOffset: 0n, fileSize: 0x100n },
    { label: "B", vaddr: 0x5000n, fileOffset: 0n, fileSize: 0x20n }
  ];
  const base = computeElfImageBase(regions);
  assert.equal(base, 0x1000n);
  const span = computeElfExecutableSpan(regions, base);
  assert.equal(span, 0x4020n);
});

void test("findElfRegionContainingVaddr returns the matching region", () => {
  const regions = [
    { label: "A", vaddr: 0x1000n, fileOffset: 0n, fileSize: 0x100n },
    { label: "B", vaddr: 0x2000n, fileOffset: 0n, fileSize: 0x10n }
  ];
  assert.equal(findElfRegionContainingVaddr(regions, 0x1050n)?.label, "A");
  assert.equal(findElfRegionContainingVaddr(regions, 0x200fn)?.label, "B");
  assert.equal(findElfRegionContainingVaddr(regions, 0x3000n), null);
});

