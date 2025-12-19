"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import type { ElfProgramHeader } from "../../analyzers/elf/types.js";
import { vaddrToFileOffset } from "../../analyzers/elf/vaddr-to-file-offset.js";

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

void test("vaddrToFileOffset maps vaddr into PT_LOAD file offsets", () => {
  const programHeaders = [ph({ offset: 0x200n, vaddr: 0x4000n, filesz: 0x100n })];
  assert.equal(vaddrToFileOffset(programHeaders, 0x4000n), 0x200n);
  assert.equal(vaddrToFileOffset(programHeaders, 0x4010n), 0x210n);
  assert.equal(vaddrToFileOffset(programHeaders, 0x40ffn), 0x2ffn);
});

void test("vaddrToFileOffset returns null when vaddr is outside file-backed PT_LOAD ranges", () => {
  const programHeaders = [ph({ offset: 0x200n, vaddr: 0x4000n, filesz: 0x10n, memsz: 0x100n })];
  assert.equal(vaddrToFileOffset(programHeaders, 0x3fffn), null);
  assert.equal(vaddrToFileOffset(programHeaders, 0x4010n), null);
});

