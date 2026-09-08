"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import { parseElfDynamicSymbols } from "../../../../analyzers/elf/dynamic-symbols.js";
import { createElfGnuHashDynamicFixture } from "../../../fixtures/elf-gnu-hash-file.js";
import { createElfFile } from "../../../fixtures/elf-sample-file.js";
import { createElfMetadataFile } from "../../../fixtures/elf-metadata-file.js";
import { expectDefined } from "../../../helpers/expect-defined.js";
import { relocationFixture } from "../../../fixtures/elf-relocations.js";
import type { ElfRelocationSymbol } from "../../../../analyzers/elf/relocation-types.js";

void test("parseElfDynamicSymbols returns imports and exports from .dynsym/.dynstr", async () => {
  const { file, expected } = createElfMetadataFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const info = await parseElfDynamicSymbols({
    file,
    programHeaders: elf.programHeaders,
    sections: elf.sections,
    is64: elf.is64,
    littleEndian: elf.littleEndian
  });
  assert.ok(info);
  assert.equal(info.importSymbols.some(sym => sym.name === expected.importSymbol), true);
  assert.equal(info.exportSymbols.some(sym => sym.name === expected.exportSymbol), true);
});

void test("parseElfDynamicSymbols returns null when dynsym is missing", async () => {
  const file = createElfFile();
  const parsed = await parseElf(file);
  const elf = expectDefined(parsed);
  const info = await parseElfDynamicSymbols({
    file,
    programHeaders: elf.programHeaders,
    sections: elf.sections,
    is64: elf.is64,
    littleEndian: elf.littleEndian
  });
  assert.equal(info, null);
});

void test("parseElfDynamicSymbols reads sectionless GNU-hash dynsym tables", async () => {
  const fixture = createElfGnuHashDynamicFixture();
  const info = await parseElfDynamicSymbols({
    file: fixture.file,
    programHeaders: fixture.programHeaders,
    sections: [],
    is64: true,
    littleEndian: true
  });

  assert.ok(info);
  assert.equal(info.exportSymbols.length, 1);
  assert.equal(info.exportSymbols[0]?.name, fixture.symbolName);
  assert.equal(info.exportSymbols[0]?.value, fixture.symbolVaddr);
});

void test("shared relocation cache excludes unterminated dynamic symbol names", async () => {
  const fixture = relocationFixture();
  fixture.elf.sections[2]!.type = 11; // SHT_DYNSYM.
  fixture.bytes[391] = 65; // Replace the final string-table NUL.
  const cache = new Map<number, ElfRelocationSymbol>();

  await parseElfDynamicSymbols({ file: fixture.file(), ...fixture.elf }, [], cache);

  assert.equal(cache.has(280), false);
});

