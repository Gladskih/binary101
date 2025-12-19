"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../analyzers/elf/index.js";
import { parseElfDynamicSymbols } from "../../analyzers/elf/dynamic-symbols.js";
import { createElfFile } from "../fixtures/elf-sample-file.js";
import { createElfMetadataFile } from "../fixtures/elf-metadata-file.js";
import { expectDefined } from "../helpers/expect-defined.js";

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

