"use strict";

import assert from "node:assert/strict";
import { test } from "node:test";
import { parseElf } from "../../../../analyzers/elf/index.js";
import {
  createElfCompressedDwarfFile,
  createElfDwarfFile
} from "../../../fixtures/elf-dwarf-file.js";

void test("parseElf connects named DWARF sections to the common analyzer", async () => {
  const elf = await parseElf(createElfDwarfFile());

  assert.equal(elf?.dwarf?.units.length, 1);
  assert.equal(elf?.dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(elf?.dwarf?.units[0]?.root?.producer, "fixture compiler");
  assert.deepEqual(elf?.dwarf?.issues, []);
});

void test("parseElf decompresses ELF64 SHF_COMPRESSED zlib DWARF sections", async () => {
  const elf = await parseElf(createElfCompressedDwarfFile());

  assert.equal(elf?.dwarf?.units[0]?.root?.name, "main.c");
  assert.equal(elf?.dwarf?.sections[0]?.compressed, true);
  assert.equal(elf?.dwarf?.sections[0]?.status, "decoded");
  assert.deepEqual(elf?.dwarf?.issues, []);
});
